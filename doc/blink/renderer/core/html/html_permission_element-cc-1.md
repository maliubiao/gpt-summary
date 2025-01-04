Response:
The user wants a summary of the functionality of the provided C++ code snippet from a Chromium Blink engine file. This is the second part of a two-part request. I should focus on summarizing the features and behaviors described in this specific code block, building upon the understanding from the previous part (though not explicitly provided here).

Here's a breakdown of the functionalities I can identify in this code:

1. **Style Adjustment:** The code manipulates the style properties (like `min-width`, `max-width`, `padding`) of the permission element based on factors like font size and whether the border is sufficiently distinct from the background. It also logs console errors for unsupported or conflicting style properties.
2. **Click Handling:** It handles user clicks (or DOMActivate events) on the permission element, triggering permission requests. It includes security checks to ensure the activation is initiated by a genuine user interaction.
3. **Permission Request Initiation:** The code initiates requests for embedded page permissions, passing relevant details like the element's position and the requested permissions.
4. **Permission Observation:** It registers observers to track the status changes of the requested permissions.
5. **Permission Status Updates:** It updates the internal state and visual appearance of the permission element based on changes in permission status.
6. **Clicking Enablement/Disablement:** The code implements logic to enable or disable clicking on the permission element based on various factors like style validity, occlusion, intersection with the viewport, and temporary delays. It uses timers to manage temporary disablement periods.
7. **Validation Change Events:** It dispatches events to signal changes in the validation status (clickability) of the element.
8. **Snapshotting and Validation:** It includes functions to take and validate snapshots of the element's state, likely for internal consistency and lifecycle management.
9. **Console Error Reporting:** The code includes mechanisms to log errors and warnings to the browser's developer console for various issues, like invalid styles or incorrect usage.
10. **Intersection Observation:** It uses an intersection observer to track the element's visibility within the viewport and disables clicking if the element is occluded or out of view.
11. **Style Validation:** It performs checks on the computed style of the element to ensure it meets certain accessibility and usability criteria (e.g., color contrast, font size).
12. **Length Adjustment with Bounds:** The code provides a utility function to adjust length values (like width and height) while enforcing minimum and maximum bounds, potentially dependent on content size or font size.
13. **Lifecycle Updates:** It responds to lifecycle updates of the frame view, potentially re-evaluating the element's intersection with the viewport and adjusting its clickability.
14. **Intersection Rectangle Computation:** It calculates the intersection rectangle between the permission element and the viewport.
15. **Recently Attached Handling:** It handles cases where the element is recently attached to the layout tree, potentially delaying click enablement.

Based on these points, I can now formulate a concise summary of the functionalities in this code snippet.
这是 blink 渲染引擎中 `HTMLPermissionElement` 类的部分代码，主要负责处理 `<permission>` 元素的行为和逻辑。结合前一部分代码，可以归纳出以下功能：

**总体功能:** `HTMLPermissionElement` 实现了 `<permission>` 元素的具体行为，使其能够作为页面嵌入的权限请求触发器。它负责管理元素的样式、用户交互、权限请求的生命周期以及状态的呈现。

**具体功能 (基于本部分代码):**

1. **动态调整样式 (基于字体大小和内容):**
   - 限制元素的 `min-width`、`max-width`、`min-height`、`max-height`：这些限制与元素的 `font-size` 相关，确保元素不会过小或过大。
   - 处理 `padding`：
     - 如果边框与背景色差异足够大，则允许左右 `padding` 不同，否则强制 `padding-right` 等于 `padding-left`。
     - 如果 `width` 或 `height` 设置为 `auto`，并且设置了 `padding-left` 或 `padding-top`，则会限制 `padding` 的最大值，使其与 `font-size` 成比例。同时强制 `padding-right` 等于 `padding-left`，`padding-bottom` 等于 `padding-top`。
   - **举例说明 (CSS):** 如果开发者设置 `<permission>` 元素的 `font-size: 16px;`，代码会基于此动态调整其 `min-width` 和 `max-width` 的允许范围。如果开发者尝试设置不同的 `padding-left` 和 `padding-right`，可能会收到控制台警告，并且样式会被强制调整。

2. **处理点击事件并触发权限请求:**
   - 响应 `DOMActivate` 事件 (通常是点击事件)。
   - 进行安全检查，确保事件是用户真实点击触发的，而不是脚本模拟的 (除非开启了测试模式)。
   - 如果点击被允许 (未被禁用)，则调用 `RequestPageEmbededPermissions()` 发起权限请求。
   - **假设输入与输出:**
     - **假设输入:** 用户点击了一个未被禁用的 `<permission>` 元素。
     - **输出:**  `RequestPageEmbededPermissions()` 被调用，向浏览器请求页面嵌入的权限。
   - **用户或编程常见的使用错误:** 开发者可能错误地使用脚本调用 `<permission>` 元素的 `click()` 方法来模拟用户点击。这将触发控制台错误 "The permission element can only be activated by actual user clicks."。

3. **管理权限观察者:**
   - 注册 `PermissionObserver` 来监听特定权限状态的变化。
   - **与 JavaScript 的关系:** 尽管这里是 C++ 代码，但观察者模式允许底层权限状态的变化能够通知到上层的 JavaScript 代码，例如通过事件触发。

4. **响应权限状态变化:**
   - `OnPermissionStatusChange()` 函数接收权限状态的更新。
   - 更新内部的 `permission_status_map_`，并调用 `UpdatePermissionStatusAndAppearance()` 来更新元素的状态和外观。

5. **处理嵌入式权限控制注册结果:**
   - `OnEmbeddedPermissionControlRegistered()` 函数处理浏览器进程对权限控制注册的响应。
   - 如果注册被允许，则初始化权限状态并注册观察者。
   - 如果注册被拒绝，则输出控制台错误。

6. **处理嵌入式权限决策结果:**
   - `OnEmbeddedPermissionsDecided()` 函数处理用户对权限请求的决定。
   - 根据用户的决定 (允许、拒绝、取消等)，触发相应的事件 (`dismiss` 或 `resolve`)。
   - **与 JavaScript 的关系:** 这些事件可以在 JavaScript 中被监听，以便开发者根据权限请求的结果执行相应的操作。例如：
     ```html
     <permission id="myPermission" types="camera"></permission>
     <script>
       document.getElementById('myPermission').addEventListener('resolve', (event) => {
         if (event.returnValue) {
           console.log('权限已授予');
         } else {
           console.log('权限被拒绝');
         }
       });
       document.getElementById('myPermission').addEventListener('dismiss', () => {
         console.log('权限请求被取消');
       });
     </script>
     ```

7. **管理点击禁用状态:**
   - 使用 `clicking_disabled_reasons_` 存储禁用点击的原因和过期时间。
   - 提供 `DisableClickingIndefinitely()`, `DisableClickingTemporarily()`, `EnableClicking()`, `EnableClickingAfterDelay()` 等方法来控制元素的点击状态。
   - **假设输入与输出:**
     - **假设输入:** 由于元素刚刚添加到布局树，调用了 `DisableClickingTemporarily(DisableReason::kRecentlyAttachedToLayoutTree, kDefaultDisableTimeout)`。
     - **输出:** 在 `kDefaultDisableTimeout` 时间后，元素的点击状态将被重新启用。
   - **用户或编程常见的使用错误:** 开发者可能会忽略控制台输出的禁用信息，导致用户点击元素没有反应，却不明白原因。

8. **触发验证状态变化事件:**
   - 当元素的点击使能状态发生变化时，会触发 `validationstatuschange` 事件。
   - **与 JavaScript 的关系:**  开发者可以监听此事件来了解 `<permission>` 元素是否可以被点击。

9. **更新快照和验证:**
   - `UpdateSnapshot()` 和 `ValidateSnapshot()` 函数用于维护和验证元素的内部状态快照。

10. **更新权限状态和外观:**
    - `UpdatePermissionStatusAndAppearance()` 函数根据当前权限状态更新元素的视觉呈现，例如可能改变显示的文本。
    - **与 CSS 的关系:**  通过 `PseudoStateChanged()` 函数，代码会更新元素的伪类状态 (如 `:permission-granted`, `:permission-element-occluded`)，允许开发者使用 CSS 来定制不同权限状态下的元素外观。例如：
      ```css
      permission::permission-granted {
        background-color: lightgreen;
        color: black;
      }
      ```

11. **更新文本内容:**
    - `UpdateText()` 函数根据权限状态和语言环境设置元素内部 `permission_text_span_` 的文本内容。
    - **与 HTML 的关系:**  这会直接修改 `<permission>` 元素内部用于显示文本的 `<span>` 元素的内容。

12. **报告控制台错误和警告:**
    - 提供 `AddConsoleError()` 和 `AddConsoleWarning()` 方法用于向开发者控制台输出信息，帮助调试和排查问题。

13. **处理 IntersectionObserver 的回调:**
    - `OnIntersectionChanged()` 函数处理 IntersectionObserver 的回调，当元素与视口的相交状态发生变化时被调用。
    - 根据相交状态 (完全可见、被遮挡或扭曲、超出视口或被裁剪)，可能会禁用或启用元素的点击。
    - **与用户体验的关系:**  这确保用户不会点击不可见的或被遮挡的权限元素，从而提升用户体验。

14. **验证样式有效性:**
    - `IsStyleValid()` 函数检查元素的计算样式是否满足特定要求，例如颜色对比度、字体大小等。
    - 如果样式无效，会输出控制台警告并禁用元素的点击。
    - **与 CSS 的关系:**  这强制开发者使用符合规范和易于访问的 CSS 样式。

15. **调整有界长度:**
    - `AdjustedBoundedLength()` 函数用于调整长度值，并强制执行最小值和最大值限制，可以基于固定的像素值或基于内容的尺寸。

16. **处理生命周期更新:**
    - `DidFinishLifecycleUpdate()` 函数在帧视图完成生命周期更新后被调用，用于检查元素与视口的相交情况，并可能临时禁用点击。

总而言之，这部分代码是 `<permission>` 元素的核心逻辑实现，涵盖了从样式管理到用户交互处理，再到权限请求生命周期管理的各个方面，并与 HTML、CSS 和 JavaScript 功能紧密结合，共同实现了 `<permission>` 元素的完整功能。

Prompt: 
```
这是目录为blink/renderer/core/html/html_permission_element.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能

"""
t(),
      /*lower_bound=*/builder.FontSize() * kMinLengthToFontSizeRatio,
      /*upper_bound=*/builder.FontSize() * kMaxLengthToFontSizeRatio,
      /*should_multiply_by_content_size=*/false));
  builder.SetMaxHeight(AdjustedBoundedLength(
      builder.MaxHeight(),
      /*lower_bound=*/std::nullopt,
      /*upper_bound=*/builder.FontSize() * kMaxLengthToFontSizeRatio,
      /*should_multiply_by_content_size=*/false));

  builder.SetMinWidth(
      AdjustedBoundedLength(builder.MinWidth(),
                            /*lower_bound=*/kMinLengthToFontSizeRatio,
                            /*upper_bound=*/kMaxLengthToFontSizeRatio,
                            /*should_multiply_by_content_size=*/true));

  bool unlimited_width_allowed =
      IsBorderSufficientlyDistinctFromBackgroundColor(builder.CloneStyle());

  if (unlimited_width_allowed) {
    if (builder.PaddingRight().IsSpecified() &&
        !builder.PaddingRight().IsZero() &&
        builder.PaddingLeft() != builder.PaddingRight()) {
      AddConsoleError(
          "The permission element does not support 'padding-right'. "
          "'padding-right' is always set to be identical to 'padding-left'.");
    }
    builder.SetPaddingRight(builder.PaddingLeft());
  } else {
    builder.SetMaxWidth(AdjustedBoundedLength(
        builder.MaxWidth(),
        /*lower_bound=*/std::nullopt, /*upper_bound=*/kMaxLengthToFontSizeRatio,
        /*should_multiply_by_content_size=*/true));

    // If width is set to auto and there is left padding specified, we will
    // respect the padding (up to a certain maximum), otherwise the padding has
    // no effect. We treat height and top/bottom padding similarly.
    if (builder.Width().IsAuto() && builder.PaddingLeft().IsSpecified() &&
        !builder.PaddingLeft().IsZero()) {
      if (builder.PaddingRight().IsSpecified() &&
          !builder.PaddingRight().IsZero() &&
          builder.PaddingLeft() != builder.PaddingRight()) {
        AddConsoleError(
            "The permission element does not support 'padding-right'. "
            "'padding-right' is always set to be identical to 'padding-left'.");
      }

      builder.SetPaddingLeft(
          AdjustedBoundedLength(builder.PaddingLeft(),
                                /*lower_bound=*/std::nullopt,
                                /*upper_bound=*/builder.FontSize() *
                                    kMaxHorizontalPaddingToFontSizeRatio,
                                /*should_multiply_by_content_size=*/false));
      builder.SetPaddingRight(builder.PaddingLeft());
    } else {
      builder.ResetPaddingLeft();
      builder.ResetPaddingRight();
    }
  }

  if (builder.Height().IsAuto() && builder.PaddingTop().IsSpecified() &&
      !builder.PaddingTop().IsZero()) {
    if (builder.PaddingBottom().IsSpecified() &&
        !builder.PaddingBottom().IsZero() &&
        builder.PaddingTop() != builder.PaddingBottom()) {
      AddConsoleError(
          "The permission element does not support 'padding-bottom'. "
          "'padding-bottom' is always set to be identical to 'padding-top'.");
    }
    builder.SetPaddingTop(AdjustedBoundedLength(
        builder.PaddingTop(),
        /*lower_bound=*/std::nullopt,
        /*upper_bound=*/builder.FontSize() * kMaxVerticalPaddingToFontSizeRatio,
        /*should_multiply_by_content_size=*/false));
    builder.SetPaddingBottom(builder.PaddingTop());
  } else {
    builder.ResetPaddingTop();
    builder.ResetPaddingBottom();
  }
}

void HTMLPermissionElement::DidRecalcStyle(const StyleRecalcChange change) {
  HTMLElement::DidRecalcStyle(change);

  if (!IsStyleValid()) {
    DisableClickingIndefinitely(DisableReason::kInvalidStyle);
    return;
  }
  EnableClickingAfterDelay(DisableReason::kInvalidStyle,
                           kDefaultDisableTimeout);
  gfx::Rect intersection_rect =
      ComputeIntersectionRectWithViewport(GetDocument().GetPage());
  if (intersection_rect_.has_value() &&
      intersection_rect_.value() != intersection_rect) {
    DisableClickingTemporarily(DisableReason::kIntersectionWithViewportChanged,
                               kDefaultDisableTimeout);
  }
  intersection_rect_ = intersection_rect;
}

void HTMLPermissionElement::DefaultEventHandler(Event& event) {
  if (event.type() == event_type_names::kDOMActivate) {
    event.SetDefaultHandled();
    if (event.IsFullyTrusted() ||
        RuntimeEnabledFeatures::BypassPepcSecurityForTestingEnabled()) {
      // TODO(crbug.com/352496162): After confirming all permission requests
      // eventually call |OnEmbeddedPermissionsDecided|, block multiple
      // permission requests when one is in progress, instead of temporairly
      // disallowing them.
      if (pending_request_created_ &&
          base::TimeTicks::Now() - *pending_request_created_ <
              kDefaultDisableTimeout) {
        AddConsoleError(
            "The permission element already has a request in progress.");
        return;
      }

      if (IsClickingEnabled()) {
        RequestPageEmbededPermissions();
      }
    } else {
      // For automated testing purposes this behavior can be overridden by
      // adding '--enable-features=BypassPepcSecurityForTesting' to the
      // command line when launching the browser.
      AddConsoleError(
          "The permission element can only be activated by actual user "
          "clicks.");
      base::UmaHistogramEnumeration(
          "Blink.PermissionElement.UserInteractionDeniedReason",
          UserInteractionDeniedReason::kUntrustedEvent);
    }
    return;
  }

  if (HandleKeyboardActivation(event)) {
    return;
  }
  HTMLElement::DefaultEventHandler(event);
}

void HTMLPermissionElement::RequestPageEmbededPermissions() {
  CHECK_GT(permission_descriptors_.size(), 0U);
  CHECK_LE(permission_descriptors_.size(), 2U);
  auto descriptor = EmbeddedPermissionRequestDescriptor::New();
  descriptor->element_position = BoundsInWidget();
  descriptor->permissions = mojo::Clone(permission_descriptors_);

  pending_request_created_ = base::TimeTicks::Now();

  GetPermissionService()->RequestPageEmbeddedPermission(
      std::move(descriptor),
      WTF::BindOnce(&HTMLPermissionElement::OnEmbeddedPermissionsDecided,
                    WrapWeakPersistent(this)));
}

void HTMLPermissionElement::RegisterPermissionObserver(
    const PermissionDescriptorPtr& descriptor,
    MojoPermissionStatus current_status) {
  mojo::PendingRemote<PermissionObserver> observer;
  permission_observer_receivers_.Add(observer.InitWithNewPipeAndPassReceiver(),
                                     descriptor->name, GetTaskRunner());
  GetPermissionService()->AddPageEmbeddedPermissionObserver(
      descriptor.Clone(), current_status, std::move(observer));
}

void HTMLPermissionElement::OnPermissionStatusChange(
    MojoPermissionStatus status) {
  auto permission_name = permission_observer_receivers_.current_context();
  auto it = permission_status_map_.find(permission_name);
  CHECK(it != permission_status_map_.end());
  it->value = status;

  UpdatePermissionStatusAndAppearance();
}

void HTMLPermissionElement::OnEmbeddedPermissionControlRegistered(
    bool allowed,
    const std::optional<Vector<MojoPermissionStatus>>& statuses) {
  if (!allowed) {
    AddConsoleError(String::Format(
        "The permission '%s' has not passed security checks or has surpassed "
        "the maximum instances quota per page.",
        GetType().Utf8().c_str()));
    return;
  }

  CHECK_GT(permission_descriptors_.size(), 0U);
  CHECK_LE(permission_descriptors_.size(), 2U);
  CHECK(statuses.has_value());
  CHECK_EQ(statuses->size(), permission_descriptors_.size());

  bool needs_permission_observer_registration =
      permission_observer_receivers_.empty();
  for (wtf_size_t i = 0; i < permission_descriptors_.size(); ++i) {
    auto status = (*statuses)[i];
    const auto& descriptor = permission_descriptors_[i];
    permission_status_map_.Set(descriptor->name, status);
    if (needs_permission_observer_registration) {
      RegisterPermissionObserver(descriptor, status);
    }
  }

  UpdatePermissionStatusAndAppearance();
  MaybeDispatchValidationChangeEvent();
}

void HTMLPermissionElement::OnEmbeddedPermissionsDecided(
    EmbeddedPermissionControlResult result) {
  pending_request_created_ = std::nullopt;

  switch (result) {
    case EmbeddedPermissionControlResult::kDismissed:
      DispatchEvent(*Event::CreateCancelableBubble(event_type_names::kDismiss));
      return;
    case EmbeddedPermissionControlResult::kGranted:
      aggregated_permission_status_ = MojoPermissionStatus::GRANTED;
      DispatchEvent(*Event::CreateCancelableBubble(event_type_names::kResolve));
      return;
    case EmbeddedPermissionControlResult::kDenied:
      DispatchEvent(*Event::CreateCancelableBubble(event_type_names::kResolve));
      return;
    case EmbeddedPermissionControlResult::kNotSupported:
      AddConsoleError(String::Format(
          "The permission request type '%s' is not supported and "
          "this <permission> element will not be functional.",
          GetType().Utf8().c_str()));
      return;
    case EmbeddedPermissionControlResult::kResolvedNoUserGesture:
      return;
  }
  NOTREACHED();
}

void HTMLPermissionElement::DisableReasonExpireTimerFired(TimerBase* timer) {
  EnableClicking(static_cast<DisableReasonExpireTimer*>(timer)->reason());
  NotifyClickingDisablePseudoStateChanged();
}

void HTMLPermissionElement::MaybeDispatchValidationChangeEvent() {
  auto state = GetClickingEnabledState();
  if (clicking_enabled_state_ == state) {
    return;
  }

  // Always keep `clicking_enabled_state_` up-to-date
  clicking_enabled_state_ = state;
  DispatchEvent(*Event::CreateCancelableBubble(
      event_type_names::kValidationstatuschange));
}

void HTMLPermissionElement::UpdateSnapshot() {
  ValidateSnapshot();
}

bool HTMLPermissionElement::ValidateSnapshot() {
  return NotifyClickingDisablePseudoStateChanged();
}

bool HTMLPermissionElement::NotifyClickingDisablePseudoStateChanged() {
  ClickingDisablePseudoState new_state(HasInvalidStyle(), IsOccluded());
  if (new_state.is_occluded != pseudo_state_.is_occluded) {
    PseudoStateChanged(CSSSelector::kPseudoPermissionElementOccluded);
  }

  if (new_state.has_invalid_style != pseudo_state_.has_invalid_style) {
    PseudoStateChanged(CSSSelector::kPseudoPermissionElementInvalidStyle);
  }

  if (pseudo_state_ != new_state) {
    pseudo_state_ = new_state;
    return false;
  }

  return true;
}

scoped_refptr<base::SingleThreadTaskRunner>
HTMLPermissionElement::GetTaskRunner() {
  return GetExecutionContext()->GetTaskRunner(TaskType::kInternalDefault);
}

bool HTMLPermissionElement::IsClickingEnabled() {
  if (permission_descriptors_.empty()) {
    AddConsoleError(String::Format(
        "The permission element '%s' cannot be activated due to invalid type.",
        GetType().Utf8().c_str()));
    base::UmaHistogramEnumeration(
        "Blink.PermissionElement.UserInteractionDeniedReason",
        UserInteractionDeniedReason::kInvalidType);
    return false;
  }

  if (!IsRegisteredInBrowserProcess()) {
    AddConsoleError(String::Format(
        "The permission element '%s' cannot be activated because of security "
        "checks or because the page's quota has been exceeded.",
        GetType().Utf8().c_str()));
    base::UmaHistogramEnumeration(
        "Blink.PermissionElement.UserInteractionDeniedReason",
        UserInteractionDeniedReason::kFailedOrHasNotBeenRegistered);
    return false;
  }

  // Do not check click-disabling reasons if the PEPC validation feature is
  // disabled. This should only occur in testing scenarios.
  if (RuntimeEnabledFeatures::BypassPepcSecurityForTestingEnabled()) {
    return true;
  }

  // Remove expired reasons. If a non-expired reason is found, then clicking is
  // disabled.
  base::TimeTicks now = base::TimeTicks::Now();
  while (!clicking_disabled_reasons_.empty()) {
    auto it = clicking_disabled_reasons_.begin();
    if (it->value >= now) {
      AddConsoleError(String::Format(
          "The permission element '%s' cannot be activated due to %s.",
          GetType().Utf8().c_str(),
          DisableReasonToString(it->key).Utf8().c_str()));
      if (it->key ==
              DisableReason::kIntersectionVisibilityOccludedOrDistorted &&
          occluder_node_id_ != kInvalidDOMNodeId) {
        if (Node* node = DOMNodeIds::NodeForId(occluder_node_id_)) {
          AddConsoleError(
              String::Format("The permission element is occluded by node %s",
                             node->ToString().Utf8().c_str()));
        }
      }
      base::UmaHistogramEnumeration(
          "Blink.PermissionElement.UserInteractionDeniedReason",
          DisableReasonToUserInteractionDeniedReason(it->key));
      return false;
    }
    clicking_disabled_reasons_.erase(it);
  }

  return true;
}

void HTMLPermissionElement::DisableClickingIndefinitely(DisableReason reason) {
  clicking_disabled_reasons_.Set(reason, base::TimeTicks::Max());
  StopTimerDueToIndefiniteReason(reason);
}

void HTMLPermissionElement::DisableClickingTemporarily(
    DisableReason reason,
    const base::TimeDelta& duration) {
  base::TimeTicks timeout_time = base::TimeTicks::Now() + duration;

  // If there is already an entry that expires later, keep the existing one.
  if (clicking_disabled_reasons_.Contains(reason) &&
      clicking_disabled_reasons_.at(reason) > timeout_time) {
    return;
  }

  // An active timer indicates that the element is temporarily disabled with a
  // reason, which is the longest alive temporary reason in
  // `clicking_disabled_reasons_`. If the timer's next fire time is less than
  // the `timeout_time` (`NextFireInterval() < duration`), a new "longest alive
  // temporary reason" emerges and we need an adjustment to the timer.
  clicking_disabled_reasons_.Set(reason, timeout_time);
  if (!disable_reason_expire_timer_.IsActive() ||
      disable_reason_expire_timer_.NextFireInterval() < duration) {
    disable_reason_expire_timer_.StartOrRestartWithReason(reason, duration);
  }

  MaybeDispatchValidationChangeEvent();
}

void HTMLPermissionElement::EnableClicking(DisableReason reason) {
  clicking_disabled_reasons_.erase(reason);
  RefreshDisableReasonsAndUpdateTimer();
}

void HTMLPermissionElement::EnableClickingAfterDelay(
    DisableReason reason,
    const base::TimeDelta& delay) {
  if (clicking_disabled_reasons_.Contains(reason)) {
    clicking_disabled_reasons_.Set(reason, base::TimeTicks::Now() + delay);
    RefreshDisableReasonsAndUpdateTimer();
  }
}

HTMLPermissionElement::ClickingEnabledState
HTMLPermissionElement::GetClickingEnabledState() const {
  if (permission_descriptors_.empty()) {
    return {false, AtomicString("type_invalid")};
  }

  if (LocalFrame* frame = GetDocument().GetFrame()) {
    if (frame->IsInFencedFrameTree()) {
      return {false, AtomicString("illegal_subframe")};
    }

    if (frame->IsCrossOriginToOutermostMainFrame() &&
        !GetExecutionContext()
             ->GetContentSecurityPolicy()
             ->HasEnforceFrameAncestorsDirectives()) {
      return {false, AtomicString("illegal_subframe")};
    }

    for (const PermissionDescriptorPtr& descriptor : permission_descriptors_) {
      if (!GetExecutionContext()->IsFeatureEnabled(
              PermissionNameToPermissionsPolicyFeature(descriptor->name))) {
        return {false, AtomicString("illegal_subframe")};
      }
    }
  }

  if (!IsRegisteredInBrowserProcess()) {
    return {false, AtomicString("unsuccessful_registration")};
  }

  if (RuntimeEnabledFeatures::BypassPepcSecurityForTestingEnabled()) {
    return {true, AtomicString()};
  }

  // If there's an "indefinitely disabling" for any reason, return that reason.
  // Otherwise, we will look into the reason of the current active timer.
  for (const auto& it : clicking_disabled_reasons_) {
    if (it.value == base::TimeTicks::Max()) {
      return {false, DisableReasonToInvalidReasonString(it.key)};
    }
  }

  if (disable_reason_expire_timer_.IsActive()) {
    return {false, DisableReasonToInvalidReasonString(
                       disable_reason_expire_timer_.reason())};
  }

  return {true, AtomicString()};
}

void HTMLPermissionElement::RefreshDisableReasonsAndUpdateTimer() {
  base::TimeTicks now = base::TimeTicks::Now();
  base::TimeTicks max_time_ticks = base::TimeTicks::Min();
  DisableReason reason = DisableReason::kUnknown;
  HashMap<DisableReason, base::TimeTicks> swap_clicking_disabled_reasons;
  for (auto it = clicking_disabled_reasons_.begin();
       it != clicking_disabled_reasons_.end(); ++it) {
    if (it->value == base::TimeTicks::Max()) {
      StopTimerDueToIndefiniteReason(it->key);
      return;
    }

    if (it->value < now) {
      continue;
    }

    swap_clicking_disabled_reasons.Set(it->key, it->value);
    if (it->value <= max_time_ticks) {
      continue;
    }

    max_time_ticks = it->value;
    reason = it->key;
  }
  // Restart the timer to match with  "longest alive, not indefinitely disabling
  // reason". That's the one has the max timeticks on
  // `clicking_disabled_reasons_`.
  if (max_time_ticks != base::TimeTicks::Min()) {
    disable_reason_expire_timer_.StartOrRestartWithReason(reason,
                                                          max_time_ticks - now);
  }

  clicking_disabled_reasons_.swap(swap_clicking_disabled_reasons);
  MaybeDispatchValidationChangeEvent();
}

void HTMLPermissionElement::UpdatePermissionStatusAndAppearance() {
  if (base::ranges::any_of(permission_status_map_, [](const auto& status) {
        return status.value == MojoPermissionStatus::DENIED;
      })) {
    aggregated_permission_status_ = MojoPermissionStatus::DENIED;
  } else if (base::ranges::any_of(
                 permission_status_map_, [](const auto& status) {
                   return status.value == MojoPermissionStatus::ASK;
                 })) {
    aggregated_permission_status_ = MojoPermissionStatus::ASK;
  } else {
    aggregated_permission_status_ = MojoPermissionStatus::GRANTED;
  }

  if (!initial_aggregated_permission_status_.has_value()) {
    initial_aggregated_permission_status_ = aggregated_permission_status_;
  }

  PseudoStateChanged(CSSSelector::kPseudoPermissionGranted);
  UpdateText();
}

void HTMLPermissionElement::UpdateText() {
  bool permission_granted;
  PermissionName permission_name;
  wtf_size_t permission_count;
  if (permission_status_map_.size() == 0U) {
    // Use |permission_descriptors_| instead and assume a "not granted" state.
    if (permission_descriptors_.size() == 0U) {
      return;
    }
    permission_granted = false;
    permission_name = permission_descriptors_[0]->name;
    permission_count = permission_descriptors_.size();
  } else {
    CHECK_LE(permission_status_map_.size(), 2u);
    permission_granted = PermissionsGranted();
    permission_name = permission_status_map_.begin()->key;
    permission_count = permission_status_map_.size();
  }

  AtomicString language_string = ComputeInheritedLanguage().LowerASCII();

  int untranslated_message_id =
      permission_count == 1
          ? GetUntranslatedMessageIDSinglePermission(
                permission_name, permission_granted, is_precise_location_)
          : GetUntranslatedMessageIDMultiplePermissions(permission_granted);
  int translated_message_id =
      GetTranslatedMessageID(untranslated_message_id, language_string);
  CHECK(translated_message_id);
  permission_text_span_->setInnerText(
      GetLocale().QueryString(translated_message_id));
}

void HTMLPermissionElement::AddConsoleError(String error) {
  AddConsoleMessage(mojom::blink::ConsoleMessageSource::kRendering,
                    mojom::blink::ConsoleMessageLevel::kError, error);
}

void HTMLPermissionElement::AddConsoleWarning(String warning) {
  AddConsoleMessage(mojom::blink::ConsoleMessageSource::kRendering,
                    mojom::blink::ConsoleMessageLevel::kWarning, warning);
}

void HTMLPermissionElement::OnIntersectionChanged(
    const HeapVector<Member<IntersectionObserverEntry>>& entries) {
  CHECK(!entries.empty());
  Member<IntersectionObserverEntry> latest_observation = entries.back();
  CHECK_EQ(this, latest_observation->target());
  IntersectionVisibility intersection_visibility =
      IntersectionVisibility::kFullyVisible;
  // `intersectionRatio` >= `kIntersectionThreshold` (1.0f) means the element is
  // fully visible on the viewport (vs `intersectionRatio` < 1.0f means its
  // bound is clipped by the viewport or styling effects). In this case, the
  // `isVisible` false means the element is occluded by something else or has
  // distorted visual effect applied.
  if (!latest_observation->isVisible()) {
    intersection_visibility =
        latest_observation->intersectionRatio() >= kIntersectionThreshold
            ? IntersectionVisibility::kOccludedOrDistorted
            : IntersectionVisibility::kOutOfViewportOrClipped;
  }

  if (intersection_visibility_ == intersection_visibility) {
    return;
  }
  intersection_visibility_ = intersection_visibility;
  occluder_node_id_ = kInvalidDOMNodeId;
  switch (intersection_visibility_) {
    case IntersectionVisibility::kFullyVisible: {
      std::optional<base::TimeDelta> interval =
          GetRecentlyAttachedTimeoutRemaining();
      DisableClickingTemporarily(
          DisableReason::kIntersectionRecentlyFullyVisible,
          interval ? interval.value() : kDefaultDisableTimeout);
      EnableClicking(DisableReason::kIntersectionVisibilityOccludedOrDistorted);
      EnableClicking(
          DisableReason::kIntersectionVisibilityOutOfViewPortOrClipped);
      break;
    }
    case IntersectionVisibility::kOccludedOrDistorted:
      occluder_node_id_ = latest_observation->GetGeometry().occluder_node_id();
      DisableClickingIndefinitely(
          DisableReason::kIntersectionVisibilityOccludedOrDistorted);
      break;
    case IntersectionVisibility::kOutOfViewportOrClipped:
      DisableClickingIndefinitely(
          DisableReason::kIntersectionVisibilityOutOfViewPortOrClipped);
      break;
  }

  // TODO(crbug.com/342330035): revisit it when we write spec for <permission>
  // element.
  GetTaskRunner()->PostTask(
      FROM_HERE, WTF::BindOnce(&HTMLPermissionElement::UpdateSnapshot,
                               WrapWeakPersistent(this)));
}

bool HTMLPermissionElement::IsStyleValid() {
  // No computed style when using `display: none`.
  if (!GetComputedStyle()) {
    AddConsoleWarning(
        String::Format("Cannot compute style for the permission element '%s'",
                       GetType().Utf8().c_str()));
    base::UmaHistogramEnumeration("Blink.PermissionElement.InvalidStyleReason",
                                  InvalidStyleReason::kNoComputedStyle);
    return false;
  }

  if (AreColorsNonOpaque(GetComputedStyle())) {
    AddConsoleWarning(
        String::Format("Color or background color of the permission element "
                       "'%s' is non-opaque",
                       GetType().Utf8().c_str()));
    base::UmaHistogramEnumeration(
        "Blink.PermissionElement.InvalidStyleReason",
        InvalidStyleReason::kNonOpaqueColorOrBackgroundColor);
    return false;
  }

  if (ContrastBetweenColorAndBackgroundColor(GetComputedStyle()) <
      kMinimumAllowedContrast) {
    AddConsoleWarning(
        String::Format("Contrast between color and background color of the "
                       "permission element '%s' is too low",
                       GetType().Utf8().c_str()));
    base::UmaHistogramEnumeration(
        "Blink.PermissionElement.InvalidStyleReason",
        InvalidStyleReason::kLowConstrastColorAndBackgroundColor);
    return false;
  }

  // Compute the font size but reverse browser zoom as it should not affect font
  // size validation. The same font size value should always pass regardless of
  // what the user's browser zoom is.
  // TODO(crbug.com/352046941): This does not currently distinguish between
  // browser zoom and cross-origin iframe zoom (set via CSS).
  float font_size_dip = GetComputedStyle()->ComputedFontSize() /
                        GetComputedStyle()->EffectiveZoom();

  float css_zoom_factor =
      GetComputedStyle()->EffectiveZoom() /
      GetDocument().GetFrame()->LocalFrameRoot().LayoutZoomFactor();

  // The min size is what `font-size:small` looks like when rendered in the
  // document element of the local root frame, without any intervening CSS
  // zoom factors applied.
  float min_font_size_dip = FontSizeFunctions::FontSizeForKeyword(
      &GetDocument(), FontSizeFunctions::KeywordSize(CSSValueID::kSmall),
      GetComputedStyle()->GetFontDescription().IsMonospace());
  if (font_size_dip < min_font_size_dip / css_zoom_factor) {
    AddConsoleWarning(
        String::Format("Font size of the permission element '%s' is too small",
                       GetType().Utf8().c_str()));
    base::UmaHistogramEnumeration("Blink.PermissionElement.InvalidStyleReason",
                                  InvalidStyleReason::kTooSmallFontSize);
    return false;
  }

  // The max size is what `font-size:xxxlarge` looks like when rendered in the
  // document element of the local root frame, without any intervening CSS
  // zoom factors applied.
  float max_font_size_dip = FontSizeFunctions::FontSizeForKeyword(
      &GetDocument(), FontSizeFunctions::KeywordSize(CSSValueID::kXxxLarge),
      GetComputedStyle()->GetFontDescription().IsMonospace());
  if (font_size_dip > max_font_size_dip / css_zoom_factor) {
    AddConsoleWarning(
        String::Format("Font size of the permission element '%s' is too large",
                       GetType().Utf8().c_str()));
    base::UmaHistogramEnumeration("Blink.PermissionElement.InvalidStyleReason",
                                  InvalidStyleReason::kTooLargeFontSize);
    return false;
  }

  return true;
}

Length HTMLPermissionElement::AdjustedBoundedLength(
    const Length& length,
    std::optional<float> lower_bound,
    std::optional<float> upper_bound,
    bool should_multiply_by_content_size) {
  CHECK(lower_bound.has_value() || upper_bound.has_value());
  bool is_content_or_stretch =
      length.HasContentOrIntrinsic() || length.HasStretch();
  if (is_content_or_stretch && !length_console_error_sent_) {
    length_console_error_sent_ = true;
    AddConsoleWarning(
        "content, intrinsic, or stretch sizes are not supported as values for "
        "the min/max width and height of the permission element");
  }

  const Length& length_to_use =
      is_content_or_stretch || length.IsNone() ? Length::Auto() : length;

  // If the |length| is not supported and the |bound| is static, return a simple
  // fixed length.
  if (length_to_use.IsAuto() && !should_multiply_by_content_size) {
    return Length(
        lower_bound.has_value() ? lower_bound.value() : upper_bound.value(),
        Length::Type::kFixed);
  }

  // If the |length| is supported and the |bound| is static, return a
  // min|max|clamp expression-type length.
  if (!should_multiply_by_content_size) {
    auto lower_bound_expr =
        lower_bound.has_value()
            ? std::optional(base::MakeRefCounted<
                            blink::CalculationExpressionPixelsAndPercentNode>(
                  PixelsAndPercent(lower_bound.value())))
            : std::nullopt;

    auto upper_bound_expr =
        upper_bound.has_value()
            ? std::optional(base::MakeRefCounted<
                            blink::CalculationExpressionPixelsAndPercentNode>(
                  PixelsAndPercent(upper_bound.value())))
            : std::nullopt;

    // expr = min|max|clamp(bound, length, [bound2])
    auto expr =
        BuildLengthBoundExpr(length_to_use, lower_bound_expr, upper_bound_expr);
    return Length(CalculationValue::CreateSimplified(
        std::move(expr), Length::ValueRange::kNonNegative));
  }

  // bound_expr = size * bound.
  auto lower_bound_expr =
      lower_bound.has_value()
          ? std::optional(BuildFitContentExpr(lower_bound.value()))
          : std::nullopt;
  auto upper_bound_expr =
      upper_bound.has_value()
          ? std::optional(BuildFitContentExpr(upper_bound.value()))
          : std::nullopt;

  scoped_refptr<const CalculationExpressionNode> bound_expr;

  if (!length_to_use.IsAuto()) {
    // bound_expr = min|max|clamp(size * bound, length, [size * bound2])
    bound_expr =
        BuildLengthBoundExpr(length_to_use, lower_bound_expr, upper_bound_expr);
  } else {
    bound_expr = lower_bound_expr.has_value()
                     ? std::move(lower_bound_expr.value())
                     : std::move(upper_bound_expr.value());
  }

  // This uses internally the CalculationExpressionSizingKeywordNode to create
  // an expression that depends on the size of the contents of the permission
  // element, in order to set necessary min/max bounds on width and height. If
  // https://drafts.csswg.org/css-values-5/#calc-size is ever abandoned,
  // the functionality should still be kept around in some way that can
  // facilitate this use case.

  auto fit_content_expr =
      base::MakeRefCounted<CalculationExpressionSizingKeywordNode>(
          CalculationExpressionSizingKeywordNode::Keyword::kFitContent);

  // expr = calc-size(fit-content, bound_expr)
  auto expr = CalculationExpressionOperationNode::CreateSimplified(
      CalculationExpressionOperationNode::Children(
          {fit_content_expr, bound_expr}),
      CalculationOperator::kCalcSize);

  return Length(CalculationValue::CreateSimplified(
      std::move(expr), Length::ValueRange::kNonNegative));
}

void HTMLPermissionElement::DidFinishLifecycleUpdate(
    const LocalFrameView& local_frame_view) {
  // This code monitors the stability of the HTMLPermissionElement and
  // temporarily disables the element if it detects an unstable state.
  // "Unstable state" in this context occurs when the intersection rectangle
  // between the viewport and the element's layout box changes, indicating that
  // the element has been moved or resized.
  gfx::Rect intersection_rect = ComputeIntersectionRectWithViewport(
      local_frame_view.GetFrame().GetPage());
  if (intersection_rect_.has_value() &&
      intersection_rect_.value() != intersection_rect) {
    DisableClickingTemporarily(DisableReason::kIntersectionWithViewportChanged,
                               kDefaultDisableTimeout);
  }
  intersection_rect_ = intersection_rect;
}

gfx::Rect HTMLPermissionElement::ComputeIntersectionRectWithViewport(
    const Page* page) {
  LayoutObject* layout_object = GetLayoutObject();
  if (!layout_object) {
    return gfx::Rect();
  }

  gfx::Rect viewport_in_root_frame =
      ToEnclosingRect(page->GetVisualViewport().VisibleRect());
  PhysicalRect rect = To<LayoutBox>(layout_object)->PhysicalBorderBoxRect();
  // `MapToVisualRectInAncestorSpace` with a null `ancestor` argument will
  // mutate `rect` to visible rect in the root frame's coordinate space.
  layout_object->MapToVisualRectInAncestorSpace(/*ancestor*/ nullptr, rect);
  return IntersectRects(viewport_in_root_frame, ToEnclosingRect(rect));
}

std::optional<base::TimeDelta>
HTMLPermissionElement::GetRecentlyAttachedTimeoutRemaining() const {
  base::TimeTicks now = base::TimeTicks::Now();
  auto it = clicking_disabled_reasons_.find(
      DisableReason::kRecentlyAttachedToLayoutTree);
  if (it == clicking_disabled_reasons_.end()) {
    return std::nullopt;
  }

  return it->value - now;
}

}  // namespace blink

"""


```