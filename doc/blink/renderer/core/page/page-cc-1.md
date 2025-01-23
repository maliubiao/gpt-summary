Response:
The user wants a summary of the functionality of the provided C++ code snippet from `blink/renderer/core/page/page.cc`. This is part 2 of 2, so I should focus on the code provided in this snippet.

I need to identify the key functions and data members and explain their purpose. Since the user specifically asks about relationships with JavaScript, HTML, and CSS, I should look for areas where the code interacts with web content and styling. Logical reasoning examples require constructing hypothetical inputs and outputs for certain functions. Common usage errors relate to how developers might misuse the functionalities. Finally, I need to consider how user actions might lead to this code being executed, forming debugging clues.

Here's a breakdown of the code's functionality:

1. **Visibility Management:**  Functions to check and update the page's visibility state (e.g., `IsPageVisible`, `DispatchedPagehideAndStillHidden`). This relates to JavaScript events like `visibilitychange` and the Page Lifecycle API.
2. **Freezing:**  A function to handle the page freezing state (`OnSetPageFrozen`). This is related to the Page Lifecycle API and impacts JavaScript execution.
3. **Frame Management:** Functions to get the maximum number of frames (`MaxNumberOfFrames`) and track subframe counts (`SubframeCount`). This is relevant to the HTML `<iframe>` element and potentially fenced frames.
4. **Safe Area Insets:**  Functions to manage and update safe area insets (`UpdateSafeAreaInsetWithBrowserControls`, `SetMaxSafeAreaInsets`). This is crucial for modern web design, especially on mobile devices with notches or other screen cutouts, impacting CSS layout.
5. **Settings Changes:** The `SettingsChanged` function handles various setting updates and their side effects. This is a central piece connecting browser settings to rendering behavior, involving JavaScript APIs, HTML elements, and CSS styling. Each `ChangeType` case needs individual consideration for its relation to web technologies.
6. **Invalidation:** Functions to trigger repaint and style recalculation (`InvalidatePaint`, `InvalidateColorScheme`). These are fundamental to how changes in HTML, CSS, and JavaScript are reflected visually.
7. **Plugin Management:** Functions to notify observers about plugin changes (`NotifyPluginsChanged`). This relates to browser plugins (now mostly deprecated).
8. **Accelerated Compositing:**  A function to update settings related to hardware acceleration for rendering (`UpdateAcceleratedCompositingSettings`). This indirectly impacts performance and how CSS transformations and animations are handled.
9. **Load Commitment:**  The `DidCommitLoad` function is called after a navigation completes, resetting state and triggering updates. This is a key point in the page lifecycle, related to JavaScript events and how the browser interprets new HTML.
10. **Language Preferences:** `AcceptLanguagesChanged` notifies the page about changes in accepted languages, affecting content negotiation.
11. **Tracing and Destruction:** Standard lifecycle methods for debugging and memory management.
12. **Scrollbar Theme:**  Determining the appropriate scrollbar style based on settings.
13. **Agent and Page Scheduling:**  Interacting with scheduling mechanisms for tasks.
14. **Autoplay:** Managing flags related to media autoplay.
15. **Fenced Frames:**  A flag indicating if the main frame is a fenced frame root.
16. **Media and Preference Overrides:**  Functions to override media features and user preferences, potentially affecting CSS and JavaScript behavior.
17. **Vision Deficiency:** A function to simulate vision deficiencies for accessibility testing.
18. **Animation:**  The `Animate` function drives animations.
19. **Lifecycle Updates:**  Functions to manage the page's rendering lifecycle.
20. **Browsing Context Group:** Functions to manage browsing context group information, relevant to isolation and cross-origin interactions.
21. **Attribution Support:**  Setting the level of support for the Attribution Reporting API.
22. **Leak Detection:**  A static method to prepare for leak detection by removing specific supplements.

For the examples:

*   **JavaScript:** The visibility functions directly relate to the `visibilitychange` event. The freezing function is tied to the Page Lifecycle API.
*   **HTML:** The frame management functions relate to the `<iframe>` and `<fencedframe>` elements.
*   **CSS:** Safe area insets and media feature overrides directly affect CSS layout and styling.

I should now synthesize this information into a concise summary.
这是`blink/renderer/core/page/page.cc`文件的第二部分，主要包含以下功能：

**功能归纳:**

1. **页面可见性管理:**
    *   `visibility()`: 获取页面的当前可见性状态。
    *   `IsPageVisible()`: 判断页面是否完全可见。
    *   `DispatchedPagehideAndStillHidden()`:  检查是否已分发 `pagehide` 事件且页面仍然隐藏。
    *   `DispatchedPagehidePersistedAndStillHidden()`: 检查是否已分发持久化的 `pagehide` 事件且页面仍然隐藏。
    *   `OnSetPageFrozen(bool frozen)`:  设置页面的冻结状态，并通知所有子框架。

2. **光标可见性:**
    *   `IsCursorVisible()`:  判断光标是否可见。

3. **框架数量限制:**
    *   `MaxNumberOfFrames()`: 获取页面允许的最大框架数量，该值可能在测试中被临时设置为较小的值。
    *   `SetMaxNumberOfFramesToTenForTesting(bool enabled)`:  用于测试，设置最大框架数量为 10。
    *   `SubframeCount()`: 获取当前页面的子框架数量（不包括主框架）。内部包含 `CheckFrameCountConsistency` 进行断言检查框架数量的一致性，考虑到 Fenced Frames。

4. **安全区域插值 (Safe Area Insets) 管理:**
    *   `UpdateSafeAreaInsetWithBrowserControls()`: 根据浏览器控件的状态更新安全区域插值，用于避免内容被设备刘海等遮挡。
    *   `SetMaxSafeAreaInsets()`: 设置最大的安全区域插值。
    *   `SetSafeAreaEnvVariables()`:  （虽然代码中没有直接展示，但从上下文推断）设置安全区域相关的环境变量，供渲染使用。

5. **页面设置变更处理 (`SettingsChanged`)**:  当页面设置发生改变时，执行相应的操作。这是该文件中非常核心的一个功能，涵盖了多种设置变更：
    *   `ChangeType::kStyle`: 触发初始样式变更。 **(CSS)**
    *   `ChangeType::kViewportDescription`: 更新视口描述信息，并更新所有框架的文本自动缩放信息。 **(HTML)**
    *   `ChangeType::kViewportPaintProperties`:  更新视口相关的绘制属性。
    *   `ChangeType::kDNSPrefetching`:  初始化所有框架的 DNS 预取。
    *   `ChangeType::kImageLoading`:  通知加载器关于图片加载设置的变更。
    *   `ChangeType::kTextAutosizing`: 更新文本自动缩放设置，可能触发样式失效。
    *   `ChangeType::kFontFamily`: 更新通用字体族设置。 **(CSS)**
    *   `ChangeType::kAcceleratedCompositing`: 更新加速合成设置。
    *   `ChangeType::kMediaQuery`:  通知所有框架媒体查询相关的设置已变更。 **(CSS, JavaScript)**
    *   `ChangeType::kAccessibilityState`: 刷新可访问性树。
    *   `ChangeType::kViewportStyle`: 更新视口样式设置。 **(CSS)**
    *   `ChangeType::kTextTrackKindUserPreference`: 为所有媒体元素设置文本轨道类型的用户偏好。 **(HTML)**
    *   `ChangeType::kDOMWorlds`: 强制初始化 DOM Worlds。
    *   `ChangeType::kMediaControls`: 通知媒体元素控制条启用状态的改变。 **(HTML)**
    *   `ChangeType::kPlugins`: 通知插件已变更。
    *   `ChangeType::kHighlightAds`: 更新广告高亮显示。
    *   `ChangeType::kPaint`: 触发重绘。
    *   `ChangeType::kScrollbarLayout`: 标记需要重新布局的滚动区域。
    *   `ChangeType::kColorScheme`:  通知所有框架配色方案已变更。 **(CSS, JavaScript)**
    *   `ChangeType::kUniversalAccess`: 处理允许从文件 URL 进行通用访问的情况。
    *   `ChangeType::kVisionDeficiency`: 通知文档视觉障碍设置已变更。
    *   `ChangeType::kForcedColors`: 处理强制颜色模式的变更。 **(CSS)**

6. **失效 (Invalidation) 相关:**
    *   `InvalidateColorScheme()`:  通知所有框架配色方案已变更，可能触发 `navigator.preferences` 的变更事件。 **(CSS, JavaScript)**
    *   `InvalidatePaint()`:  使整个页面失效，触发重绘。

7. **插件变更通知:**
    *   `NotifyPluginsChanged()`: 通知所有注册的观察者插件已变更。

8. **加速合成设置更新:**
    *   `UpdateAcceleratedCompositingSettings()`: 更新加速合成相关的设置，并标记需要更新绘制属性的滚动区域。

9. **页面加载提交处理 (`DidCommitLoad`)**: 在页面加载提交后执行的操作，例如清除控制台消息，重置链接高亮等。

10. **语言偏好变更处理 (`AcceptLanguagesChanged`)**:  通知页面的 DOMWindow 接受的语言已变更。 **(JavaScript)**

11. **生命周期管理和追踪:**
    *   `Trace()`: 用于调试和追踪对象的生命周期。
    *   `DidInitializeCompositing()`:  在合成器初始化后进行相关操作，如初始化链接高亮的动画宿主。
    *   `WillStopCompositing()`: 在停止合成前执行清理工作。
    *   `WillBeDestroyed()`:  在页面即将被销毁时执行清理工作，包括断开主框架的连接，从全局列表中移除自身等。

12. **插件变更观察者注册:**
    *   `RegisterPluginsChangedObserver()`:  注册插件变更的观察者。

13. **滚动条主题获取:**
    *   `GetScrollbarTheme()`:  获取当前页面的滚动条主题。

14. **代理组调度器和页面调度器获取:**
    *   `GetAgentGroupScheduler()`: 获取代理组调度器。
    *   `GetPageScheduler()`: 获取页面调度器。

15. **页面类型判断:**
    *   `IsOrdinary()`: 判断页面是否为普通页面。

16. **主帧开始请求的预期状态:**
    *   `RequestBeginMainFrameNotExpected()`: 通知 ChromeClient 主帧开始请求是否为非预期状态。

17. **自动播放标志管理:**
    *   `AddAutoplayFlags()`: 添加自动播放相关的标志。
    *   `ClearAutoplayFlags()`: 清除自动播放相关的标志。
    *   `AutoplayFlags()`: 获取当前的自动播放标志。

18. **Fenced Frame 根判断:**
    *   `SetIsMainFrameFencedFrameRoot()`: 设置主框架是否为 Fenced Frame 树的根。
    *   `IsMainFrameFencedFrameRoot()`: 判断主框架是否为 Fenced Frame 树的根。

19. **媒体特性和偏好覆盖:**
    *   `SetMediaFeatureOverride()`:  覆盖指定的媒体特性值。 **(CSS, JavaScript)**
    *   `ClearMediaFeatureOverrides()`: 清除媒体特性覆盖。
    *   `SetPreferenceOverride()`: 覆盖指定的偏好特性值。 **(JavaScript)**
    *   `ClearPreferenceOverrides()`: 清除偏好特性覆盖。

20. **视觉障碍模拟:**
    *   `SetVisionDeficiency()`: 设置模拟的视觉障碍类型。

21. **动画处理:**
    *   `Animate()`:  驱动页面上的动画，包括自动滚动和脚本控制的动画。

22. **生命周期更新:**
    *   `UpdateLifecycle()`:  根据请求的更新类型更新页面的生命周期状态。

23. **浏览上下文组管理:**
    *   `BrowsingContextGroupToken()`: 获取浏览上下文组的 Token。
    *   `CoopRelatedGroupToken()`: 获取 COOP 相关的组 Token。
    *   `UpdateBrowsingContextGroup()`: 更新浏览上下文组信息。

24. **Attribution 支持:**
    *   `SetAttributionSupport()`: 设置归因报告 API 的支持级别。

25. **泄漏检测准备:**
    *   `PrepareForLeakDetection()`:  在进行泄漏检测前清理一些可能持有引用的对象。

**与 JavaScript, HTML, CSS 的关系举例:**

*   **JavaScript:**
    *   `IsPageVisible()` 的状态变化会触发 JavaScript 的 `visibilitychange` 事件。
    *   `SettingsChanged` 中 `ChangeType::kMediaQuery` 和 `ChangeType::kColorScheme` 的改变会影响 JavaScript 中通过 `matchMedia()` 查询媒体查询结果。
    *   `AcceptLanguagesChanged()` 会触发 `LocalDOMWindow` 的事件，JavaScript 可以监听这些事件来获取语言偏好变更。
    *   `SetMediaFeatureOverride()` 和 `SetPreferenceOverride()` 可以通过 Blink 提供的接口影响 JavaScript 中对媒体特性和用户偏好的读取。

*   **HTML:**
    *   `MaxNumberOfFrames()` 限制了页面中 `<iframe>` 和 `<fencedframe>` 元素的数量。
    *   `SettingsChanged` 中 `ChangeType::kViewportDescription` 的改变会影响 HTML 中 `<meta name="viewport">` 标签的解析和应用。
    *   `SettingsChanged` 中 `ChangeType::kTextTrackKindUserPreference` 会影响 `<video>` 或 `<audio>` 元素中 `<track>` 标签的行为。
    *   `SettingsChanged` 中 `ChangeType::kMediaControls` 会影响 `<video>` 或 `<audio>` 元素的默认控制条是否显示。

*   **CSS:**
    *   `UpdateSafeAreaInsetWithBrowserControls()` 会影响 CSS 中 `safe-area-inset-*` 环境变量的值，从而影响页面的布局。
    *   `SettingsChanged` 中 `ChangeType::kStyle`, `ChangeType::kFontFamily`, `ChangeType::kViewportStyle`, `ChangeType::kColorScheme`, `ChangeType::kForcedColors` 等都会直接影响 CSS 的解析和渲染结果。
    *   `SetMediaFeatureOverride()` 可以强制覆盖某些 CSS 媒体查询的结果，例如 `prefers-color-scheme`。

**逻辑推理的假设输入与输出:**

假设输入 `Page` 对象当前状态为 `lifecycle_state_->visibility` 为 `mojom::blink::PageVisibilityState::kHidden`。

*   **输入:** 调用 `IsPageVisible()`。
*   **输出:** `false`。

假设输入 `Page` 对象的 `g_limit_max_frames_to_ten_for_testing` 为 `true`。

*   **输入:** 调用 `MaxNumberOfFrames()`。
*   **输出:** `kTenFrames` 的值（假设为 10）。

**用户或编程常见的使用错误举例:**

*   **错误地假设 `IsPageVisible()` 在 `pagehide` 事件触发后立即返回 `false`:**  实际上，页面可能在 `pagehide` 事件分发后仍然短暂可见，需要使用 `DispatchedPagehideAndStillHidden()` 或 `DispatchedPagehidePersistedAndStillHidden()` 来更准确地判断。
*   **在不理解 `SettingsChanged` 的情况下，直接修改某些底层数据，而没有调用 `SettingsChanged` 来触发相应的更新:** 这可能导致页面状态不一致，例如修改了字体设置但没有通知渲染器更新字体。
*   **在测试环境下忘记调用 `SetMaxNumberOfFramesToTenForTesting(false)` 导致一些预期之外的框架创建失败:** 这会影响依赖于框架数量的应用逻辑。

**用户操作如何一步步到达这里作为调试线索:**

1. **用户打开一个网页:**  创建 `Page` 对象，设置初始状态。
2. **用户滚动页面:** 可能触发安全区域插值的更新 (`UpdateSafeAreaInsetWithBrowserControls`)。
3. **用户调整浏览器设置 (例如，更改主题，缩放级别，字体大小等):**  触发 `SettingsChanged`，根据具体的设置变更类型执行相应的代码分支。
4. **用户最小化或切换标签页:**  触发页面可见性状态的改变，调用 `OnSetPageFrozen`，`lifecycle_state_->visibility` 的值会发生变化。
5. **页面加载新的资源 (图片，字体等):**  可能触发 `SettingsChanged` 中与资源加载相关的分支。
6. **网站使用 JavaScript API 修改页面样式或执行动画:**  可能间接导致需要调用 `InvalidatePaint` 或 `InvalidateColorScheme`。
7. **用户安装或卸载浏览器插件:**  触发 `NotifyPluginsChanged`。
8. **用户导航到新的页面或刷新当前页面:**  触发 `DidCommitLoad`。

通过分析这些用户操作和对应的代码执行路径，可以帮助开发者理解代码的执行逻辑，排查问题。例如，如果在调整浏览器主题后页面样式没有正确更新，可以检查 `SettingsChanged` 中 `ChangeType::kColorScheme` 的处理逻辑是否正确。

### 提示词
```
这是目录为blink/renderer/core/page/page.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
cycle_state_->visibility;
}

bool Page::IsPageVisible() const {
  return lifecycle_state_->visibility ==
         mojom::blink::PageVisibilityState::kVisible;
}

bool Page::DispatchedPagehideAndStillHidden() {
  return lifecycle_state_->pagehide_dispatch !=
         mojom::blink::PagehideDispatch::kNotDispatched;
}

bool Page::DispatchedPagehidePersistedAndStillHidden() {
  return lifecycle_state_->pagehide_dispatch ==
         mojom::blink::PagehideDispatch::kDispatchedPersisted;
}

void Page::OnSetPageFrozen(bool frozen) {
  if (frozen_ == frozen)
    return;
  frozen_ = frozen;

  for (Frame* frame = main_frame_.Get(); frame;
       frame = frame->Tree().TraverseNext()) {
    if (auto* local_frame = DynamicTo<LocalFrame>(frame)) {
      local_frame->OnPageLifecycleStateUpdated();
    }
  }
}

bool Page::IsCursorVisible() const {
  return is_cursor_visible_;
}

// static
int Page::MaxNumberOfFrames() {
  if (g_limit_max_frames_to_ten_for_testing) [[unlikely]] {
    return kTenFrames;
  }
  return kMaxNumberOfFrames;
}

// static
void Page::SetMaxNumberOfFramesToTenForTesting(bool enabled) {
  g_limit_max_frames_to_ten_for_testing = enabled;
}

#if DCHECK_IS_ON()
void CheckFrameCountConsistency(int expected_frame_count, Frame* frame) {
  DCHECK_GE(expected_frame_count, 0);

  int actual_frame_count = 0;

  for (; frame; frame = frame->Tree().TraverseNext()) {
    ++actual_frame_count;

    // Check the ``DocumentFencedFrames`` on every local frame beneath
    // the ``frame`` to get an accurate count (i.e. if an iframe embeds
    // a fenced frame and creates a new ``DocumentFencedFrames`` object).
    if (auto* local_frame = DynamicTo<LocalFrame>(frame)) {
      if (auto* fenced_frames =
              DocumentFencedFrames::Get(*local_frame->GetDocument())) {
        actual_frame_count +=
            static_cast<int>(fenced_frames->GetFencedFrames().size());
      }
    }
  }

  DCHECK_EQ(expected_frame_count, actual_frame_count);
}
#endif

int Page::SubframeCount() const {
#if DCHECK_IS_ON()
  CheckFrameCountConsistency(subframe_count_ + 1, MainFrame());
#endif
  return subframe_count_;
}

void Page::UpdateSafeAreaInsetWithBrowserControls(
    const BrowserControls& browser_controls,
    bool force_update) {
  DCHECK(GetSettings().GetDynamicSafeAreaInsetsEnabled());

  if (!DeprecatedLocalMainFrame()) {
    return;
  }

  if (Fullscreen::HasFullscreenElements() && !force_update) {
    LOG(WARNING) << "Attempt to set SAI with browser controls in fullscreen.";
    return;
  }

  gfx::Insets new_safe_area = gfx::Insets::TLBR(
      max_safe_area_insets_.top(), max_safe_area_insets_.left(),
      max_safe_area_insets_.bottom(), max_safe_area_insets_.right());
  if (max_safe_area_insets_.bottom() > 0) {
    // Adjust the top / left / right is not needed, since they are set when
    // display insets was received at |SetSafeArea()|.
    int inset_bottom = max_safe_area_insets_.bottom();
    int bottom_controls_full_height = browser_controls.BottomHeight();
    float control_ratio = browser_controls.BottomShownRatio();
    float dip_scale = chrome_client_->GetScreenInfo(*DeprecatedLocalMainFrame())
                          .device_scale_factor;

    // As control_ratio decrease, safe_area_inset_bottom will be added to the
    // web page to keep the bottom element out from the display cutout area.
    float safe_area_inset_bottom = std::max(
        0.f,
        inset_bottom - control_ratio * bottom_controls_full_height / dip_scale);

    new_safe_area.set_bottom(safe_area_inset_bottom);
  }

  if (new_safe_area != applied_safe_area_insets_ || force_update) {
    applied_safe_area_insets_ = new_safe_area;
    SetSafeAreaEnvVariables(DeprecatedLocalMainFrame(), new_safe_area);
  }
}

void Page::SetMaxSafeAreaInsets(LocalFrame* setter, gfx::Insets max_safe_area) {
  max_safe_area_insets_ = max_safe_area;

  // When the SAI is changed when DynamicSafeAreaInsetsEnabled, the SAI for the
  // main frame needs to be set per browser controls state.
  if (GetSettings().GetDynamicSafeAreaInsetsEnabled() &&
      setter->IsMainFrame()) {
    UpdateSafeAreaInsetWithBrowserControls(GetBrowserControls(), true);
  } else {
    SetSafeAreaEnvVariables(setter, max_safe_area);
  }
}

void Page::SettingsChanged(ChangeType change_type) {
  switch (change_type) {
    case ChangeType::kStyle:
      InitialStyleChanged();
      break;
    case ChangeType::kViewportDescription:
      if (MainFrame() && MainFrame()->IsLocalFrame()) {
        DeprecatedLocalMainFrame()
            ->GetDocument()
            ->GetViewportData()
            .UpdateViewportDescription();
        // The text autosizer has dependencies on the viewport. Viewport
        // description only applies to the main frame. On a viewport description
        // change; any changes will be calculated starting from the local main
        // frame renderer and propagated to the OOPIF renderers.
        TextAutosizer::UpdatePageInfoInAllFrames(MainFrame());
      }
      break;
    case ChangeType::kViewportPaintProperties:
      if (GetVisualViewport().IsActiveViewport()) {
        GetVisualViewport().SetNeedsPaintPropertyUpdate();
        GetVisualViewport().InitializeScrollbars();
      }
      if (auto* local_frame = DynamicTo<LocalFrame>(MainFrame())) {
        if (LocalFrameView* view = local_frame->View())
          view->SetNeedsPaintPropertyUpdate();
      }
      break;
    case ChangeType::kDNSPrefetching:
      for (Frame* frame = MainFrame(); frame;
           frame = frame->Tree().TraverseNext()) {
        if (auto* local_frame = DynamicTo<LocalFrame>(frame))
          local_frame->GetDocument()->InitDNSPrefetch();
      }
      break;
    case ChangeType::kImageLoading:
      for (Frame* frame = MainFrame(); frame;
           frame = frame->Tree().TraverseNext()) {
        if (auto* local_frame = DynamicTo<LocalFrame>(frame)) {
          // Notify the fetcher that the image loading setting has changed,
          // which may cause previously deferred requests to load.
          local_frame->GetDocument()->Fetcher()->ReloadImagesIfNotDeferred();
          local_frame->GetDocument()->Fetcher()->SetAutoLoadImages(
              GetSettings().GetLoadsImagesAutomatically());
        }
      }
      break;
    case ChangeType::kTextAutosizing:
      if (!MainFrame())
        break;
      // We need to update even for remote main frames since this setting
      // could be changed via InternalSettings.
      TextAutosizer::UpdatePageInfoInAllFrames(MainFrame());
      // The new text-size-adjust implementation requires the text autosizing
      // setting but applies the adjustment in style rather than via the text
      // autosizer, so we need to invalidate style.
      if (RuntimeEnabledFeatures::TextSizeAdjustImprovementsEnabled()) {
        InitialStyleChanged();
      }
      break;
    case ChangeType::kFontFamily:
      for (Frame* frame = MainFrame(); frame;
           frame = frame->Tree().TraverseNext()) {
        if (auto* local_frame = DynamicTo<LocalFrame>(frame))
          local_frame->GetDocument()
              ->GetStyleEngine()
              .UpdateGenericFontFamilySettings();
      }
      break;
    case ChangeType::kAcceleratedCompositing:
      UpdateAcceleratedCompositingSettings();
      break;
    case ChangeType::kMediaQuery:
      for (Frame* frame = MainFrame(); frame;
           frame = frame->Tree().TraverseNext()) {
        if (auto* local_frame = DynamicTo<LocalFrame>(frame)) {
          local_frame->GetDocument()->MediaQueryAffectingValueChanged(
              MediaValueChange::kOther);
          if (RuntimeEnabledFeatures::WebPreferencesEnabled()) {
            auto* navigator = local_frame->DomWindow()->navigator();
            if (auto* preferences =
                    NavigatorPreferences::preferences(*navigator)) {
              preferences->PreferenceMaybeChanged();
            }
          }
        }
      }
      break;
    case ChangeType::kAccessibilityState:
      if (!MainFrame() || !MainFrame()->IsLocalFrame()) {
        break;
      }
      DeprecatedLocalMainFrame()->GetDocument()->RefreshAccessibilityTree();
      break;
    case ChangeType::kViewportStyle: {
      auto* main_local_frame = DynamicTo<LocalFrame>(MainFrame());
      if (!main_local_frame)
        break;
      if (Document* doc = main_local_frame->GetDocument())
        doc->GetStyleEngine().ViewportStyleSettingChanged();
      break;
    }
    case ChangeType::kTextTrackKindUserPreference:
      for (Frame* frame = MainFrame(); frame;
           frame = frame->Tree().TraverseNext()) {
        if (auto* local_frame = DynamicTo<LocalFrame>(frame)) {
          Document* doc = local_frame->GetDocument();
          if (doc)
            HTMLMediaElement::SetTextTrackKindUserPreferenceForAllMediaElements(
                doc);
        }
      }
      break;
    case ChangeType::kDOMWorlds: {
      if (!GetSettings().GetForceMainWorldInitialization())
        break;
      for (Frame* frame = MainFrame(); frame;
           frame = frame->Tree().TraverseNext()) {
        if (auto* window = DynamicTo<LocalDOMWindow>(frame->DomWindow())) {
          // Forcibly instantiate WindowProxy.
          window->GetScriptController().WindowProxy(
              DOMWrapperWorld::MainWorld(window->GetIsolate()));
        }
      }
      break;
    }
    case ChangeType::kMediaControls:
      for (Frame* frame = MainFrame(); frame;
           frame = frame->Tree().TraverseNext()) {
        auto* local_frame = DynamicTo<LocalFrame>(frame);
        if (!local_frame)
          continue;
        Document* doc = local_frame->GetDocument();
        if (doc)
          HTMLMediaElement::OnMediaControlsEnabledChange(doc);
      }
      break;
    case ChangeType::kPlugins: {
      NotifyPluginsChanged();
      break;
    }
    case ChangeType::kHighlightAds: {
      for (Frame* frame = MainFrame(); frame;
           frame = frame->Tree().TraverseNext()) {
        if (auto* local_frame = DynamicTo<LocalFrame>(frame))
          local_frame->UpdateAdHighlight();
      }
      break;
    }
    case ChangeType::kPaint: {
      InvalidatePaint();
      break;
    }
    case ChangeType::kScrollbarLayout: {
      for (Frame* frame = MainFrame(); frame;
           frame = frame->Tree().TraverseNext()) {
        auto* local_frame = DynamicTo<LocalFrame>(frame);
        if (!local_frame)
          continue;
        // Iterate through all of the scrollable areas and mark their layout
        // objects for layout.
        if (LocalFrameView* view = local_frame->View()) {
          for (const auto& scrollable_area : view->ScrollableAreas().Values()) {
            if (scrollable_area->ScrollsOverflow()) {
              if (auto* layout_box = scrollable_area->GetLayoutBox()) {
                layout_box->SetNeedsLayout(
                    layout_invalidation_reason::kScrollbarChanged);
              }
            }
          }
        }
      }
      break;
    }
    case ChangeType::kColorScheme:
      InvalidateColorScheme();
      break;
    case ChangeType::kUniversalAccess: {
      if (!GetSettings().GetAllowUniversalAccessFromFileURLs())
        break;
      for (Frame* frame = MainFrame(); frame;
           frame = frame->Tree().TraverseNext()) {
        // If we got granted universal access from file urls we need to grant
        // any outstanding security origin cross agent cluster access since
        // newly allocated agent clusters will be the universal agent.
        if (auto* local_frame = DynamicTo<LocalFrame>(frame)) {
          auto* window = local_frame->DomWindow();
          window->GetMutableSecurityOrigin()->GrantCrossAgentClusterAccess();
        }
      }
      break;
    }
    case ChangeType::kVisionDeficiency: {
      if (auto* main_local_frame = DynamicTo<LocalFrame>(MainFrame()))
        main_local_frame->GetDocument()->VisionDeficiencyChanged();
      break;
    }
    case ChangeType::kForcedColors: {
      ForcedColorsChanged();
      break;
    }
  }
}

void Page::InvalidateColorScheme() {
  for (Frame* frame = MainFrame(); frame;
       frame = frame->Tree().TraverseNext()) {
    if (auto* local_frame = DynamicTo<LocalFrame>(frame)) {
      local_frame->GetDocument()->ColorSchemeChanged();
      if (RuntimeEnabledFeatures::WebPreferencesEnabled()) {
        auto* navigator = local_frame->DomWindow()->navigator();
        if (auto* preferences = NavigatorPreferences::preferences(*navigator)) {
          preferences->PreferenceMaybeChanged();
        }
      }
    }
  }
}

void Page::InvalidatePaint() {
  for (Frame* frame = MainFrame(); frame;
       frame = frame->Tree().TraverseNext()) {
    auto* local_frame = DynamicTo<LocalFrame>(frame);
    if (!local_frame)
      continue;
    if (LayoutView* view = local_frame->ContentLayoutObject())
      view->InvalidatePaintForViewAndDescendants();
  }
}

void Page::NotifyPluginsChanged() const {
  HeapVector<Member<PluginsChangedObserver>, 32> observers(
      plugins_changed_observers_);
  for (PluginsChangedObserver* observer : observers)
    observer->PluginsChanged();
}

void Page::UpdateAcceleratedCompositingSettings() {
  for (Frame* frame = MainFrame(); frame;
       frame = frame->Tree().TraverseNext()) {
    auto* local_frame = DynamicTo<LocalFrame>(frame);
    if (!local_frame)
      continue;
    // Mark all scrollable areas as needing a paint property update because the
    // compositing reasons may have changed.
    if (LocalFrameView* view = local_frame->View()) {
      for (const auto& scrollable_area : view->ScrollableAreas().Values()) {
        if (scrollable_area->ScrollsOverflow()) {
          if (auto* layout_box = scrollable_area->GetLayoutBox()) {
            layout_box->SetNeedsPaintPropertyUpdate();
          }
        }
      }
    }
  }
}

void Page::DidCommitLoad(LocalFrame* frame) {
  if (main_frame_ == frame) {
    GetConsoleMessageStorage().Clear();
    GetInspectorIssueStorage().Clear();
    // TODO(loonybear): Most of this doesn't appear to take into account that
    // each SVGImage gets it's own Page instance.
    GetDeprecation().ClearSuppression();
    // Need to reset visual viewport position here since before commit load we
    // would update the previous history item, Page::didCommitLoad is called
    // after a new history item is created in FrameLoader.
    // See crbug.com/642279
    GetVisualViewport().SetScrollOffset(ScrollOffset(),
                                        mojom::blink::ScrollType::kProgrammatic,
                                        mojom::blink::ScrollBehavior::kInstant,
                                        ScrollableArea::ScrollCallback());
  }
  // crbug/1312107: If DevTools has "Highlight ad frames" checked when the
  // main frame is refreshed or the ad frame is navigated to a different
  // process, DevTools calls `Settings::SetHighlightAds` so early that the
  // local frame is still in provisional state (not swapped in). Explicitly
  // invalidate the settings here as `Page::DidCommitLoad` is only fired after
  // the navigation is committed, at which point the local frame must already
  // be swapped-in.
  //
  // This explicit update is placed outside the above if-block to accommodate
  // iframes. The iframes share the same Page (frame tree) as the main frame,
  // but local frame swap can happen to any of the iframes.
  //
  // TODO(crbug/1357763): Properly apply the settings when the local frame
  // becomes the main frame of the page (i.e. when the navigation is
  // committed).
  frame->UpdateAdHighlight();
  GetLinkHighlight().ResetForPageNavigation();
}

void Page::AcceptLanguagesChanged() {
  HeapVector<Member<LocalFrame>> frames;

  // Even though we don't fire an event from here, the LocalDOMWindow's will
  // fire an event so we keep the frames alive until we are done.
  for (Frame* frame = MainFrame(); frame;
       frame = frame->Tree().TraverseNext()) {
    if (auto* local_frame = DynamicTo<LocalFrame>(frame))
      frames.push_back(local_frame);
  }

  for (unsigned i = 0; i < frames.size(); ++i)
    frames[i]->DomWindow()->AcceptLanguagesChanged();
}

void Page::Trace(Visitor* visitor) const {
  visitor->Trace(animator_);
  visitor->Trace(autoscroll_controller_);
  visitor->Trace(chrome_client_);
  visitor->Trace(drag_caret_);
  visitor->Trace(drag_controller_);
  visitor->Trace(focus_controller_);
  visitor->Trace(context_menu_controller_);
  visitor->Trace(page_scale_constraints_set_);
  visitor->Trace(page_visibility_observer_set_);
  visitor->Trace(pointer_lock_controller_);
  visitor->Trace(scrolling_coordinator_);
  visitor->Trace(browser_controls_);
  visitor->Trace(console_message_storage_);
  visitor->Trace(global_root_scroller_controller_);
  visitor->Trace(visual_viewport_);
  visitor->Trace(link_highlight_);
  visitor->Trace(spatial_navigation_controller_);
  visitor->Trace(svg_resource_document_cache_);
  visitor->Trace(main_frame_);
  visitor->Trace(previous_main_frame_for_local_swap_);
  visitor->Trace(plugin_data_);
  visitor->Trace(validation_message_client_);
  visitor->Trace(plugins_changed_observers_);
  visitor->Trace(next_related_page_);
  visitor->Trace(prev_related_page_);
  visitor->Trace(agent_group_scheduler_);
  visitor->Trace(v8_compile_hints_producer_);
  visitor->Trace(v8_compile_hints_consumer_);
  visitor->Trace(close_task_handler_);
  visitor->Trace(opener_);
  Supplementable<Page>::Trace(visitor);
}

void Page::DidInitializeCompositing(cc::AnimationHost& host) {
  GetLinkHighlight().AnimationHostInitialized(host);
}

void Page::WillStopCompositing() {
  GetLinkHighlight().WillCloseAnimationHost();
  // We may have disconnected the associated LayerTreeHost during
  // the frame lifecycle so ensure the PageAnimator is reset to the
  // default state.
  animator_->SetSuppressFrameRequestsWorkaroundFor704763Only(false);
}

void Page::WillBeDestroyed() {
  Frame* main_frame = main_frame_;

  // TODO(https://crbug.com/838348): Sadly, there are situations where Blink may
  // attempt to detach a main frame twice due to a bug. That rewinds
  // FrameLifecycle from kDetached to kDetaching, but GetPage() will already be
  // null. Since Detach() has already happened, just skip the actual Detach()
  // call to try to limit the side effects of this bug on the rest of frame
  // detach.
  if (main_frame->GetPage()) {
    main_frame->Detach(FrameDetachType::kRemove);
  }

  // Only begin clearing state after JS has run, since running JS itself can
  // sometimes alter Page's state.
  DCHECK(AllPages().Contains(this));
  AllPages().erase(this);
  OrdinaryPages().erase(this);

  {
    // Before: ... -> prev -> this -> next -> ...
    // After: ... -> prev -> next -> ...
    // (this is ok even if |this| is the only element on the list).
    Page* prev = prev_related_page_;
    Page* next = next_related_page_;
    next->prev_related_page_ = prev;
    prev->next_related_page_ = next;
    prev_related_page_ = nullptr;
    next_related_page_ = nullptr;
  }

  if (svg_resource_document_cache_) {
    svg_resource_document_cache_->WillBeDestroyed();
  }

  if (scrolling_coordinator_)
    scrolling_coordinator_->WillBeDestroyed();

  GetChromeClient().ChromeDestroyed();
  if (validation_message_client_)
    validation_message_client_->WillBeDestroyed();
  main_frame_ = nullptr;

  for (auto observer : page_visibility_observer_set_) {
    observer->ObserverSetWillBeCleared();
  }
  page_visibility_observer_set_.clear();

  page_scheduler_ = nullptr;

  if (close_task_handler_) {
    close_task_handler_->SetPage(nullptr);
    close_task_handler_ = nullptr;
  }
}

void Page::RegisterPluginsChangedObserver(PluginsChangedObserver* observer) {
  plugins_changed_observers_.insert(observer);
}

ScrollbarTheme& Page::GetScrollbarTheme() const {
  if (settings_->GetForceAndroidOverlayScrollbar())
    return ScrollbarThemeOverlayMobile::GetInstance();

  // Ensures that renderer preferences are set.
  DCHECK(main_frame_);
  return ScrollbarTheme::GetTheme();
}

AgentGroupScheduler& Page::GetAgentGroupScheduler() const {
  return *agent_group_scheduler_;
}

PageScheduler* Page::GetPageScheduler() const {
  DCHECK(page_scheduler_);
  return page_scheduler_.get();
}

bool Page::IsOrdinary() const {
  return is_ordinary_;
}

bool Page::RequestBeginMainFrameNotExpected(bool new_state) {
  if (!main_frame_ || !main_frame_->IsLocalFrame())
    return false;

  chrome_client_->RequestBeginMainFrameNotExpected(*DeprecatedLocalMainFrame(),
                                                   new_state);
  return true;
}

void Page::AddAutoplayFlags(int32_t value) {
  autoplay_flags_ |= value;
}

void Page::ClearAutoplayFlags() {
  autoplay_flags_ = 0;
}

int32_t Page::AutoplayFlags() const {
  return autoplay_flags_;
}

void Page::SetIsMainFrameFencedFrameRoot() {
  is_fenced_frame_tree_ = true;
}

bool Page::IsMainFrameFencedFrameRoot() const {
  return is_fenced_frame_tree_;
}

void Page::SetMediaFeatureOverride(const AtomicString& media_feature,
                                   const String& value) {
  if (!media_feature_overrides_) {
    if (value.empty())
      return;
    media_feature_overrides_ = std::make_unique<MediaFeatureOverrides>();
  }

  const Document* document = nullptr;
  if (auto* local_frame = DynamicTo<LocalFrame>(MainFrame())) {
    document = local_frame->GetDocument();
  }

  media_feature_overrides_->SetOverride(media_feature, value, document);
  if (media_feature == "prefers-color-scheme" ||
      media_feature == "forced-colors")
    SettingsChanged(ChangeType::kColorScheme);
  else
    SettingsChanged(ChangeType::kMediaQuery);
}

void Page::ClearMediaFeatureOverrides() {
  media_feature_overrides_.reset();
  SettingsChanged(ChangeType::kMediaQuery);
  SettingsChanged(ChangeType::kColorScheme);
}

void Page::SetPreferenceOverride(const AtomicString& media_feature,
                                 const String& value) {
  if (!preference_overrides_) {
    if (value.empty()) {
      return;
    }
    preference_overrides_ = std::make_unique<PreferenceOverrides>();
  }

  const Document* document = nullptr;
  if (auto* local_frame = DynamicTo<LocalFrame>(MainFrame())) {
    document = local_frame->GetDocument();
  }

  preference_overrides_->SetOverride(media_feature, value, document);
  if (media_feature == "prefers-color-scheme") {
    SettingsChanged(ChangeType::kColorScheme);
  } else {
    SettingsChanged(ChangeType::kMediaQuery);
  }
}

void Page::ClearPreferenceOverrides() {
  preference_overrides_.reset();
  SettingsChanged(ChangeType::kMediaQuery);
  SettingsChanged(ChangeType::kColorScheme);
}

void Page::SetVisionDeficiency(VisionDeficiency new_vision_deficiency) {
  if (new_vision_deficiency != vision_deficiency_) {
    vision_deficiency_ = new_vision_deficiency;
    SettingsChanged(ChangeType::kVisionDeficiency);
  }
}

void Page::Animate(base::TimeTicks monotonic_frame_begin_time) {
  GetAutoscrollController().Animate();
  Animator().ServiceScriptedAnimations(monotonic_frame_begin_time);
  // The ValidationMessage overlay manages its own internal Page that isn't
  // hooked up the normal BeginMainFrame flow, so we manually tick its
  // animations here.
  GetValidationMessageClient().ServiceScriptedAnimations(
      monotonic_frame_begin_time);
}

void Page::UpdateLifecycle(LocalFrame& root,
                           WebLifecycleUpdate requested_update,
                           DocumentUpdateReason reason) {
  if (requested_update == WebLifecycleUpdate::kLayout) {
    Animator().UpdateLifecycleToLayoutClean(root, reason);
  } else if (requested_update == WebLifecycleUpdate::kPrePaint) {
    Animator().UpdateAllLifecyclePhasesExceptPaint(root, reason);
  } else {
    Animator().UpdateAllLifecyclePhases(root, reason);
  }
}

const base::UnguessableToken& Page::BrowsingContextGroupToken() {
  return browsing_context_group_info_.browsing_context_group_token;
}

const base::UnguessableToken& Page::CoopRelatedGroupToken() {
  return browsing_context_group_info_.coop_related_group_token;
}

void Page::UpdateBrowsingContextGroup(
    const blink::BrowsingContextGroupInfo& browsing_context_group_info) {
  if (browsing_context_group_info_ == browsing_context_group_info) {
    return;
  }

  if (base::FeatureList::IsEnabled(
          features::kPausePagesPerBrowsingContextGroup) &&
      ScopedBrowsingContextGroupPauser::IsActive(*this)) {
    CHECK(paused_);
    SetPaused(false);
  }

  browsing_context_group_info_ = browsing_context_group_info;

  if (base::FeatureList::IsEnabled(
          features::kPausePagesPerBrowsingContextGroup) &&
      ScopedBrowsingContextGroupPauser::IsActive(*this)) {
    SetPaused(true);
  }
}

void Page::SetAttributionSupport(
    network::mojom::AttributionSupport attribution_support) {
  attribution_support_ = attribution_support;
}

template class CORE_TEMPLATE_EXPORT Supplement<Page>;

const char InternalSettingsPageSupplementBase::kSupplementName[] =
    "InternalSettings";

// static
void Page::PrepareForLeakDetection() {
  // Internal settings are ScriptWrappable and thus may retain documents
  // depending on whether the garbage collector(s) are able to find the settings
  // object through the Page supplement. Prepares for leak detection by removing
  // all InternalSetting objects from Pages.
  for (Page* page : OrdinaryPages()) {
    page->RemoveSupplement<InternalSettingsPageSupplementBase>();

    // V8CrowdsourcedCompileHintsProducer keeps v8::Script objects alive until
    // the page becomes interactive. Give it a chance to clean up.
    page->v8_compile_hints_producer_->ClearData();
  }
}

// Ensure the 10 bits reserved for connected frame count in NodeRareData are
// sufficient.
static_assert(kMaxNumberOfFrames <
                  (1 << NodeRareData::kConnectedFrameCountBits),
              "Frame limit should fit in rare data count");
static_assert(kTenFrames < kMaxNumberOfFrames,
              "Reduced frame limit for testing should actually be lower");

}  // namespace blink
```