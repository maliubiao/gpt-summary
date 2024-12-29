Response:
The user wants to understand the functionality of the `validation_message_overlay_delegate.cc` file in the Chromium Blink engine. I need to:

1. **Summarize the file's purpose:**  Identify the main task of this class.
2. **Relate to web technologies:** Explain how this code interacts with JavaScript, HTML, and CSS, providing concrete examples.
3. **Illustrate logic:** Demonstrate the decision-making process with input and output examples.
4. **Highlight potential errors:**  Point out common mistakes users or programmers might make that relate to this code.
5. **Describe user interaction:** Trace the steps a user might take that would lead to this code being executed.

**Plan:**

* **Identify the core function:** The class is responsible for displaying validation messages as overlays on web pages.
* **HTML interaction:**  The `WriteDocument` method generates the HTML structure for the validation bubble. I'll show the generated HTML and how it's used.
* **CSS interaction:** The code loads CSS from a resource. I'll explain how the CSS styles the bubble and its components.
* **JavaScript interaction:**  While this specific file doesn't directly execute JavaScript, I'll mention how JavaScript validation triggers this overlay.
* **Logic example:** Focus on the `AdjustBubblePosition` method and demonstrate how the position of the bubble is calculated based on the anchor element and viewport.
* **Common errors:**  Think about scenarios where the validation message might not display correctly.
* **User steps:** Describe a typical form validation scenario that triggers the overlay.
这个文件 `validation_message_overlay_delegate.cc` 的主要功能是**在 Chromium Blink 引擎中创建一个用于显示表单验证消息的浮层 (overlay)**。它负责构建、显示和定位这个验证消息气泡，使其出现在与触发验证错误的表单元素相关的位置。

下面我将详细列举其功能，并解释它与 JavaScript、HTML 和 CSS 的关系，以及提供相关的例子：

**功能列表:**

1. **创建和管理浮层页面:**
   - 当需要显示验证消息时，`ValidationMessageOverlayDelegate` 会创建一个轻量级的内部页面 (`Page` 对象) 来渲染验证消息气泡。
   - 这个内部页面拥有自己的 `LocalFrame` 和 `LocalFrameView`。
   - 使用 `WriteDocument` 方法动态生成这个内部页面的 HTML 内容。

2. **渲染验证消息内容:**
   - 接收要显示的验证消息文本 (`message_`) 和子消息文本 (`sub_message_`)。
   - 将这些文本内容填充到内部页面的 HTML 元素中（通过 `GetElementById` 获取元素并设置 `textContent`）。

3. **定位验证消息气泡:**
   - `AdjustBubblePosition` 方法负责根据锚点元素 (`anchor_`) 的位置和当前视口 (`view_rect`) 的大小，计算验证消息气泡的合适位置。
   - 考虑了气泡的大小、锚点元素的位置，以及是否需要显示顶部或底部的箭头。
   - 使用 CSS 属性（如 `left`、`top`、`transform-origin`）来定位气泡和箭头。

4. **处理动画效果:**
   - 包含了显示和隐藏动画相关的逻辑（虽然代码中主要是设置 CSS `transition` 属性，实际动画效果由 Blink 的渲染引擎处理）。
   - `StartToHide` 方法会修改气泡的 CSS 类名，触发隐藏动画。

5. **与其他 Blink 组件交互:**
   - 与 `Page`、`LocalFrame`、`LocalFrameView`、`Element` 等 Blink 核心组件交互。
   - 使用 `ChromeClient` 来处理一些浏览器级别的操作，例如动画调度。
   - 获取锚点元素的布局信息（通过 `GetLayoutObject`）。
   - 获取文档的布局缩放因子 (`LayoutZoomFactor`)。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **HTML:**
    - **功能关系:** `ValidationMessageOverlayDelegate` 通过 `WriteDocument` 方法生成了显示验证消息所需的 HTML 结构。这个 HTML 定义了气泡的容器、箭头、图标、主消息和子消息的元素。
    - **举例说明:**
      ```html
      <!DOCTYPE html>
      <head>
          <meta charset='UTF-8'>
          <meta name='color-scheme' content='light dark'>
          <style>
              /* CSS 内容，定义气泡的样式 */
          </style>
      </head>
      <body dir=ltr>
          <div id=container class="shown-initially">
              <div id=outer-arrow-top></div>
              <div id=inner-arrow-top></div>
              <div id=spacer-top></div>
              <main id=bubble-body>
                  <svg>...</svg>  <!-- 图标 -->
                  <div dir=ltr id=main-message></div> <!-- 主消息 -->
                  <div dir=ltr id=sub-message></div> <!-- 子消息 -->
              </main>
              <div id=outer-arrow-bottom></div>
              <div id=inner-arrow-bottom></div>
              <div id=spacer-bottom></div>
          </div>
      </body>
      </html>
      ```
      `WriteDocument` 方法生成的 HTML 代码包含了用于显示消息的 `div` 元素，并设置了相应的 `id`，例如 `container`、`main-message`、`sub-message` 等。

* **CSS:**
    - **功能关系:**  `ValidationMessageOverlayDelegate` 加载了名为 `IDR_VALIDATION_BUBBLE_CSS` 的 CSS 资源，用于定义验证消息气泡的样式，包括外观、颜色、字体、箭头形状、动画效果等。
    - **举例说明:**  `IDR_VALIDATION_BUBBLE_CSS` 资源中可能包含类似以下的 CSS 规则：
      ```css
      #container {
          position: absolute;
          background-color: white;
          border: 1px solid #ccc;
          border-radius: 4px;
          box-shadow: 0 2px 5px rgba(0, 0, 0, 0.2);
          padding: 10px;
          /* ... 更多样式 ... */
          transition: opacity 0.2s ease-in-out; /* 定义动画 */
      }

      #main-message {
          font-weight: bold;
      }

      .bottom-arrow #outer-arrow-bottom {
          /* 底部箭头的样式 */
      }
      ```
      这些 CSS 规则决定了验证消息气泡的视觉呈现。代码中使用 `container.setAttribute(html_names::kClassAttr, ...)` 来动态添加或修改 CSS 类名，从而应用不同的样式。

* **JavaScript:**
    - **功能关系:** 虽然这个 C++ 文件本身不包含 JavaScript 代码，但它响应了 Blink 引擎中与表单验证相关的 JavaScript 事件或操作。当 JavaScript 检测到表单元素存在验证错误时，通常会触发 Blink 引擎的内部机制来显示验证消息，最终会调用到 `ValidationMessageOverlayDelegate` 来创建和显示浮层。
    - **举例说明:**  假设有一个带有 `required` 属性的 HTML 输入框：
      ```html
      <input type="text" required id="name">
      ```
      当用户尝试提交表单时，如果 `name` 输入框为空，浏览器内置的表单验证机制会阻止提交，并且可能会触发显示验证消息。Blink 引擎会调用相应的接口，最终由 `ValidationMessageOverlayDelegate` 负责呈现这个消息。

**逻辑推理的假设输入与输出:**

**场景:**  `AdjustBubblePosition` 方法根据锚点元素和视口计算气泡位置。

**假设输入:**

* `view_rect`:  视口的矩形区域，例如 `gfx::Rect(0, 0, 800, 600)` (左上角坐标 (0,0)，宽度 800 像素，高度 600 像素)。
* `anchor_`:  指向触发验证错误的表单元素的指针，假设其在视口中的可见边界是 `gfx::Rect(100, 100, 100, 30)` (左上角坐标 (100, 100)，宽度 100 像素，高度 30 像素)。
* `bubble_size_`:  验证消息气泡的尺寸，例如 `gfx::Size(200, 80)` (宽度 200 像素，高度 80 像素)。

**逻辑推理:**

1. **计算初始的 `bubble_y`:** 默认情况下，气泡显示在锚点元素的下方，所以初始 `bubble_y` 为 `anchor_rect.bottom()`，即 `100 + 30 = 130`。
2. **检查是否超出视口底部:**  `view_rect.bottom() - anchor_rect.bottom()` 为 `600 - 130 = 470`。如果 `470 < bubble_size_.height()` (80)，则气泡会超出视口底部。在这个例子中，`470 > 80`，所以气泡可以显示在下方。
3. **计算 `bubble_x`:** 气泡的水平位置以锚点元素的中心为基准，减去气泡宽度的一半。`anchor_rect.x() + anchor_rect.width() / 2 - bubble_size_.width() / 2` 为 `100 + 100 / 2 - 200 / 2 = 50`。
4. **检查是否超出视口左右边界:** 检查 `bubble_x` 是否小于视口左边界（0）或 `bubble_x + bubble_size_.width()` 是否大于视口右边界（800）。在这个例子中，`50 >= 0` 且 `50 + 200 = 250 <= 800`，所以水平位置没有超出边界。
5. **设置气泡的 CSS 属性:**  最终，会将计算出的 `bubble_x` 和 `bubble_y` 值转换为 CSS 的 `left` 和 `top` 属性，用于定位气泡。

**假设输出:**

* 验证消息气泡会显示在锚点元素的下方，左上角坐标大约为 `(50, 130)`。
* 箭头的方向会根据气泡的位置进行调整。

**涉及用户或者编程常见的使用错误，请举例说明:**

1. **前端开发者错误地阻止了默认的表单验证行为:**  如果 JavaScript 代码中使用了 `event.preventDefault()` 或返回了 `false`，可能会阻止浏览器显示默认的验证消息。虽然 `ValidationMessageOverlayDelegate` 的代码本身没有错误，但用户可能看不到验证消息。

   **例子:**
   ```javascript
   const form = document.getElementById('myForm');
   form.addEventListener('submit', function(event) {
       if (!form.checkValidity()) {
           event.preventDefault(); // 阻止了默认的验证提示
           // 可能开发者想自定义验证提示，但没有正确实现
       }
   });
   ```

2. **CSS 样式冲突导致气泡显示异常:**  页面上的其他 CSS 样式可能意外地覆盖了验证消息气泡的样式，导致气泡显示不正确（例如，位置错误、不可见、样式错乱）。

   **例子:**  某个全局 CSS 规则意外地设置了 `position: fixed` 和 `z-index` 值，导致验证消息气泡的位置不正确或被其他元素遮挡。

3. **后端验证与前端验证不一致:**  虽然 `ValidationMessageOverlayDelegate` 处理的是前端验证消息，但如果后端验证逻辑与前端验证逻辑不一致，可能会导致用户看到不符合预期的验证消息。

   **例子:** 前端 JavaScript 只检查了必填项，但后端还检查了邮箱格式，如果用户跳过前端验证直接提交，后端可能会返回一个与前端验证不同的错误消息。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户在网页上填写表单:** 用户与网页上的表单元素进行交互，例如在文本框中输入内容、选择单选按钮或复选框等。
2. **用户触发表单验证:**  这通常发生在以下几种情况：
   - **尝试提交表单:** 用户点击提交按钮。
   - **失去焦点 (blur):** 用户将焦点从某个表单元素移开。
   - **输入时实时验证:**  有些表单会在用户输入时实时进行验证。
3. **JavaScript 或浏览器内置验证检测到错误:**  当用户的输入不符合表单元素的验证规则时（例如，必填项为空、邮箱格式不正确等），浏览器内置的表单验证机制或开发者编写的 JavaScript 验证代码会检测到这些错误.
4. **Blink 引擎接收到验证错误信息:**  浏览器将验证错误的信息传递给 Blink 渲染引擎。
5. **调用 ValidationMessageClientImpl::ShowValidationMessage:** Blink 内部会调用到 `ValidationMessageClientImpl` 的 `ShowValidationMessage` 方法，这个方法负责触发显示验证消息的操作。
6. **创建 ValidationMessageOverlayDelegate 对象:**  `ShowValidationMessage` 方法会创建一个 `ValidationMessageOverlayDelegate` 对象，并传入相关的参数，例如锚点元素、消息内容等。
7. **调用 ValidationMessageOverlayDelegate::CreatePage:**  创建 `ValidationMessageOverlayDelegate` 对象后，会调用其 `CreatePage` 方法来创建内部的浮层页面。
8. **ValidationMessageOverlayDelegate::WriteDocument 生成 HTML:**  `WriteDocument` 方法被调用，生成用于显示验证消息的 HTML 结构。
9. **加载 CSS 样式:**  加载 `IDR_VALIDATION_BUBBLE_CSS` 资源，为气泡添加样式。
10. **填充消息内容:**  将接收到的验证消息文本填充到 HTML 元素中。
11. **ValidationMessageOverlayDelegate::AdjustBubblePosition 计算位置:**  调用 `AdjustBubblePosition` 方法，根据锚点元素和视口计算气泡的显示位置。
12. **渲染浮层:** Blink 渲染引擎根据生成的 HTML、CSS 和计算出的位置信息，将验证消息气泡渲染到屏幕上。

**调试线索:**

如果在调试过程中想知道验证消息浮层是如何显示的，可以按照以下步骤进行：

1. **在 `ValidationMessageOverlayDelegate` 的关键方法中设置断点:**  例如 `CreatePage`、`WriteDocument`、`AdjustBubblePosition` 等。
2. **触发表单验证:**  在网页上进行操作，使表单元素出现验证错误。
3. **观察断点处的变量:**  查看 `anchor_` 指向的元素，`message_` 和 `sub_message_` 的内容，`view_rect` 和 `bubble_size_` 的值，以及计算出的气泡位置。
4. **检查生成的 HTML 和应用的 CSS:**  可以使用浏览器的开发者工具查看 `ValidationMessageOverlayDelegate` 创建的内部页面的 HTML 结构和应用的 CSS 样式。

通过这些步骤，可以深入了解验证消息浮层的创建、内容填充和定位过程，从而帮助调试相关的 bug。

Prompt: 
```
这是目录为blink/renderer/core/page/validation_message_overlay_delegate.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/page/validation_message_overlay_delegate.h"

#include <memory>

#include "base/memory/ptr_util.h"
#include "mojo/public/cpp/bindings/pending_remote.h"
#include "third_party/blink/public/common/storage_key/storage_key.h"
#include "third_party/blink/public/common/tokens/tokens.h"
#include "third_party/blink/public/resources/grit/blink_resources.h"
#include "third_party/blink/renderer/core/dom/dom_token_list.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/dom/events/event_dispatch_forbidden_scope.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/frame/visual_viewport.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/loader/empty_clients.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/page/page_animator.h"
#include "third_party/blink/renderer/core/page/page_popup_client.h"
#include "third_party/blink/renderer/platform/data_resource_helper.h"
#include "third_party/blink/renderer/platform/graphics/paint/cull_rect.h"
#include "third_party/blink/renderer/platform/graphics/paint/drawing_recorder.h"
#include "third_party/blink/renderer/platform/graphics/paint/paint_record_builder.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/text/platform_locale.h"
#include "third_party/blink/renderer/platform/web_test_support.h"

namespace blink {

// ChromeClient for an internal page of ValidationMessageOverlayDelegate.
class ValidationMessageChromeClient : public EmptyChromeClient {
 public:
  explicit ValidationMessageChromeClient(ChromeClient& main_chrome_client,
                                         LocalFrameView* anchor_view)
      : main_chrome_client_(main_chrome_client), anchor_view_(anchor_view) {}

  void Trace(Visitor* visitor) const override {
    visitor->Trace(main_chrome_client_);
    visitor->Trace(anchor_view_);
    EmptyChromeClient::Trace(visitor);
  }

  void ScheduleAnimation(const LocalFrameView*,
                         base::TimeDelta delay = base::TimeDelta()) override {
    // Need to pass LocalFrameView for the anchor element because the Frame for
    // this overlay doesn't have an associated WebFrameWidget, which schedules
    // animation.
    main_chrome_client_->ScheduleAnimation(anchor_view_, delay);
    anchor_view_->SetVisualViewportOrOverlayNeedsRepaint();
  }

  float WindowToViewportScalar(LocalFrame* local_frame,
                               const float scalar_value) const override {
    return main_chrome_client_->WindowToViewportScalar(local_frame,
                                                       scalar_value);
  }

 private:
  Member<ChromeClient> main_chrome_client_;
  Member<LocalFrameView> anchor_view_;
};

ValidationMessageOverlayDelegate::ValidationMessageOverlayDelegate(
    Page& main_page,
    const Element& anchor,
    const String& message,
    TextDirection message_dir,
    const String& sub_message,
    TextDirection sub_message_dir)
    : main_page_(main_page),
      anchor_(anchor),
      message_(message),
      sub_message_(sub_message),
      message_dir_(message_dir),
      sub_message_dir_(sub_message_dir) {}

ValidationMessageOverlayDelegate::~ValidationMessageOverlayDelegate() {
  if (page_) {
    // This function can be called in EventDispatchForbiddenScope for the main
    // document, and the following operations dispatch some events. It's safe
    // because the page can't listen the events.
    EventDispatchForbiddenScope::AllowUserAgentEvents allow_events;
    page_->WillBeDestroyed();
  }
  if (destroyed_ptr_)
    *destroyed_ptr_ = true;
}

LocalFrameView& ValidationMessageOverlayDelegate::FrameView() const {
  DCHECK(page_)
      << "Do not call FrameView() before the first call of CreatePage()";
  return *To<LocalFrame>(page_->MainFrame())->View();
}

void ValidationMessageOverlayDelegate::PaintFrameOverlay(
    const FrameOverlay& overlay,
    GraphicsContext& context,
    const gfx::Size& view_size) const {
  if (IsHiding() && !page_)
    return;

  if (DrawingRecorder::UseCachedDrawingIfPossible(context, overlay,
                                                  DisplayItem::kFrameOverlay))
    return;
  DrawingRecorder recorder(context, overlay, DisplayItem::kFrameOverlay,
                           gfx::Rect(view_size));
  context.DrawRecord(FrameView().GetPaintRecord());
}

void ValidationMessageOverlayDelegate::ServiceScriptedAnimations(
    base::TimeTicks monotonic_frame_begin_time) {
  page_->Animator().ServiceScriptedAnimations(monotonic_frame_begin_time);
}

void ValidationMessageOverlayDelegate::UpdateFrameViewState(
    const FrameOverlay& overlay) {
  gfx::Size view_size = overlay.Size();
  if (FrameView().Size() != view_size) {
    FrameView().Resize(view_size);
    page_->GetVisualViewport().SetSize(view_size);
  }
  gfx::Rect intersection = overlay.Frame().RemoteViewportIntersection();
  AdjustBubblePosition(intersection.IsEmpty()
                           ? gfx::Rect(gfx::Point(), view_size)
                           : intersection);

  // This manual invalidation is necessary to avoid a DCHECK failure in
  // FindVisualRectNeedingUpdateScopeBase::CheckVisualRect().
  FrameView().GetLayoutView()->SetSubtreeShouldCheckForPaintInvalidation();

  FrameView().UpdateAllLifecyclePhases(DocumentUpdateReason::kOverlay);
}

void ValidationMessageOverlayDelegate::CreatePage(const FrameOverlay& overlay) {
  DCHECK(!page_);

  // TODO(tkent): Can we share code with WebPagePopupImpl and
  // InspectorOverlayAgent?
  gfx::Size view_size = overlay.Size();
  chrome_client_ = MakeGarbageCollected<ValidationMessageChromeClient>(
      main_page_->GetChromeClient(), anchor_->GetDocument().View());
  Settings& main_settings = main_page_->GetSettings();
  page_ = Page::CreateNonOrdinary(
      *chrome_client_, main_page_->GetPageScheduler()->GetAgentGroupScheduler(),
      &main_page_->GetColorProviderColorMaps());
  page_->GetSettings().SetMinimumFontSize(main_settings.GetMinimumFontSize());
  page_->GetSettings().SetMinimumLogicalFontSize(
      main_settings.GetMinimumLogicalFontSize());

  auto* frame = MakeGarbageCollected<LocalFrame>(
      MakeGarbageCollected<EmptyLocalFrameClient>(), *page_, nullptr, nullptr,
      nullptr, FrameInsertType::kInsertInConstructor, LocalFrameToken(),
      nullptr, nullptr, mojo::NullRemote());
  frame->SetView(MakeGarbageCollected<LocalFrameView>(*frame, view_size));
  frame->Init(/*opener=*/nullptr, DocumentToken(), /*policy_container=*/nullptr,
              StorageKey(), /*document_ukm_source_id=*/ukm::kInvalidSourceId,
              /*creator_base_url=*/KURL());
  frame->View()->SetCanHaveScrollbars(false);
  frame->View()->SetBaseBackgroundColor(Color::kTransparent);
  page_->GetVisualViewport().SetSize(view_size);

  // Propagate dark mode settings from anchor document to allow CSS of
  // overlay bubble to detect dark mode. See the comments in
  // PagePopupClient::AdjustSettingsFromOwnerColorScheme for more information.
  page_->GetSettings().SetForceDarkModeEnabled(false);
  bool in_forced_colors_mode = anchor_->GetDocument().InForcedColorsMode();
  LayoutObject* anchor_layout = anchor_->GetLayoutObject();
  page_->GetSettings().SetPreferredColorScheme(
      !in_forced_colors_mode && anchor_layout &&
              anchor_layout->StyleRef().UsedColorScheme() ==
                  mojom::blink::ColorScheme::kDark
          ? mojom::blink::PreferredColorScheme::kDark
          : mojom::blink::PreferredColorScheme::kLight);

  SegmentedBuffer data;
  WriteDocument(data);
  float zoom_factor = anchor_->GetDocument().GetFrame()->LayoutZoomFactor();
  frame->SetLayoutZoomFactor(zoom_factor);

  // ForceSynchronousDocumentInstall can cause another call to
  // ValidationMessageClientImpl::ShowValidationMessage, which will hide this
  // validation message and may even delete this. In order to avoid continuing
  // when this is destroyed, |destroyed| will be set to true in the destructor.
  bool destroyed = false;
  DCHECK(!destroyed_ptr_);
  destroyed_ptr_ = &destroyed;
  frame->ForceSynchronousDocumentInstall(AtomicString("text/html"),
                                         std::move(data));
  if (destroyed)
    return;
  destroyed_ptr_ = nullptr;

  Element& main_message = GetElementById(AtomicString("main-message"));
  main_message.setTextContent(message_);
  Element& sub_message = GetElementById(AtomicString("sub-message"));
  sub_message.setTextContent(sub_message_);

  Element& container = GetElementById(AtomicString("container"));
  if (WebTestSupport::IsRunningWebTest()) {
    container.SetInlineStyleProperty(CSSPropertyID::kTransition, "none");
    GetElementById(AtomicString("icon"))
        .SetInlineStyleProperty(CSSPropertyID::kTransition, "none");
    main_message.SetInlineStyleProperty(CSSPropertyID::kTransition, "none");
    sub_message.SetInlineStyleProperty(CSSPropertyID::kTransition, "none");
  }
  // Get the size to decide position later.
  // TODO(rendering-core): This gets a size, so we should only need to update
  // to layout.
  FrameView().UpdateAllLifecyclePhases(DocumentUpdateReason::kOverlay);
  bubble_size_ = container.VisibleBoundsInLocalRoot().size();
  // Add one because the content sometimes exceeds the exact width due to
  // rounding errors.
  bubble_size_.Enlarge(1, 0);
  container.SetInlineStyleProperty(CSSPropertyID::kMinWidth,
                                   bubble_size_.width() / zoom_factor,
                                   CSSPrimitiveValue::UnitType::kPixels);
  container.setAttribute(html_names::kClassAttr,
                         AtomicString("shown-initially"));
  FrameView().UpdateAllLifecyclePhases(DocumentUpdateReason::kOverlay);
}

void ValidationMessageOverlayDelegate::WriteDocument(SegmentedBuffer& data) {
  PagePopupClient::AddString(
      "<!DOCTYPE html><head><meta charset='UTF-8'><meta name='color-scheme' "
      "content='light dark'><style>",
      data);
  data.Append(UncompressResourceAsBinary(IDR_VALIDATION_BUBBLE_CSS));
  PagePopupClient::AddString("</style></head>", data);
  PagePopupClient::AddString(
      Locale::DefaultLocale().IsRTL() ? "<body dir=rtl>" : "<body dir=ltr>",
      data);
  PagePopupClient::AddString(
      "<div id=container>"
      "<div id=outer-arrow-top></div>"
      "<div id=inner-arrow-top></div>"
      "<div id=spacer-top></div>"
      "<main id=bubble-body>",
      data);
  data.Append(UncompressResourceAsBinary(IDR_VALIDATION_BUBBLE_ICON));
  PagePopupClient::AddString(message_dir_ == TextDirection::kLtr
                                 ? "<div dir=ltr id=main-message></div>"
                                 : "<div dir=rtl id=main-message></div>",
                             data);
  PagePopupClient::AddString(sub_message_dir_ == TextDirection::kLtr
                                 ? "<div dir=ltr id=sub-message></div>"
                                 : "<div dir=rtl id=sub-message></div>",
                             data);
  PagePopupClient::AddString(
      "</main>"
      "<div id=outer-arrow-bottom></div>"
      "<div id=inner-arrow-bottom></div>"
      "<div id=spacer-bottom></div>"
      "</div></body></html>\n",
      data);
}

Element& ValidationMessageOverlayDelegate::GetElementById(
    const AtomicString& id) const {
  Element* element =
      To<LocalFrame>(page_->MainFrame())->GetDocument()->getElementById(id);
  DCHECK(element) << "No element with id=" << id
                  << ". Failed to load the document?";
  return *element;
}

void ValidationMessageOverlayDelegate::AdjustBubblePosition(
    const gfx::Rect& view_rect) {
  if (IsHiding())
    return;
  float zoom_factor = To<LocalFrame>(page_->MainFrame())->LayoutZoomFactor();
  gfx::Rect anchor_rect = anchor_->VisibleBoundsInLocalRoot();

  Page* anchor_page = anchor_->GetDocument().GetPage();
  // If the main frame is local the overlay is attached to it so we have to
  // account for the anchor's position relative to the visual viewport. If the
  // main frame is remote the overlay will be attached to the local root so the
  // visual viewport transform will already be applied to the overlay.
  if (IsA<LocalFrame>(anchor_page->MainFrame())) {
    PhysicalRect rect(anchor_rect);
    anchor_->GetDocument()
        .GetFrame()
        ->LocalFrameRoot()
        .ContentLayoutObject()
        ->MapToVisualRectInAncestorSpace(nullptr, rect);
    anchor_rect = ToPixelSnappedRect(rect);
    anchor_rect =
        anchor_page->GetVisualViewport().RootFrameToViewport(anchor_rect);
    anchor_rect.Intersect(gfx::Rect(anchor_page->GetVisualViewport().Size()));
  }

  bool show_bottom_arrow = false;
  double bubble_y = anchor_rect.bottom();
  if (view_rect.bottom() - anchor_rect.bottom() < bubble_size_.height()) {
    bubble_y = anchor_rect.y() - bubble_size_.height();
    show_bottom_arrow = true;
  }
  double bubble_x =
      anchor_rect.x() + anchor_rect.width() / 2 - bubble_size_.width() / 2;
  if (bubble_x < view_rect.x())
    bubble_x = view_rect.x();
  else if (bubble_x + bubble_size_.width() > view_rect.right())
    bubble_x = view_rect.right() - bubble_size_.width();

  Element& container = GetElementById(AtomicString("container"));
  container.SetInlineStyleProperty(CSSPropertyID::kLeft, bubble_x / zoom_factor,
                                   CSSPrimitiveValue::UnitType::kPixels);
  container.SetInlineStyleProperty(CSSPropertyID::kTop, bubble_y / zoom_factor,
                                   CSSPrimitiveValue::UnitType::kPixels);

  // Should match to --arrow-size in validation_bubble.css.
  const int kArrowSize = 8;
  const int kArrowMargin = 10;
  const int kMinArrowAnchorX = kArrowSize + kArrowMargin;
  double max_arrow_anchor_x =
      bubble_size_.width() - (kArrowSize + kArrowMargin) * zoom_factor;
  double arrow_anchor_x;
  const int kOffsetToAnchorRect = 8;
  double anchor_rect_center = anchor_rect.x() + anchor_rect.width() / 2;
  if (!Locale::DefaultLocale().IsRTL()) {
    double anchor_rect_left =
        anchor_rect.x() + kOffsetToAnchorRect * zoom_factor;
    if (anchor_rect_left > anchor_rect_center)
      anchor_rect_left = anchor_rect_center;

    arrow_anchor_x = kMinArrowAnchorX * zoom_factor;
    if (bubble_x + arrow_anchor_x < anchor_rect_left) {
      arrow_anchor_x = anchor_rect_left - bubble_x;
      if (arrow_anchor_x > max_arrow_anchor_x)
        arrow_anchor_x = max_arrow_anchor_x;
    }
  } else {
    double anchor_rect_right =
        anchor_rect.right() - kOffsetToAnchorRect * zoom_factor;
    if (anchor_rect_right < anchor_rect_center)
      anchor_rect_right = anchor_rect_center;

    arrow_anchor_x = max_arrow_anchor_x;
    if (bubble_x + arrow_anchor_x > anchor_rect_right) {
      arrow_anchor_x = anchor_rect_right - bubble_x;
      if (arrow_anchor_x < kMinArrowAnchorX * zoom_factor)
        arrow_anchor_x = kMinArrowAnchorX * zoom_factor;
    }
  }
  double arrow_x = arrow_anchor_x / zoom_factor - kArrowSize;
  double arrow_anchor_percent = arrow_anchor_x * 100 / bubble_size_.width();
  if (show_bottom_arrow) {
    GetElementById(AtomicString("outer-arrow-bottom"))
        .SetInlineStyleProperty(CSSPropertyID::kLeft, arrow_x,
                                CSSPrimitiveValue::UnitType::kPixels);
    GetElementById(AtomicString("inner-arrow-bottom"))
        .SetInlineStyleProperty(CSSPropertyID::kLeft, arrow_x,
                                CSSPrimitiveValue::UnitType::kPixels);
    container.setAttribute(html_names::kClassAttr,
                           AtomicString("shown-fully bottom-arrow"));
    container.SetInlineStyleProperty(
        CSSPropertyID::kTransformOrigin,
        String::Format("%.2f%% bottom", arrow_anchor_percent));
  } else {
    GetElementById(AtomicString("outer-arrow-top"))
        .SetInlineStyleProperty(CSSPropertyID::kLeft, arrow_x,
                                CSSPrimitiveValue::UnitType::kPixels);
    GetElementById(AtomicString("inner-arrow-top"))
        .SetInlineStyleProperty(CSSPropertyID::kLeft, arrow_x,
                                CSSPrimitiveValue::UnitType::kPixels);
    container.setAttribute(html_names::kClassAttr, AtomicString("shown-fully"));
    container.SetInlineStyleProperty(
        CSSPropertyID::kTransformOrigin,
        String::Format("%.2f%% top", arrow_anchor_percent));
  }
}

void ValidationMessageOverlayDelegate::StartToHide() {
  anchor_ = nullptr;
  if (!page_)
    return;
  GetElementById(AtomicString("container"))
      .classList()
      .replace(AtomicString("shown-fully"), AtomicString("hiding"),
               ASSERT_NO_EXCEPTION);
}

bool ValidationMessageOverlayDelegate::IsHiding() const {
  return !anchor_;
}

}  // namespace blink

"""

```