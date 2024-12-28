Response:
The user wants to understand the functionality of the `web_frame_widget_test.cc` file in the Chromium Blink engine. They're particularly interested in its relation to JavaScript, HTML, and CSS, and want examples, logical reasoning with inputs/outputs, and common usage errors. This is the first part of a three-part request, so the focus should be on summarizing the file's capabilities as presented in the given code snippet.

**Plan:**

1. **Identify the main purpose of the file:** Based on the name and the content, it's a test file for `WebFrameWidgetImpl`.
2. **Analyze the tests:** Go through each `TEST_F` and understand what aspect of `WebFrameWidgetImpl` it's verifying.
3. **Categorize the functionalities:** Group the tests based on the features they cover.
4. **Identify connections to JavaScript, HTML, and CSS:** Look for tests that interact with or test features related to these web technologies.
5. **Look for logical reasoning and examples:** Some tests might demonstrate specific input-output behavior.
6. **Identify potential user/programming errors:**  The test file itself doesn't directly highlight user errors, but its tests reveal aspects of the system where errors *could* occur.
7. **Summarize the functionalities:**  Provide a concise overview of what the test file covers.
这个文件 `web_frame_widget_test.cc` 是 Chromium Blink 引擎中 `WebFrameWidgetImpl` 类的单元测试文件。它的主要功能是：

**主要功能：测试 `WebFrameWidgetImpl` 类的各种功能和行为。**

`WebFrameWidgetImpl` 类是 Blink 渲染引擎中用于管理和控制网页帧（frame）在渲染过程中的一个重要组件。 它负责处理帧的各种视觉属性、输入事件、生命周期管理以及与其他渲染组件的交互。

**以下是根据提供的代码片段归纳出的主要测试功能点：**

1. **测试自动调整大小 (Auto-Resize) 功能:**
   - **功能描述:**  验证当 `WebView` 被自动调整大小时，`WebFrameWidgetImpl` 能否正确请求分配新的 `viz::LocalSurfaceId`。`LocalSurfaceId` 用于在渲染过程中唯一标识一个渲染表面。
   - **与 JavaScript/HTML/CSS 的关系:** 当页面的布局发生变化（例如，通过 JavaScript 修改 DOM 或 CSS 样式），可能会触发自动调整大小。
   - **假设输入与输出:**
     - **假设输入:**  `WebView` 启用了自动调整大小，并且需要调整到一个新的尺寸。
     - **预期输出:** `WebFrameWidgetImpl` 内部会发出请求，要求分配一个新的 `LocalSurfaceId`。

2. **测试帧接收器 ID (FrameSinkId) 的命中测试 API:**
   - **功能描述:**  测试通过给定屏幕坐标，`WebFrameWidgetImpl` 能否正确返回该坐标所在的帧的 `FrameSinkId`。`FrameSinkId` 用于标识渲染进程中的渲染表面。
   - **与 JavaScript/HTML/CSS 的关系:**  涉及到页面元素的布局和层叠关系。用户点击或触摸屏幕上的某个位置时，需要确定该事件发生在哪个帧上。HTML 的 `<iframe>` 元素会创建子帧。
   - **假设输入与输出:**
     - **假设输入 1:**  屏幕坐标位于主框架的可见区域内。
     - **预期输出 1:** 返回主框架的 `FrameSinkId`。
     - **假设输入 2:** 屏幕坐标位于一个 `<iframe>` 子框架的可见区域内。
     - **预期输出 2:**  仍然返回主框架的 `FrameSinkId` (因为命中测试是在主框架级别进行的)，并返回相对于主框架的坐标。

3. **测试在输入事件时强制发送元数据 (Force Send Metadata On Input):** (仅限 Android)
   - **功能描述:**  验证某些操作（例如显示虚拟键盘）是否会触发 `WebFrameWidgetImpl` 请求强制发送渲染元数据。这通常是为了确保渲染器能及时更新状态。
   - **与 JavaScript/HTML/CSS 的关系:**  虚拟键盘的显示通常与 HTML 输入元素（例如 `<input>`, `<textarea>`) 交互相关。
   - **假设输入与输出:**
     - **假设输入:**  在 Android 设备上调用 `WebView().MainFrameViewWidget()->ShowVirtualKeyboard()`。
     - **预期输出:**  `WebFrameWidgetImpl` 会请求强制发送元数据。

4. **测试 Pinch 手势状态的同步 (Active Pinch Gesture Updates LayerTreeHostSubFrame):** (涉及到远程子框架)
   - **功能描述:** 验证当父框架发生 Pinch 手势时，这个状态能否正确同步到子框架的 `LayerTreeHost`。`LayerTreeHost` 负责管理渲染树的合成。
   - **与 JavaScript/HTML/CSS 的关系:** Pinch 手势是用户与网页交互的一种方式，可能会影响页面的缩放。涉及多个框架时，需要同步状态。
   - **假设输入与输出:**
     - **假设输入 1:**  父框架检测到 Pinch 手势开始。
     - **预期输出 1:** 子框架的 `LayerTreeHost` 的 `is_external_pinch_gesture_active_for_testing()` 返回 `true`。
     - **假设输入 2:** 父框架检测到 Pinch 手势结束。
     - **预期输出 2:** 子框架的 `LayerTreeHost` 的 `is_external_pinch_gesture_active_for_testing()` 返回 `false`。

5. **测试事件监听器的性能指标 (RenderWidgetInputEventUmaMetrics):**
   - **功能描述:**  测试针对不同类型的触摸事件分发策略（例如，被动监听器、可取消监听器等），是否正确记录了 UMA (User Metrics Analysis) 指标。
   - **与 JavaScript/HTML/CSS 的关系:**  涉及到 JavaScript 中使用 `addEventListener` 注册的触摸事件监听器，以及在 HTML 中定义的事件处理属性。CSS 的 `touch-action` 属性也会影响事件的处理方式。
   - **假设输入与输出:**  会模拟不同 `dispatch_type` 的触摸事件，并断言特定 UMA 直方图的计数是否符合预期。例如，模拟一个可取消的触摸事件后，`EVENT_LISTENER_RESULT_HISTOGRAM` 中 `PASSIVE_LISTENER_UMA_ENUM_CANCELABLE` 的计数会增加。

6. **测试弹性滚动 (Elastic Overscroll) 的发送:**
   - **功能描述:**  验证当用户使用触摸板或触摸屏进行滚动操作并超出滚动边界时，`WebFrameWidgetImpl` 能否正确地将相应的 Gesture 事件和滚动量发送到合成线程。
   - **与 JavaScript/HTML/CSS 的关系:**  涉及到用户与网页的滚动交互，以及 CSS 中 `overscroll-behavior` 属性对滚动溢出的控制。
   - **假设输入与输出:**  模拟触摸板和触摸屏的滚动事件，并断言 `ObserveGestureEventAndResult` 方法被调用。

7. **测试手写笔交互 (Start Stylus Writing):**
   - **功能描述:**  测试当使用手写笔在特定的 HTML 元素上按下时，能否正确地将焦点设置到该元素。
   - **与 JavaScript/HTML/CSS 的关系:**  涉及到用户使用手写笔与 HTML 输入元素 (`<input>`) 或可编辑元素 (`contenteditable`) 进行交互。
   - **假设输入与输出:**
     - **假设输入 1:** 手写笔点击一个 `<input type='text'>` 元素。
     - **预期输出 1:** 该 `<input>` 元素获得焦点。
     - **假设输入 2:** 手写笔点击一个 `contenteditable` 的 `<div>` 元素。
     - **预期输出 2:** 该 `<div>` 元素获得焦点。
     - **假设输入 3:** 手写笔点击一个 `contenteditable` 元素的子元素。
     - **预期输出 3:** 该 `contenteditable` 父元素获得焦点。

8. **测试光标变化 (Cursor Change):**
   - **功能描述:**  测试 `WebFrameWidgetImpl` 能否正确处理光标的变化，并将光标信息同步到 `WidgetHost`。
   - **与 JavaScript/HTML/CSS 的关系:**  涉及到 CSS 的 `cursor` 属性，以及 JavaScript 中动态修改光标的行为。
   - **假设输入与输出:**
     - **假设输入 1:** 调用 `MockMainFrameWidget()->SetCursor()` 设置一个光标。
     - **预期输出 1:** `WidgetHost` 记录到光标设置操作。
     - **假设输入 2:** 触发 `mouseleave` 事件。
     - **预期输出 2:** 光标设置操作的计数保持不变 (因为没有新的显式设置)。
     - **假设输入 3:** 再次调用 `MockMainFrameWidget()->SetCursor()` 设置相同的光标。
     - **预期输出 3:** `WidgetHost` 记录到新的光标设置操作 (即使光标类型相同)。

**用户或编程常见的使用错误 (可能通过测试揭示):**

虽然测试本身不是为了直接捕获用户错误，但它们可以揭示 `WebFrameWidgetImpl` 在处理不当情况时的行为，从而间接反映可能出现的编程错误：

- **未正确处理自动调整大小:** 如果开发者没有正确处理 `DidAutoResize` 事件或相关的渲染逻辑，可能导致页面布局错乱或渲染异常。
- **错误的 FrameSinkId 命中测试逻辑:**  如果 `GetFrameSinkIdAtPoint` 的实现有误，可能导致事件被错误地分发到错误的帧，尤其是在包含 `<iframe>` 的页面中。
- **事件监听器配置错误:**  JavaScript 开发者可能会错误地配置事件监听器为阻塞型，导致页面滚动或其他交互卡顿。测试中针对不同 `dispatch_type` 的指标可以帮助发现这类问题。
- **手写笔交互处理不当:**  开发者可能没有考虑到手写笔输入的情况，导致焦点处理或输入行为不符合预期。

**总结:**

总而言之，`web_frame_widget_test.cc` 的第一部分主要集中在测试 `WebFrameWidgetImpl` 的以下核心功能： **渲染表面的管理 (通过 `LocalSurfaceId` 和 `FrameSinkId`)、自动调整大小、输入事件处理 (包括触摸事件、鼠标事件、手势事件和手写笔事件)、以及与合成线程的交互 (例如同步 Pinch 手势状态和发送弹性滚动信息)。** 这些功能直接关系到网页的渲染、用户交互和性能表现。

Prompt: 
```
这是目录为blink/renderer/core/frame/web_frame_widget_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共3部分，请归纳一下它的功能

"""
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/functional/callback_helpers.h"
#include "base/run_loop.h"
#include "base/task/single_thread_task_runner.h"
#include "base/test/bind.h"
#include "base/test/metrics/histogram_tester.h"
#include "base/test/scoped_feature_list.h"
#include "base/unguessable_token.h"
#include "build/build_config.h"
#include "cc/layers/solid_color_layer.h"
#include "cc/test/property_tree_test_utils.h"
#include "components/viz/common/surfaces/parent_local_surface_id_allocator.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/common/input/synthetic_web_input_event_builders.h"
#include "third_party/blink/public/mojom/page/widget.mojom-shared.h"
#include "third_party/blink/renderer/core/css/properties/css_property_ref.h"
#include "third_party/blink/renderer/core/css/properties/longhands.h"
#include "third_party/blink/renderer/core/css/style_engine.h"
#include "third_party/blink/renderer/core/dom/events/add_event_listener_options_resolved.h"
#include "third_party/blink/renderer/core/dom/events/native_event_listener.h"
#include "third_party/blink/renderer/core/editing/editing_utilities.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/web_frame_widget_impl.h"
#include "third_party/blink/renderer/core/frame/web_local_frame_impl.h"
#include "third_party/blink/renderer/core/geometry/dom_rect.h"
#include "third_party/blink/renderer/core/html/forms/html_input_element.h"
#include "third_party/blink/renderer/core/html/forms/html_text_area_element.h"
#include "third_party/blink/renderer/core/html/html_div_element.h"
#include "third_party/blink/renderer/core/input/event_handler.h"
#include "third_party/blink/renderer/core/paint/paint_layer_scrollable_area.h"
#include "third_party/blink/renderer/core/testing/sim/sim_request.h"
#include "third_party/blink/renderer/core/testing/sim/sim_test.h"
#include "third_party/blink/renderer/platform/scheduler/test/fake_task_runner.h"
#include "third_party/blink/renderer/platform/testing/runtime_enabled_features_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"
#include "third_party/blink/renderer/platform/widget/input/widget_input_handler_manager.h"
#include "third_party/blink/renderer/platform/widget/widget_base.h"
#include "ui/base/mojom/window_show_state.mojom-blink.h"

#if BUILDFLAG(IS_WIN)
#include "components/stylus_handwriting/win/features.h"
#endif  // BUILDFLAG(IS_WIN)

namespace blink {

using testing::_;

bool operator==(const InputHandlerProxy::DidOverscrollParams& lhs,
                const InputHandlerProxy::DidOverscrollParams& rhs) {
  return lhs.accumulated_overscroll == rhs.accumulated_overscroll &&
         lhs.latest_overscroll_delta == rhs.latest_overscroll_delta &&
         lhs.current_fling_velocity == rhs.current_fling_velocity &&
         lhs.causal_event_viewport_point == rhs.causal_event_viewport_point &&
         lhs.overscroll_behavior == rhs.overscroll_behavior;
}

namespace {

class TouchMoveEventListener final : public NativeEventListener {
 public:
  void Invoke(ExecutionContext*, Event*) override { invoked_ = true; }

  bool GetInvokedStateAndReset() {
    bool invoked = invoked_;
    invoked_ = false;
    return invoked;
  }

 private:
  bool invoked_ = false;
};

}  // namespace

class WebFrameWidgetSimTest : public SimTest {};

// Tests that if a WebView is auto-resized, the associated
// WebFrameWidgetImpl requests a new viz::LocalSurfaceId to be allocated on the
// impl thread.
TEST_F(WebFrameWidgetSimTest, AutoResizeAllocatedLocalSurfaceId) {
  LoadURL("about:blank");
  // Resets CommitState::new_local_surface_id_request.
  Compositor().BeginFrame();

  viz::ParentLocalSurfaceIdAllocator allocator;

  // Enable auto-resize.
  VisualProperties visual_properties;
  visual_properties.screen_infos = display::ScreenInfos(display::ScreenInfo());
  visual_properties.auto_resize_enabled = true;
  visual_properties.min_size_for_auto_resize = gfx::Size(100, 100);
  visual_properties.max_size_for_auto_resize = gfx::Size(200, 200);
  allocator.GenerateId();
  visual_properties.local_surface_id = allocator.GetCurrentLocalSurfaceId();
  WebView().MainFrameWidget()->ApplyVisualProperties(visual_properties);
  WebView().MainFrameViewWidget()->UpdateSurfaceAndScreenInfo(
      visual_properties.local_surface_id.value(),
      visual_properties.compositor_viewport_pixel_rect,
      visual_properties.screen_infos);

  EXPECT_EQ(allocator.GetCurrentLocalSurfaceId(),
            WebView().MainFrameViewWidget()->LocalSurfaceIdFromParent());
  EXPECT_FALSE(WebView()
                   .MainFrameViewWidget()
                   ->LayerTreeHostForTesting()
                   ->new_local_surface_id_request_for_testing());

  constexpr gfx::Size size(200, 200);
  WebView().MainFrameViewWidget()->DidAutoResize(size);
  EXPECT_EQ(allocator.GetCurrentLocalSurfaceId(),
            WebView().MainFrameViewWidget()->LocalSurfaceIdFromParent());
  EXPECT_TRUE(WebView()
                  .MainFrameViewWidget()
                  ->LayerTreeHostForTesting()
                  ->new_local_surface_id_request_for_testing());
}

TEST_F(WebFrameWidgetSimTest, FrameSinkIdHitTestAPI) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(
      R"HTML(
      <style>
      html, body {
        margin :0px;
        padding: 0px;
      }
      </style>

      <div style='background: green; padding: 100px; margin: 0px;'>
        <iframe style='width: 200px; height: 100px;'
          srcdoc='<body style="margin : 0px; height : 100px; width : 200px;">
          </body>'>
        </iframe>
      </div>

      )HTML");

  gfx::PointF point;
  viz::FrameSinkId main_frame_sink_id =
      WebView().MainFrameViewWidget()->GetFrameSinkIdAtPoint(
          gfx::PointF(10.43, 10.74), &point);
  EXPECT_EQ(WebView().MainFrameViewWidget()->GetFrameSinkId(),
            main_frame_sink_id);
  EXPECT_EQ(gfx::PointF(10.43, 10.74), point);

  // Targeting a child frame should also return the FrameSinkId for the main
  // widget.
  viz::FrameSinkId frame_sink_id =
      WebView().MainFrameViewWidget()->GetFrameSinkIdAtPoint(
          gfx::PointF(150.27, 150.25), &point);
  EXPECT_EQ(main_frame_sink_id, frame_sink_id);
  EXPECT_EQ(gfx::PointF(150.27, 150.25), point);
}

#if BUILDFLAG(IS_ANDROID)
TEST_F(WebFrameWidgetSimTest, ForceSendMetadataOnInput) {
  const cc::LayerTreeHost* layer_tree_host =
      WebView().MainFrameViewWidget()->LayerTreeHostForTesting();
  // We should not have any force send metadata requests at start.
  EXPECT_FALSE(
      layer_tree_host->pending_commit_state()->force_send_metadata_request);
  // ShowVirtualKeyboard will trigger a text input state update.
  WebView().MainFrameViewWidget()->ShowVirtualKeyboard();
  // We should now have a force send metadata request.
  EXPECT_TRUE(
      layer_tree_host->pending_commit_state()->force_send_metadata_request);
}
#endif  // BUILDFLAG(IS_ANDROID)

// A test that forces a RemoteMainFrame to be created.
class WebFrameWidgetImplRemoteFrameSimTest : public SimTest {
 public:
  void SetUp() override {
    SimTest::SetUp();
    InitializeRemote();
    CHECK(static_cast<WebFrameWidgetImpl*>(LocalFrameRoot().FrameWidget())
              ->ForSubframe());
  }

  WebFrameWidgetImpl* LocalFrameRootWidget() {
    return static_cast<WebFrameWidgetImpl*>(LocalFrameRoot().FrameWidget());
  }
};

// Tests that the value of VisualProperties::is_pinch_gesture_active is
// propagated to the LayerTreeHost when properties are synced for child local
// roots.
TEST_F(WebFrameWidgetImplRemoteFrameSimTest,
       ActivePinchGestureUpdatesLayerTreeHostSubFrame) {
  cc::LayerTreeHost* layer_tree_host =
      LocalFrameRootWidget()->LayerTreeHostForTesting();
  EXPECT_FALSE(layer_tree_host->is_external_pinch_gesture_active_for_testing());
  VisualProperties visual_properties;
  visual_properties.screen_infos = display::ScreenInfos(display::ScreenInfo());

  // Sync visual properties on a child widget.
  visual_properties.is_pinch_gesture_active = true;
  LocalFrameRootWidget()->ApplyVisualProperties(visual_properties);
  // We expect the |is_pinch_gesture_active| value to propagate to the
  // LayerTreeHost for sub-frames. Since GesturePinch events are handled
  // directly in the main-frame's layer tree (and only there), information about
  // whether or not we're in a pinch gesture must be communicated separately to
  // sub-frame layer trees, via OnUpdateVisualProperties. This information
  // is required to allow sub-frame compositors to throttle rastering while
  // pinch gestures are active.
  EXPECT_TRUE(layer_tree_host->is_external_pinch_gesture_active_for_testing());
  visual_properties.is_pinch_gesture_active = false;
  LocalFrameRootWidget()->ApplyVisualProperties(visual_properties);
  EXPECT_FALSE(layer_tree_host->is_external_pinch_gesture_active_for_testing());
}

const char EVENT_LISTENER_RESULT_HISTOGRAM[] = "Event.PassiveListeners";

// Keep in sync with enum defined in
// RenderWidgetInputHandler::LogPassiveEventListenersUma.
enum {
  PASSIVE_LISTENER_UMA_ENUM_PASSIVE,
  PASSIVE_LISTENER_UMA_ENUM_UNCANCELABLE,
  PASSIVE_LISTENER_UMA_ENUM_SUPPRESSED,
  PASSIVE_LISTENER_UMA_ENUM_CANCELABLE,
  PASSIVE_LISTENER_UMA_ENUM_CANCELABLE_AND_CANCELED,
  PASSIVE_LISTENER_UMA_ENUM_FORCED_NON_BLOCKING_DUE_TO_FLING,
  PASSIVE_LISTENER_UMA_ENUM_FORCED_NON_BLOCKING_DUE_TO_MAIN_THREAD_RESPONSIVENESS_DEPRECATED,
  PASSIVE_LISTENER_UMA_ENUM_COUNT
};

// Since std::unique_ptr<InputHandlerProxy::DidOverscrollParams> isn't copyable
// we can't use the MockCallback template.
class MockHandledEventCallback {
 public:
  MockHandledEventCallback() = default;
  MockHandledEventCallback(const MockHandledEventCallback&) = delete;
  MockHandledEventCallback& operator=(const MockHandledEventCallback&) = delete;
  MOCK_METHOD4_T(Run,
                 void(mojom::InputEventResultState,
                      const ui::LatencyInfo&,
                      InputHandlerProxy::DidOverscrollParams*,
                      std::optional<cc::TouchAction>));

  WidgetBaseInputHandler::HandledEventCallback GetCallback() {
    return WTF::BindOnce(&MockHandledEventCallback::HandleCallback,
                         WTF::Unretained(this));
  }

 private:
  void HandleCallback(
      mojom::InputEventResultState ack_state,
      const ui::LatencyInfo& latency_info,
      std::unique_ptr<InputHandlerProxy::DidOverscrollParams> overscroll,
      std::optional<cc::TouchAction> touch_action) {
    Run(ack_state, latency_info, overscroll.get(), touch_action);
  }
};

class MockWebFrameWidgetImpl : public frame_test_helpers::TestWebFrameWidget {
 public:
  using frame_test_helpers::TestWebFrameWidget::TestWebFrameWidget;

  MOCK_METHOD1(HandleInputEvent,
               WebInputEventResult(const WebCoalescedInputEvent&));
  MOCK_METHOD0(DispatchBufferedTouchEvents, WebInputEventResult());

  MOCK_METHOD4(ObserveGestureEventAndResult,
               void(const WebGestureEvent& gesture_event,
                    const gfx::Vector2dF& unused_delta,
                    const cc::OverscrollBehavior& overscroll_behavior,
                    bool event_processed));
};

class WebFrameWidgetImplSimTest : public SimTest {
 public:
  frame_test_helpers::TestWebFrameWidget* CreateWebFrameWidget(
      base::PassKey<WebLocalFrame> pass_key,
      CrossVariantMojoAssociatedRemote<
          mojom::blink::FrameWidgetHostInterfaceBase> frame_widget_host,
      CrossVariantMojoAssociatedReceiver<mojom::blink::FrameWidgetInterfaceBase>
          frame_widget,
      CrossVariantMojoAssociatedRemote<mojom::blink::WidgetHostInterfaceBase>
          widget_host,
      CrossVariantMojoAssociatedReceiver<mojom::blink::WidgetInterfaceBase>
          widget,
      scoped_refptr<base::SingleThreadTaskRunner> task_runner,
      const viz::FrameSinkId& frame_sink_id,
      bool hidden,
      bool never_composited,
      bool is_for_child_local_root,
      bool is_for_nested_main_frame,
      bool is_for_scalable_page) override {
    return MakeGarbageCollected<MockWebFrameWidgetImpl>(
        pass_key, std::move(frame_widget_host), std::move(frame_widget),
        std::move(widget_host), std::move(widget), std::move(task_runner),
        frame_sink_id, hidden, never_composited, is_for_child_local_root,
        is_for_nested_main_frame, is_for_scalable_page);
  }

  MockWebFrameWidgetImpl* MockMainFrameWidget() {
    return static_cast<MockWebFrameWidgetImpl*>(MainFrame().FrameWidget());
  }

  EventHandler& GetEventHandler() {
    return GetDocument().GetFrame()->GetEventHandler();
  }

  void SendInputEvent(const WebInputEvent& event,
                      WidgetBaseInputHandler::HandledEventCallback callback) {
    MockMainFrameWidget()->ProcessInputEventSynchronouslyForTesting(
        WebCoalescedInputEvent(event.Clone(), {}, {}, ui::LatencyInfo()),
        std::move(callback));
  }

  void OnStartStylusWriting() {
    MockMainFrameWidget()->OnStartStylusWriting(
#if BUILDFLAG(IS_WIN)
        /*focus_rect_in_widget=*/gfx::Rect(),
#endif  // BUILDFLAG(IS_WIN)
        base::DoNothing());
  }

  const base::HistogramTester& histogram_tester() const {
    return histogram_tester_;
  }

 private:
  base::HistogramTester histogram_tester_;
};

TEST_F(WebFrameWidgetImplSimTest, CursorChange) {
  ui::Cursor cursor;

  frame_test_helpers::TestWebFrameWidgetHost& widget_host =
      MockMainFrameWidget()->WidgetHost();

  MockMainFrameWidget()->SetCursor(cursor);
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(widget_host.CursorSetCount(), 1u);

  MockMainFrameWidget()->SetCursor(cursor);
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(widget_host.CursorSetCount(), 1u);

  EXPECT_CALL(*MockMainFrameWidget(), HandleInputEvent(_))
      .WillOnce(::testing::Return(WebInputEventResult::kNotHandled));
  SendInputEvent(
      SyntheticWebMouseEventBuilder::Build(WebInputEvent::Type::kMouseLeave),
      base::DoNothing());
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(widget_host.CursorSetCount(), 1u);

  MockMainFrameWidget()->SetCursor(cursor);
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(widget_host.CursorSetCount(), 2u);
}

TEST_F(WebFrameWidgetImplSimTest, RenderWidgetInputEventUmaMetrics) {
  SyntheticWebTouchEvent touch;
  touch.PressPoint(10, 10);
  touch.touch_start_or_first_touch_move = true;

  EXPECT_CALL(*MockMainFrameWidget(), HandleInputEvent(_))
      .Times(5)
      .WillRepeatedly(::testing::Return(WebInputEventResult::kNotHandled));
  EXPECT_CALL(*MockMainFrameWidget(), DispatchBufferedTouchEvents())
      .Times(5)
      .WillRepeatedly(::testing::Return(WebInputEventResult::kNotHandled));
  SendInputEvent(touch, base::DoNothing());
  histogram_tester().ExpectBucketCount(EVENT_LISTENER_RESULT_HISTOGRAM,
                                       PASSIVE_LISTENER_UMA_ENUM_CANCELABLE, 1);

  touch.dispatch_type = WebInputEvent::DispatchType::kEventNonBlocking;
  SendInputEvent(touch, base::DoNothing());
  histogram_tester().ExpectBucketCount(EVENT_LISTENER_RESULT_HISTOGRAM,
                                       PASSIVE_LISTENER_UMA_ENUM_UNCANCELABLE,
                                       1);

  touch.dispatch_type =
      WebInputEvent::DispatchType::kListenersNonBlockingPassive;
  SendInputEvent(touch, base::DoNothing());
  histogram_tester().ExpectBucketCount(EVENT_LISTENER_RESULT_HISTOGRAM,
                                       PASSIVE_LISTENER_UMA_ENUM_PASSIVE, 1);

  touch.dispatch_type =
      WebInputEvent::DispatchType::kListenersForcedNonBlockingDueToFling;
  SendInputEvent(touch, base::DoNothing());
  histogram_tester().ExpectBucketCount(
      EVENT_LISTENER_RESULT_HISTOGRAM,
      PASSIVE_LISTENER_UMA_ENUM_FORCED_NON_BLOCKING_DUE_TO_FLING, 1);

  touch.MovePoint(0, 10, 10);
  touch.touch_start_or_first_touch_move = true;
  touch.dispatch_type =
      WebInputEvent::DispatchType::kListenersForcedNonBlockingDueToFling;
  SendInputEvent(touch, base::DoNothing());
  histogram_tester().ExpectBucketCount(
      EVENT_LISTENER_RESULT_HISTOGRAM,
      PASSIVE_LISTENER_UMA_ENUM_FORCED_NON_BLOCKING_DUE_TO_FLING, 2);

  EXPECT_CALL(*MockMainFrameWidget(), HandleInputEvent(_))
      .WillOnce(::testing::Return(WebInputEventResult::kNotHandled));
  EXPECT_CALL(*MockMainFrameWidget(), DispatchBufferedTouchEvents())
      .WillOnce(::testing::Return(WebInputEventResult::kHandledSuppressed));
  touch.dispatch_type = WebInputEvent::DispatchType::kBlocking;
  SendInputEvent(touch, base::DoNothing());
  histogram_tester().ExpectBucketCount(EVENT_LISTENER_RESULT_HISTOGRAM,
                                       PASSIVE_LISTENER_UMA_ENUM_SUPPRESSED, 1);

  EXPECT_CALL(*MockMainFrameWidget(), HandleInputEvent(_))
      .WillOnce(::testing::Return(WebInputEventResult::kNotHandled));
  EXPECT_CALL(*MockMainFrameWidget(), DispatchBufferedTouchEvents())
      .WillOnce(::testing::Return(WebInputEventResult::kHandledApplication));
  touch.dispatch_type = WebInputEvent::DispatchType::kBlocking;
  SendInputEvent(touch, base::DoNothing());
  histogram_tester().ExpectBucketCount(
      EVENT_LISTENER_RESULT_HISTOGRAM,
      PASSIVE_LISTENER_UMA_ENUM_CANCELABLE_AND_CANCELED, 1);
}

// Ensures that the compositor thread gets sent the gesture event & overscroll
// amount for an overscroll initiated by a touchpad.
TEST_F(WebFrameWidgetImplSimTest, SendElasticOverscrollForTouchpad) {
  WebGestureEvent scroll(WebInputEvent::Type::kGestureScrollUpdate,
                         WebInputEvent::kNoModifiers, base::TimeTicks::Now(),
                         WebGestureDevice::kTouchpad);
  scroll.SetPositionInWidget(gfx::PointF(-10, 0));
  scroll.data.scroll_update.delta_y = 10;

  // We only really care that ObserveGestureEventAndResult was called; we
  // therefore suppress the warning for the call to
  // HandleInputEvent().
  EXPECT_CALL(*MockMainFrameWidget(), ObserveGestureEventAndResult(_, _, _, _))
      .Times(1);
  EXPECT_CALL(*MockMainFrameWidget(), HandleInputEvent(_))
      .Times(testing::AnyNumber());

  SendInputEvent(scroll, base::DoNothing());
}

// Ensures that the compositor thread gets sent the gesture event & overscroll
// amount for an overscroll initiated by a touchscreen.
TEST_F(WebFrameWidgetImplSimTest, SendElasticOverscrollForTouchscreen) {
  WebGestureEvent scroll(WebInputEvent::Type::kGestureScrollUpdate,
                         WebInputEvent::kNoModifiers, base::TimeTicks::Now(),
                         WebGestureDevice::kTouchscreen);
  scroll.SetPositionInWidget(gfx::PointF(-10, 0));
  scroll.data.scroll_update.delta_y = 10;

  // We only really care that ObserveGestureEventAndResult was called; we
  // therefore suppress the warning for the call to
  // HandleInputEvent().
  EXPECT_CALL(*MockMainFrameWidget(), ObserveGestureEventAndResult(_, _, _, _))
      .Times(1);
  EXPECT_CALL(*MockMainFrameWidget(), HandleInputEvent(_))
      .Times(testing::AnyNumber());

  SendInputEvent(scroll, base::DoNothing());
}

TEST_F(WebFrameWidgetImplSimTest, TestStartStylusWritingForInputElement) {
  ScopedStylusHandwritingForTest enable_stylus_handwriting(true);
  WebView().MainFrameViewWidget()->Resize(gfx::Size(400, 400));
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(
      R"HTML(
      <!doctype html>
      <body style='padding: 0px; width: 400px; height: 400px;'>
      <input type='text' id='first' style='width: 100px; height: 100px;'>
      </body>
      )HTML");
  Compositor().BeginFrame();
  Element* first =
      DynamicTo<Element>(GetDocument().getElementById(AtomicString("first")));
  WebPointerEvent event(
      WebInputEvent::Type::kPointerDown,
      WebPointerProperties(1, WebPointerProperties::PointerType::kPen,
                           WebPointerProperties::Button::kLeft,
                           gfx::PointF(100, 100), gfx::PointF(100, 100)),
      1, 1);
  GetEventHandler().HandlePointerEvent(event, Vector<WebPointerEvent>(),
                                       Vector<WebPointerEvent>());
  EXPECT_EQ(nullptr, GetDocument().FocusedElement());
  OnStartStylusWriting();
  EXPECT_EQ(first, GetDocument().FocusedElement());
}

TEST_F(WebFrameWidgetImplSimTest,
       TestStartStylusWritingForContentEditableElement) {
  ScopedStylusHandwritingForTest enable_stylus_handwriting(true);
  WebView().MainFrameViewWidget()->Resize(gfx::Size(400, 400));
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(
      R"HTML(
      <!doctype html>
      <body style='padding: 0px; width: 400px; height: 400px;'>
      <div contenteditable='true' id='first' style='width: 100px; height: 100px;'></div>
      </body>
      )HTML");
  Compositor().BeginFrame();
  Element* first =
      DynamicTo<Element>(GetDocument().getElementById(AtomicString("first")));
  WebPointerEvent event(
      WebInputEvent::Type::kPointerDown,
      WebPointerProperties(1, WebPointerProperties::PointerType::kPen,
                           WebPointerProperties::Button::kLeft,
                           gfx::PointF(100, 100), gfx::PointF(100, 100)),
      1, 1);
  GetEventHandler().HandlePointerEvent(event, Vector<WebPointerEvent>(),
                                       Vector<WebPointerEvent>());
  EXPECT_EQ(nullptr, GetDocument().FocusedElement());
  OnStartStylusWriting();
  EXPECT_EQ(first, GetDocument().FocusedElement());
}

TEST_F(WebFrameWidgetImplSimTest,
       TestStartStylusWritingForContentEditableChildElement) {
  ScopedStylusHandwritingForTest enable_stylus_handwriting(true);
  WebView().MainFrameViewWidget()->Resize(gfx::Size(400, 400));
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(
      R"HTML(
      <!doctype html>
      <body style='padding: 0px; width: 400px; height: 400px;'>
      <div contenteditable='true' id='first'>
      <div id='second' style='width: 100px; height: 100px;'>Hello</div>
      </div>
      </body>
      )HTML");
  Compositor().BeginFrame();
  Element* first =
      DynamicTo<Element>(GetDocument().getElementById(AtomicString("first")));
  Element* second =
      DynamicTo<Element>(GetDocument().getElementById(AtomicString("second")));
  WebPointerEvent event(
      WebInputEvent::Type::kPointerDown,
      WebPointerProperties(1, WebPointerProperties::PointerType::kPen,
                           WebPointerProperties::Button::kLeft,
                           gfx::PointF(100, 100), gfx::PointF(100, 100)),
      1, 1);
  GetEventHandler().HandlePointerEvent(event, Vector<WebPointerEvent>(),
                                       Vector<WebPointerEvent>());
  EXPECT_EQ(second, GetEventHandler().CurrentTouchDownElement());
  EXPECT_EQ(nullptr, GetDocument().FocusedElement());
  OnStartStylusWriting();
  EXPECT_EQ(first, GetDocument().FocusedElement());
}

#if BUILDFLAG(IS_WIN)
struct ProximateBoundsCollectionArgs final {
  base::RepeatingCallback<gfx::Rect(const Document&)> get_focus_rect_in_widget;
  std::string expected_focus_id;
  bool expect_null_proximate_bounds;
  gfx::Range expected_range;
  std::vector<gfx::Rect> expected_bounds;
};

std::ostream& operator<<(std::ostream& os,
                         const ProximateBoundsCollectionArgs& args) {
  os << "\nexpected_focus_id: " << args.expected_focus_id;
  os << "\nexpect_null_proximate_bounds: " << args.expect_null_proximate_bounds;
  os << "\nexpected_range: " << args.expected_range;
  os << "\nexpected_bounds.size: [";
  for (const auto& bounds : args.expected_bounds) {
    os << "{" << bounds.ToString() << "}, ";
  }
  os << "]";
  return os;
}

struct WebFrameWidgetProximateBoundsCollectionSimTestParam {
  using TupleType = std::tuple</*enable_stylus_handwriting_win=*/bool,
                               /*html_document=*/std::string,
                               /*args=*/ProximateBoundsCollectionArgs>;
  explicit WebFrameWidgetProximateBoundsCollectionSimTestParam(TupleType tup)
      : enable_stylus_handwriting_win_(std::get<0>(tup)),
        html_document_(std::get<1>(tup)),
        proximate_bounds_collection_args_(std::get<2>(tup)) {}

  bool IsStylusHandwritingWinEnabled() const {
    return enable_stylus_handwriting_win_;
  }

  const std::string& GetHTMLDocument() const { return html_document_; }

  const std::string& GetExpectedFocusId() const {
    return proximate_bounds_collection_args_.expected_focus_id;
  }

  gfx::Rect GetFocusRectInWidget(const Document& document) const {
    return proximate_bounds_collection_args_.get_focus_rect_in_widget.Run(
        document);
  }

  bool ExpectNullProximateBounds() const {
    return proximate_bounds_collection_args_.expect_null_proximate_bounds;
  }

  const gfx::Range& GetExpectedRange() const {
    return proximate_bounds_collection_args_.expected_range;
  }

  const std::vector<gfx::Rect>& GetExpectedBounds() const {
    return proximate_bounds_collection_args_.expected_bounds;
  }

 private:
  friend std::ostream& operator<<(
      std::ostream& os,
      const WebFrameWidgetProximateBoundsCollectionSimTestParam& param);
  const bool enable_stylus_handwriting_win_;
  const std::string html_document_;
  const ProximateBoundsCollectionArgs proximate_bounds_collection_args_;
};

std::ostream& operator<<(
    std::ostream& os,
    const WebFrameWidgetProximateBoundsCollectionSimTestParam& param) {
  return os << "\nenable_stylus_handwriting_win: "
            << param.enable_stylus_handwriting_win_
            << "\nhtml_document: " << param.html_document_
            << "\nproximate_bounds_collection_args: {"
            << param.proximate_bounds_collection_args_ << "}";
}

class WebFrameWidgetProximateBoundsCollectionSimTestBase
    : public WebFrameWidgetImplSimTest {
 public:
  void LoadDocument(const String& html_document) {
    WebView().MainFrameViewWidget()->Resize(gfx::Size(400, 400));
    SimRequest request("https://example.com/test.html", "text/html");
    SimSubresourceRequest style_resource("https://example.com/styles.css",
                                         "text/css");
    SimSubresourceRequest font_resource("https://example.com/Ahem.woff2",
                                        "font/woff2");
    LoadURL("https://example.com/test.html");
    request.Complete(html_document);
    style_resource.Complete(R"CSS(
      @font-face {
        font-family: custom-font;
        src: url(https://example.com/Ahem.woff2) format("woff2");
      }
      body {
        margin: 0;
        padding: 0;
        border: 0;
        width: 400px;
        height: 400px;
      }
      #target_editable,
      #target_readonly,
      #second,
      #touch_fallback {
        font: 10px/1 custom-font, monospace;
        margin: 0;
        padding: 0;
        border: none;
        width: 260px;
      }
      #touch_fallback {
        position: absolute;
        left: 0px;
        top: 200px;
      }
    )CSS");
    Compositor().BeginFrame();
    // Finish font loading, and trigger invalidations.
    font_resource.Complete(
        *test::ReadFromFile(test::CoreTestDataPath("Ahem.woff2")));
    Compositor().BeginFrame();
  }

  void HandlePointerDownEventOverTouchFallback() {
    const Element* touch_fallback = GetElementById("touch_fallback");
    const gfx::Point tap_point = touch_fallback->BoundsInWidget().CenterPoint();
    const WebPointerEvent event(
        WebInputEvent::Type::kPointerDown,
        WebPointerProperties(1, WebPointerProperties::PointerType::kPen,
                             WebPointerProperties::Button::kLeft,
                             gfx::PointF(tap_point), gfx::PointF(tap_point)),
        1, 1);
    GetEventHandler().HandlePointerEvent(event, Vector<WebPointerEvent>(),
                                         Vector<WebPointerEvent>());
    EXPECT_EQ(GetDocument().FocusedElement(), nullptr);
  }

  void OnStartStylusWriting(const gfx::Rect& focus_rect_in_widget) {
    MockMainFrameWidget()->OnStartStylusWriting(
        focus_rect_in_widget,
        base::BindOnce(&WebFrameWidgetProximateBoundsCollectionSimTestBase::
                           OnStartStylusWritingComplete,
                       weak_factory_.GetWeakPtr()));
  }

  Element* GetElementById(const char* id) {
    return GetDocument().getElementById(AtomicString(id));
  }

  const mojom::blink::ProximateCharacterRangeBounds* GetLastProximateBounds()
      const {
    return last_proximate_bounds_.get();
  }

 protected:
  explicit WebFrameWidgetProximateBoundsCollectionSimTestBase(
      bool enable_stylus_handwriting_win) {
    if (enable_stylus_handwriting_win) {
      // Note: kProximateBoundsCollectionHalfLimit is negative here to exercise
      // the absolute value logic in `ProximateBoundsCollectionHalfLimit()`.
      // Logically positive and negative values are equivalent for this, so it
      // has no special meaning.
      scoped_feature_list_.InitWithFeaturesAndParameters(
          /*enabled_features=*/
          {{stylus_handwriting::win::kStylusHandwritingWin,
            base::FieldTrialParams()},
           {stylus_handwriting::win::kProximateBoundsCollection,
            base::FieldTrialParams(
                {{stylus_handwriting::win::kProximateBoundsCollectionHalfLimit
                      .name,
                  base::NumberToString(-2)}})}},
          /*disabled_features=*/{});
      enable_stylus_handwriting_.emplace(true);
    } else {
      scoped_feature_list_.InitWithFeaturesAndParameters(
          /*enabled_features=*/{},
          /*disabled_features=*/{
              stylus_handwriting::win::kStylusHandwritingWin});
    }
  }

 private:
  void OnStartStylusWritingComplete(
      mojom::blink::StylusWritingFocusResultPtr focus_result) {
    last_proximate_bounds_ =
        focus_result ? std::move(focus_result->proximate_bounds) : nullptr;
  }

  base::test::ScopedFeatureList scoped_feature_list_;
  // Needed in tests because StyleAdjuster::AdjustEffectiveTouchAction depends
  // on `RuntimeEnabledFeatures::StylusHandwritingEnabled()` to remove
  // TouchAction::kInternalNotWritable from TouchAction::kAuto.
  // In production this will be handled by web contents prefs propagation.
  std::optional<ScopedStylusHandwritingForTest> enable_stylus_handwriting_;
  mojom::blink::ProximateCharacterRangeBoundsPtr last_proximate_bounds_;
  base::WeakPtrFactory<WebFrameWidgetProximateBoundsCollectionSimTestBase>
      weak_factory_{this};
};

class WebFrameWidgetProximateBoundsCollectionSimTestF
    : public WebFrameWidgetProximateBoundsCollectionSimTestBase {
 public:
  WebFrameWidgetProximateBoundsCollectionSimTestF()
      : WebFrameWidgetProximateBoundsCollectionSimTestBase(
            /*enable_stylus_handwriting_win=*/true) {}

  void StartStylusWritingOnElementCenter(const Element& element) {
    gfx::Rect focus_rect_in_widget(element.BoundsInWidget().CenterPoint(),
                                   gfx::Size());
    focus_rect_in_widget.Outset(gfx::Outsets(25));
    OnStartStylusWriting(focus_rect_in_widget);
  }
};

class WebFrameWidgetProximateBoundsCollectionSimTestP
    : public WebFrameWidgetProximateBoundsCollectionSimTestBase,
      public testing::WithParamInterface<
          WebFrameWidgetProximateBoundsCollectionSimTestParam> {
 public:
  WebFrameWidgetProximateBoundsCollectionSimTestP()
      : WebFrameWidgetProximateBoundsCollectionSimTestBase(
            /*enable_stylus_handwriting_win=*/GetParam()
                .IsStylusHandwritingWinEnabled()) {}
};

TEST_F(WebFrameWidgetProximateBoundsCollectionSimTestF,
       ProximateBoundsDisabled) {
  base::test::ScopedFeatureList scoped_feature_list;
  scoped_feature_list.InitWithFeaturesAndParameters(
      /*enabled_features=*/
      {{stylus_handwriting::win::kProximateBoundsCollection,
        base::FieldTrialParams(
            {{stylus_handwriting::win::kProximateBoundsCollectionHalfLimit.name,
              base::NumberToString(0)}})}},
      /*disabled_features=*/{});
  LoadDocument(String(R"HTML(
    <!doctype html>
    <link rel="stylesheet" href="styles.css">
    <body>
      <div id='target_editable' contenteditable>ABCDEFGHIJKLMNOPQRSTUVWXYZ</div>
      <div id="touch_fallback" contenteditable>Fallback Text</div>
    </body>
  )HTML"));
  HandlePointerDownEventOverTouchFallback();
  const Element& target_editable = *GetElementById("target_editable");
  StartStylusWritingOnElementCenter(target_editable);
  EXPECT_EQ(GetDocument().FocusedElement(), ta
"""


```