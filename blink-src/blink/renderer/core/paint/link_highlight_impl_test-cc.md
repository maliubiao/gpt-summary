Response:
Let's break down the thought process for analyzing the `link_highlight_impl_test.cc` file.

1. **Understand the Purpose of Tests:** The first and most crucial step is recognizing that this is a *test file*. Test files in software development are designed to verify the functionality of other parts of the codebase. Therefore, the core purpose of this file is to test something. The file name itself, `link_highlight_impl_test.cc`, strongly suggests it's testing `link_highlight_impl.h` (or a related implementation).

2. **Identify the Target Class:**  The `#include` statement for `link_highlight_impl.h` confirms the primary target of these tests is the `LinkHighlightImpl` class.

3. **Analyze the Test Structure (GTest):**  The presence of `#include "testing/gtest/include/gtest/gtest.h"` immediately tells us that the tests are using the Google Test framework (GTest). Key elements of GTest are:
    * `TEST_F(TestFixtureName, TestName)`:  Defines an individual test case.
    * `ASSERT_*` macros:  Fatal assertions; if they fail, the test immediately stops.
    * `EXPECT_*` macros: Non-fatal assertions; if they fail, the test continues.
    * Test Fixtures (`LinkHighlightImplTest`): Classes that set up the environment and provide helper methods for the tests.

4. **Examine the Test Fixture (`LinkHighlightImplTest`):**  This is where the setup and common utilities are located. Look for:
    * `SetUp()`:  Code executed *before* each test. Here, it initializes a `WebViewHelper` and loads a test HTML file (`test_touch_link_highlight.html`). This is a strong clue that the functionality being tested is related to web page rendering and interaction.
    * `TearDown()`: Code executed *after* each test for cleanup.
    * Helper methods like `GetTargetedEvent`, `GestureShowPress`, `LayerCount`, `AnimationCount`, `GetLinkHighlight`, `GetLinkHighlightImpl`, `UpdateAllLifecyclePhases`. These reveal the kinds of interactions and checks the tests perform. The names are often self-explanatory (e.g., `GestureShowPress` suggests simulating a touch event).
    * Member variables like `web_view_helper_`:  Indicates interaction with a web view component.

5. **Analyze Individual Test Cases:** Now, go through each `TEST_P` or `TEST_F` function:
    * **`verifyWebViewImplIntegration`:**  The name suggests it's checking how `LinkHighlightImpl` works with the `WebViewImpl`. The test simulates touch events (`GestureShowPress`) on different parts of the page and verifies whether a link highlight is created (`EnableTapHighlightAtPoint`). It also checks for the presence of animations. The comments within the test provide further context.
    * **`resetDuringNodeRemoval`:** This focuses on what happens to the link highlight when the target DOM node is removed. It checks if the `LinkHighlightImpl` correctly handles this scenario.
    * **`resetLayerTreeView`:** This test seems to focus on the lifecycle of the `LayerTreeView` and ensures the link highlight doesn't cause crashes when the tree is destroyed.
    * **`HighlightLayerEffectNode`:** This test delves into the compositing aspects, checking if the highlight creates a layer and has associated effects (opacity, animation). It also introduces `ScopedWebTestMode(false)` which hints at differences in behavior between web test and normal modes.
    * **`RemoveNodeDuringHighlightAnimation`:** Similar to `resetDuringNodeRemoval`, but specifically during an animation.
    * **`MultiColumn`:** This test explicitly handles the case where a link spans multiple columns in a multi-column layout. It verifies the creation of multiple highlight layers for each fragment.
    * **`DisplayContents`:** This tests a scenario where a touch occurs on a non-link element (specifically a text node within a `display: contents` element). It confirms that no link highlight is created in this case.

6. **Infer Functionality from Tests:**  By observing what the tests are *doing* and what they are *asserting*, we can infer the functionality of `LinkHighlightImpl`:
    * **Highlighting Links on Touch:** The primary function is to visually highlight links when they are touched.
    * **Integration with Compositing:**  It creates layers and uses animations for the highlight effect.
    * **Handling DOM Changes:**  It needs to correctly handle cases where the target link node is removed.
    * **Multi-Column Support:** It correctly highlights links that span multiple columns.
    * **Avoiding Highlighting Non-Links:** It doesn't highlight elements that aren't links (or don't have a "hand cursor").

7. **Relate to Web Technologies:** Connect the observed behavior to HTML, CSS, and JavaScript:
    * **HTML:** The tests load an HTML file, and the highlighting is triggered by touching link elements (`<a>`).
    * **CSS:** The presence of "hand cursor" check implies CSS cursor styles are involved. The "multi-column" test directly interacts with CSS multi-column layout. The inline style manipulation in `HighlightLayerEffectNode` is also CSS-related.
    * **JavaScript:** While this specific test file doesn't directly execute JavaScript, the underlying link highlighting mechanism is triggered by user interaction, which often involves JavaScript event listeners.

8. **Consider User Actions and Debugging:**  Think about how a user would trigger this code:
    * Tapping or long-pressing on a link on a touchscreen device.
    * The debugging clues come from understanding the event flow (touch events, hit testing) and the lifecycle of the highlight (creation, animation, removal).

9. **Speculate on Logic and Errors:** Based on the tests, hypothesize about the underlying logic and potential errors:
    * **Logic:**  Hit testing to determine the target element, checking for link attributes or appropriate cursor styles, creating and animating layers.
    * **Errors:** Incorrect hit testing, failing to handle node removal properly, issues with multi-column layout calculations, incorrect animation timing.

10. **Structure the Explanation:** Finally, organize the findings into a clear and logical explanation covering the key aspects requested in the prompt. Use the evidence gathered from the code analysis to support each point.

By following this systematic approach, we can effectively understand the purpose and functionality of even complex test files like `link_highlight_impl_test.cc`. The key is to treat the tests as specifications of the code they are testing.
这个文件 `blink/renderer/core/paint/link_highlight_impl_test.cc` 是 Chromium Blink 引擎中的一个 **单元测试文件**。它的主要功能是 **测试 `LinkHighlightImpl` 类的各种行为和功能**。`LinkHighlightImpl` 类负责实现用户在触摸屏设备上触摸链接时，链接高亮显示的效果。

以下是对其功能的详细解释，并结合与 JavaScript、HTML、CSS 的关系进行说明：

**1. 功能：测试链接高亮显示的实现**

* **核心功能验证：** 该测试文件旨在验证 `LinkHighlightImpl` 类是否能正确地识别并高亮显示用户触摸的链接。这包括在不同布局、不同场景下，是否能准确地找到链接元素并为其创建高亮效果。
* **动画效果测试：**  `LinkHighlightImpl` 通常会通过动画来呈现高亮效果，例如淡入淡出。测试会验证这些动画是否正确启动、更新和结束。
* **生命周期管理：** 测试确保当链接元素从 DOM 树中移除时，高亮效果能够正确地清理和释放资源，避免内存泄漏或错误。
* **与合成线程交互：** 链接高亮通常通过创建 compositor layers 来实现，这样可以利用 GPU 加速，提高性能。测试会验证 `LinkHighlightImpl` 与 compositor 的交互是否正确，例如是否创建了必要的 layer，并正确地设置了 layer 的属性。
* **多列布局支持：** 测试会验证在多列布局下，当链接跨越多列时，高亮效果是否能正确地覆盖所有列。

**2. 与 JavaScript, HTML, CSS 的关系举例说明：**

* **HTML:**
    * **测试目标：**  测试文件会加载包含链接的 HTML 页面 (`test_touch_link_highlight.html`)。这些链接是 `<a>` 标签，可能带有 `href` 属性。
    * **定位链接：** 测试通过模拟触摸事件，命中 HTML 页面中的特定链接元素，并验证 `LinkHighlightImpl` 是否能正确识别这些元素。例如，测试会模拟在坐标 (20, 20) 处触摸，而该坐标可能对应于 HTML 中的一个链接。
    * **多列布局：** 测试会创建包含多列布局的 HTML 结构，例如使用 CSS 的 `column-count` 或 `column-width` 属性，并验证在多列布局下链接高亮是否正常工作。
    * **`display: contents`:**  测试用例 `DisplayContents` 验证了当触摸位于 `display: contents` 元素的文本节点上时，不会触发链接高亮（因为该文本节点本身不是一个链接）。

* **CSS:**
    * **手型光标：** 测试用例 `verifyWebViewImplIntegration` 中提到 "Don't highlight if no 'hand cursor'"，这意味着 `LinkHighlightImpl` 的触发可能与链接元素是否具有手型光标（通过 CSS `cursor: pointer` 设置）有关。
    * **视觉效果：** 虽然测试文件本身不直接涉及 CSS 样式的具体细节，但它验证了高亮效果的 *存在* 和 *行为*，而高亮效果的视觉呈现最终是由 Blink 引擎内部的样式和渲染机制决定的。
    * **变换 (Transform)：**  在 `HighlightLayerEffectNode` 测试用例中，通过 JavaScript 设置了元素的 `transform` 属性 (`translateX(-1px)`）。这用于触发特定情况，以验证 `LinkHighlightImpl` 在元素具有 paint properties 时的行为。

* **JavaScript:**
    * **事件触发：** 尽管测试文件是 C++ 代码，它模拟了用户在 Web 页面上的交互，例如触摸事件 (`GestureShowPress`)。这些事件在实际的 Web 页面中通常是由 JavaScript 事件监听器处理的。`LinkHighlightImpl` 的工作就是在这些事件发生后，由 Blink 引擎内部的机制触发的。
    * **动态修改 DOM：** 测试用例 `resetDuringNodeRemoval` 和 `RemoveNodeDuringHighlightAnimation` 通过 C++ 代码模拟了 JavaScript 动态修改 DOM 的行为（例如，使用 `node->remove()`），并验证了 `LinkHighlightImpl` 在这些场景下的正确性。

**3. 逻辑推理、假设输入与输出：**

**假设输入：**

* **HTML 内容：** 加载了包含不同类型链接（例如，文本链接、包含在块级元素中的链接、多列布局中的链接）的 HTML 页面。
* **触摸事件：** 模拟了 `GestureShowPress` 类型的触摸事件，并指定了触摸发生的屏幕坐标 (例如 `gfx::PointF(20, 20)`）。

**逻辑推理：**

* **命中测试：** Blink 引擎会进行命中测试，判断触摸事件发生的位置是否位于一个可点击的链接元素上。
* **条件判断：** `LinkHighlightImpl` 可能会检查被触摸元素是否是一个链接 (`<a>` 标签) 或者具有某些特定的 CSS 属性（例如，手型光标）。
* **高亮创建：** 如果满足条件，`LinkHighlightImpl` 会创建一个或多个 compositor layers，用于绘制高亮效果。
* **动画执行：** 可能会启动一个动画，例如改变高亮层的透明度，实现淡入淡出的效果。
* **移除高亮：** 当触摸结束或链接元素被移除时，高亮效果会被移除，相关的 compositor layers 会被销毁。

**假设输出：**

* **`verifyWebViewImplIntegration`：**
    * **输入：** 在链接区域 (20, 20) 模拟 `GestureShowPress`。
    * **输出：** `GetLinkHighlightImpl()` 返回一个非空的指针，表示高亮效果已创建。`highlight->FragmentCountForTesting()` 返回 1，表示为一个链接片段创建了一个高亮层。
    * **输入：** 在非链接区域 (20, 40) 模拟 `GestureShowPress`。
    * **输出：** `web_view_impl->BestTapNode(targeted_event)` 返回 false，且 `GetLinkHighlightImpl()` 返回空指针，表示没有创建高亮。
* **`resetDuringNodeRemoval`：**
    * **输入：** 在链接上创建高亮，然后移除该链接节点。
    * **输出：** 在节点移除后，`highlight->GetLayoutObject()` 返回空指针，表示高亮效果正确地感知到目标元素的消失。
* **`MultiColumn`：**
    * **输入：** 触摸一个跨越多列的链接。
    * **输出：** `highlight->FragmentCountForTesting()` 返回值大于 1，表示为链接的每个列片段都创建了单独的高亮层。

**4. 用户或编程常见的使用错误：**

* **误判非链接元素：**  `LinkHighlightImpl` 的逻辑如果存在缺陷，可能会错误地将非链接元素（例如，仅仅是带有点击事件的 `<div>`）识别为链接并高亮显示。测试用例会覆盖这种情况，确保只有真正的链接才会被高亮。
* **资源泄漏：** 如果在链接元素被移除后，高亮效果相关的 compositor layers 没有被正确释放，就会导致内存泄漏。测试用例如 `resetDuringNodeRemoval` 旨在检测这类问题。
* **动画错误：** 高亮动画可能出现卡顿、闪烁或不符合预期的行为。测试会验证动画的正确性。
* **多列布局计算错误：** 在多列布局下，计算链接片段的位置和大小可能比较复杂。`LinkHighlightImpl` 如果计算错误，可能导致高亮效果的位置或尺寸不正确。`MultiColumn` 测试用例会覆盖这种情况。
* **并发问题：**  在复杂的渲染流水线中，如果 `LinkHighlightImpl` 与其他模块（例如，布局、合成）的交互存在并发问题，可能会导致难以预测的错误。虽然这个测试文件可能不直接测试并发，但其验证的功能是并发环境下的重要组成部分。

**5. 用户操作如何一步步到达这里，作为调试线索：**

1. **用户在触摸屏设备上打开一个包含链接的网页。**
2. **用户用手指或触摸笔点击或长按屏幕上的一个链接。**
3. **操作系统或浏览器接收到触摸事件。**
4. **浏览器（Chromium）将触摸事件传递给 Blink 引擎的输入处理模块。**
5. **Blink 的事件处理模块识别出这是一个可能的链接点击操作。**
6. **Blink 进行命中测试，确定触摸点下的 DOM 元素。**
7. **如果命中测试结果是一个链接元素，Blink 会通知 `LinkHighlight` 模块。**
8. **`LinkHighlight` 模块创建 `LinkHighlightImpl` 对象（如果尚未创建）。**
9. **`LinkHighlightImpl` 根据链接元素的位置和尺寸信息，创建用于高亮显示的 compositor layers。**
10. **`LinkHighlightImpl` 可能会启动一个动画，改变高亮层的属性，实现视觉效果。**
11. **当用户抬起手指或触摸笔，或者链接导航发生时，`LinkHighlightImpl` 会清理高亮效果，移除相关的 compositor layers。**

**作为调试线索：**

* **如果用户报告触摸链接时没有高亮显示，或者高亮显示不正确，** 开发人员可能会首先检查 `LinkHighlightImpl` 的相关代码和测试。
* **测试文件中的用例可以帮助复现问题场景。** 例如，如果用户在高亮显示时快速滑动导致问题，可能需要添加或修改测试用例来模拟这种快速滑动的场景。
* **断点调试：** 开发人员可以在 `LinkHighlightImpl` 的关键方法（例如，创建高亮层、更新动画、移除高亮层）中设置断点，跟踪代码执行流程，查看变量的值，从而找出问题所在。
* **日志输出：** 在 `LinkHighlightImpl` 的代码中添加日志输出，记录关键事件和状态，可以帮助分析问题。

总而言之，`blink/renderer/core/paint/link_highlight_impl_test.cc` 是一个至关重要的测试文件，用于确保 Chromium Blink 引擎中链接高亮功能的正确性和稳定性。它通过模拟各种场景和用户交互，验证 `LinkHighlightImpl` 类的行为，并帮助开发者避免和修复与链接高亮相关的 bug。

Prompt: 
```
这是目录为blink/renderer/core/paint/link_highlight_impl_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
/*
 * Copyright (C) 2012 Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1.  Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 * 2.  Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE INC. AND ITS CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL APPLE INC. OR ITS CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

#include "third_party/blink/renderer/core/paint/link_highlight_impl.h"

#include <memory>

#include "cc/animation/animation_timeline.h"
#include "cc/layers/picture_layer.h"
#include "cc/trees/layer_tree_host.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/input/web_input_event.h"
#include "third_party/blink/public/web/web_frame.h"
#include "third_party/blink/public/web/web_local_frame_client.h"
#include "third_party/blink/public/web/web_view_client.h"
#include "third_party/blink/renderer/core/dom/node.h"
#include "third_party/blink/renderer/core/events/web_input_event_conversion.h"
#include "third_party/blink/renderer/core/exported/web_view_impl.h"
#include "third_party/blink/renderer/core/frame/frame_test_helpers.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/web_local_frame_impl.h"
#include "third_party/blink/renderer/core/input/event_handler.h"
#include "third_party/blink/renderer/core/layout/layout_object.h"
#include "third_party/blink/renderer/core/page/link_highlight.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/paint/fragment_data_iterator.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/graphics/compositing/paint_artifact_compositor.h"
#include "third_party/blink/renderer/platform/heap/thread_state.h"
#include "third_party/blink/renderer/platform/testing/paint_test_configurations.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/url_loader_mock_factory.h"
#include "third_party/blink/renderer/platform/testing/url_test_helpers.h"
#include "third_party/blink/renderer/platform/web_test_support.h"
#include "ui/gfx/geometry/rect.h"

namespace blink {

class LinkHighlightImplTest : public testing::Test,
                              public PaintTestConfigurations {
 protected:
  GestureEventWithHitTestResults GetTargetedEvent(
      WebGestureEvent& touch_event) {
    WebGestureEvent scaled_event = TransformWebGestureEvent(
        web_view_helper_.GetWebView()->MainFrameImpl()->GetFrameView(),
        touch_event);
    return web_view_helper_.GetWebView()
        ->GetPage()
        ->DeprecatedLocalMainFrame()
        ->GetEventHandler()
        .TargetGestureEvent(scaled_event, true);
  }

  void SetUp() override {
    // TODO(crbug.com/751425): We should use the mock functionality
    // via |web_view_helper_|.
    WebURL url = url_test_helpers::RegisterMockedURLLoadFromBase(
        WebString::FromUTF8("http://www.test.com/"), test::CoreTestDataPath(),
        WebString::FromUTF8("test_touch_link_highlight.html"));
    web_view_helper_.InitializeAndLoad(url.GetString().Utf8());

    int page_width = 640;
    int page_height = 480;
    WebViewImpl* web_view_impl = web_view_helper_.GetWebView();
    web_view_impl->MainFrameViewWidget()->Resize(
        gfx::Size(page_width, page_height));
    UpdateAllLifecyclePhases();
  }

  GestureEventWithHitTestResults GestureShowPress(const gfx::PointF& point) {
    WebGestureEvent touch_event(WebInputEvent::Type::kGestureShowPress,
                                WebInputEvent::kNoModifiers,
                                WebInputEvent::GetStaticTimeStampForTests(),
                                WebGestureDevice::kTouchscreen);
    touch_event.SetPositionInWidget(point);
    return GetTargetedEvent(touch_event);
  }

  void TearDown() override {
    url_test_helpers::UnregisterAllURLsAndClearMemoryCache();

    // Ensure we fully clean up while scoped settings are enabled. Without this,
    // garbage collection would occur after Scoped[setting]ForTest is out of
    // scope, so the settings would not apply in some destructors.
    web_view_helper_.Reset();
    ThreadState::Current()->CollectAllGarbageForTesting();
  }

  size_t LayerCount() {
    return paint_artifact_compositor()->RootLayer()->children().size();
  }

  size_t AnimationCount() {
    cc::AnimationHost* animation_host = web_view_helper_.LocalMainFrame()
                                            ->GetFrameView()
                                            ->GetCompositorAnimationHost();
    return animation_host->ticking_animations_for_testing().size();
  }

  PaintArtifactCompositor* paint_artifact_compositor() {
    auto* local_frame_view = web_view_helper_.LocalMainFrame()->GetFrameView();
    return local_frame_view->GetPaintArtifactCompositor();
  }

  void UpdateAllLifecyclePhases() {
    web_view_helper_.GetWebView()->MainFrameWidget()->UpdateAllLifecyclePhases(
        DocumentUpdateReason::kTest);
  }

  LinkHighlight& GetLinkHighlight() {
    return web_view_helper_.GetWebView()->GetPage()->GetLinkHighlight();
  }

  LinkHighlightImpl* GetLinkHighlightImpl() {
    return GetLinkHighlight().impl_.get();
  }

  cc::AnimationHost* GetAnimationHost() {
    EXPECT_EQ(GetLinkHighlight().timeline_->animation_host(),
              GetLinkHighlight().animation_host_);
    return GetLinkHighlight().animation_host_;
  }

  test::TaskEnvironment task_environment_;
  frame_test_helpers::WebViewHelper web_view_helper_;
};

INSTANTIATE_PAINT_TEST_SUITE_P(LinkHighlightImplTest);

TEST_P(LinkHighlightImplTest, verifyWebViewImplIntegration) {
  WebViewImpl* web_view_impl = web_view_helper_.GetWebView();
  size_t animation_count_before_highlight = AnimationCount();

  GestureEventWithHitTestResults targeted_event =
      GestureShowPress(gfx::PointF(20, 20));
  ASSERT_TRUE(web_view_impl->BestTapNode(targeted_event));

  targeted_event = GestureShowPress(gfx::PointF(20, 40));
  EXPECT_FALSE(web_view_impl->BestTapNode(targeted_event));

  targeted_event = GestureShowPress(gfx::PointF(20, 20));
  // Shouldn't crash.
  web_view_impl->EnableTapHighlightAtPoint(targeted_event);

  const auto* highlight = GetLinkHighlightImpl();
  EXPECT_TRUE(highlight);
  EXPECT_EQ(1u, highlight->FragmentCountForTesting());
  EXPECT_TRUE(highlight->LayerForTesting(0));

  // Find a target inside a scrollable div
  targeted_event = GestureShowPress(gfx::PointF(20, 100));
  web_view_impl->EnableTapHighlightAtPoint(targeted_event);
  GetLinkHighlight().UpdateOpacityAndRequestAnimation();
  UpdateAllLifecyclePhases();
  ASSERT_TRUE(highlight);

  // Ensure the timeline and animation was added to a host.
  EXPECT_TRUE(GetAnimationHost());
  EXPECT_EQ(animation_count_before_highlight + 1, AnimationCount());

  // Don't highlight if no "hand cursor"
  targeted_event = GestureShowPress(
      gfx::PointF(20, 220));  // An A-link with cross-hair cursor.
  web_view_impl->EnableTapHighlightAtPoint(targeted_event);
  EXPECT_FALSE(GetLinkHighlightImpl());
  // Expect animation to have been removed.
  EXPECT_EQ(animation_count_before_highlight, AnimationCount());

  targeted_event = GestureShowPress(gfx::PointF(20, 260));  // A text input box.
  web_view_impl->EnableTapHighlightAtPoint(targeted_event);
  EXPECT_FALSE(GetLinkHighlightImpl());
}

TEST_P(LinkHighlightImplTest, resetDuringNodeRemoval) {
  WebViewImpl* web_view_impl = web_view_helper_.GetWebView();

  GestureEventWithHitTestResults targeted_event =
      GestureShowPress(gfx::PointF(20, 20));
  Node* touch_node = web_view_impl->BestTapNode(targeted_event);
  ASSERT_TRUE(touch_node);

  web_view_impl->EnableTapHighlightAtPoint(targeted_event);
  const auto* highlight = GetLinkHighlightImpl();
  ASSERT_TRUE(highlight);
  EXPECT_EQ(touch_node->GetLayoutObject(), highlight->GetLayoutObject());

  touch_node->remove(IGNORE_EXCEPTION_FOR_TESTING);
  UpdateAllLifecyclePhases();

  ASSERT_EQ(highlight, GetLinkHighlightImpl());
  ASSERT_TRUE(highlight);
  EXPECT_FALSE(highlight->GetLayoutObject());
}

// A lifetime test: delete LayerTreeView while running LinkHighlights.
TEST_P(LinkHighlightImplTest, resetLayerTreeView) {
  WebViewImpl* web_view_impl = web_view_helper_.GetWebView();

  GestureEventWithHitTestResults targeted_event =
      GestureShowPress(gfx::PointF(20, 20));
  Node* touch_node = web_view_impl->BestTapNode(targeted_event);
  ASSERT_TRUE(touch_node);

  web_view_impl->EnableTapHighlightAtPoint(targeted_event);
  ASSERT_TRUE(GetLinkHighlightImpl());
}

TEST_P(LinkHighlightImplTest, HighlightLayerEffectNode) {
  // We need to test highlight animation which is disabled in web test mode.
  ScopedWebTestMode web_test_mode(false);
  WebViewImpl* web_view_impl = web_view_helper_.GetWebView();

  size_t layer_count_before_highlight = LayerCount();

  GestureEventWithHitTestResults targeted_event =
      GestureShowPress(gfx::PointF(20, 20));
  Node* touch_node = web_view_impl->BestTapNode(targeted_event);
  ASSERT_TRUE(touch_node);

  // This is to reproduce crbug.com/1193486 without the fix by forcing the node
  // to always have paint properties. The issue was otherwise hidden because
  // we also unnecessarily forced PaintPropertyChangeType::kNodeAddedOrRemoved
  // when an object entered or exited the highlighted mode.
  To<Element>(touch_node)
      ->SetInlineStyleProperty(CSSPropertyID::kTransform, "translateX(-1px)",
                               false);

  web_view_impl->EnableTapHighlightAtPoint(targeted_event);
  // The highlight should create one additional layer.
  EXPECT_EQ(layer_count_before_highlight + 1, LayerCount());

  auto* highlight = GetLinkHighlightImpl();
  ASSERT_TRUE(highlight);

  // Check that the link highlight cc layer has a cc effect property tree node.
  EXPECT_EQ(1u, highlight->FragmentCountForTesting());
  auto* layer = highlight->LayerForTesting(0);
  // We don't set layer's element id.
  EXPECT_EQ(cc::ElementId(), layer->element_id());
  auto effect_tree_index = layer->effect_tree_index();
  auto* property_trees = layer->layer_tree_host()->property_trees();
  EXPECT_EQ(effect_tree_index,
            property_trees->effect_tree()
                .FindNodeFromElementId(highlight->ElementIdForTesting())
                ->id);
  // The link highlight cc effect node should correspond to the blink effect
  // node.
  EXPECT_EQ(highlight->Effect().GetCompositorElementId(),
            highlight->ElementIdForTesting());

  // Initially the highlight node has full opacity as it is expected to remain
  // visible until the user completes a tap. See https://crbug.com/974631
  EXPECT_EQ(1.f, highlight->Effect().Opacity());
  EXPECT_TRUE(highlight->Effect().HasActiveOpacityAnimation());

  // After starting the highlight animation the effect node's opacity should
  // be 0.f as it will be overridden by the animation but may become visible
  // before the animation is destructed. See https://crbug.com/974160
  GetLinkHighlight().UpdateOpacityAndRequestAnimation();
  EXPECT_EQ(0.f, highlight->Effect().Opacity());
  EXPECT_TRUE(highlight->Effect().HasActiveOpacityAnimation());

  highlight->NotifyAnimationFinished(base::TimeDelta(), 0);
  EXPECT_TRUE(web_view_impl->MainFrameImpl()
                  ->GetFrameView()
                  ->VisualViewportOrOverlayNeedsRepaintForTesting());
  UpdateAllLifecyclePhases();
  // Removing the highlight layer should drop the cc layer count by one.
  EXPECT_EQ(layer_count_before_highlight, LayerCount());
}

TEST_P(LinkHighlightImplTest, RemoveNodeDuringHighlightAnimation) {
  // We need to test highlight animation which is disabled in web test mode.
  ScopedWebTestMode web_test_mode(false);
  WebViewImpl* web_view_impl = web_view_helper_.GetWebView();

  size_t layer_count_before_highlight = LayerCount();
  size_t animation_count_before_highlight = AnimationCount();

  GestureEventWithHitTestResults targeted_event =
      GestureShowPress(gfx::PointF(20, 20));
  Node* touch_node = web_view_impl->BestTapNode(targeted_event);
  ASSERT_TRUE(touch_node);

  web_view_impl->EnableTapHighlightAtPoint(targeted_event);
  GetLinkHighlight().UpdateOpacityAndRequestAnimation();
  // The animation should not be created until the next lifecycle update
  // after the effect node composition can be verified.
  EXPECT_EQ(animation_count_before_highlight, AnimationCount());
  UpdateAllLifecyclePhases();
  // The highlight should create one additional layer and animate it.
  EXPECT_EQ(layer_count_before_highlight + 1, LayerCount());
  EXPECT_EQ(animation_count_before_highlight + 1, AnimationCount());

  touch_node->remove(IGNORE_EXCEPTION_FOR_TESTING);
  UpdateAllLifecyclePhases();
  // Removing the highlight layer should drop the cc layer count by one and
  // its corresponding animation.
  EXPECT_EQ(layer_count_before_highlight, LayerCount());
  EXPECT_EQ(animation_count_before_highlight, AnimationCount());
}

TEST_P(LinkHighlightImplTest, MultiColumn) {
  WebViewImpl* web_view_impl = web_view_helper_.GetWebView();

  UpdateAllLifecyclePhases();
  size_t layer_count_before_highlight = LayerCount();

  // This will touch the link under multicol.
  GestureEventWithHitTestResults targeted_event =
      GestureShowPress(gfx::PointF(20, 300));
  Node* touch_node = web_view_impl->BestTapNode(targeted_event);
  ASSERT_TRUE(touch_node);

  web_view_impl->EnableTapHighlightAtPoint(targeted_event);

  const auto* highlight = GetLinkHighlightImpl();
  ASSERT_TRUE(highlight);

  // The link highlight cc effect node should correspond to the blink effect
  // node.
  const auto& effect = highlight->Effect();
  EXPECT_EQ(effect.GetCompositorElementId(), highlight->ElementIdForTesting());
  EXPECT_TRUE(effect.HasActiveOpacityAnimation());

  FragmentDataIterator iterator1(*touch_node->GetLayoutObject());
  const auto* first_fragment = iterator1.GetFragmentData();
  iterator1.Advance();
  const auto* second_fragment = iterator1.GetFragmentData();
  ASSERT_TRUE(second_fragment);
  EXPECT_FALSE(iterator1.Advance());

  auto check_layer = [&](const cc::PictureLayer* layer) {
    ASSERT_TRUE(layer);
    // We don't set layer's element id.
    EXPECT_EQ(cc::ElementId(), layer->element_id());
    auto effect_tree_index = layer->effect_tree_index();
    auto* property_trees = layer->layer_tree_host()->property_trees();
    EXPECT_EQ(effect_tree_index,
              property_trees->effect_tree()
                  .FindNodeFromElementId(highlight->ElementIdForTesting())
                  ->id);
  };

  // The highlight should create 2 additional layer, each for each fragment.
  EXPECT_EQ(layer_count_before_highlight + 2, LayerCount());
  EXPECT_EQ(2u, highlight->FragmentCountForTesting());
  check_layer(highlight->LayerForTesting(0));
  check_layer(highlight->LayerForTesting(1));

  Element* multicol = touch_node->parentElement();
  EXPECT_EQ(50, multicol->OffsetHeight());
  // Make multicol shorter to create 3 total columns for touch_node.
  multicol->setAttribute(html_names::kStyleAttr, AtomicString("height: 25px"));
  UpdateAllLifecyclePhases();
  ASSERT_EQ(first_fragment, &touch_node->GetLayoutObject()->FirstFragment());
  FragmentDataIterator iterator2(*touch_node->GetLayoutObject());
  iterator2.Advance();
  second_fragment = iterator2.GetFragmentData();
  ASSERT_TRUE(second_fragment);
  iterator2.Advance();
  const auto* third_fragment = iterator2.GetFragmentData();
  ASSERT_TRUE(third_fragment);
  EXPECT_FALSE(iterator2.Advance());

  EXPECT_EQ(layer_count_before_highlight + 3, LayerCount());
  EXPECT_EQ(3u, highlight->FragmentCountForTesting());
  check_layer(highlight->LayerForTesting(0));
  check_layer(highlight->LayerForTesting(1));
  check_layer(highlight->LayerForTesting(2));

  // Make multicol taller to create only 1 column for touch_node.
  multicol->setAttribute(html_names::kStyleAttr, AtomicString("height: 100px"));
  UpdateAllLifecyclePhases();
  ASSERT_EQ(first_fragment, &touch_node->GetLayoutObject()->FirstFragment());
  FragmentDataIterator iterator3(*touch_node->GetLayoutObject());
  EXPECT_FALSE(iterator3.Advance());

  EXPECT_EQ(layer_count_before_highlight + 1, LayerCount());
  EXPECT_EQ(1u, highlight->FragmentCountForTesting());
  check_layer(highlight->LayerForTesting(0));

  touch_node->remove(IGNORE_EXCEPTION_FOR_TESTING);
  UpdateAllLifecyclePhases();
  // Removing the highlight layer should drop the cc layers for highlights.
  EXPECT_EQ(layer_count_before_highlight, LayerCount());
}

TEST_P(LinkHighlightImplTest, DisplayContents) {
  WebViewImpl* web_view_impl = web_view_helper_.GetWebView();

  GestureEventWithHitTestResults targeted_event =
      GestureShowPress(gfx::PointF(20, 400));
  const Node* touched_node = targeted_event.GetHitTestResult().InnerNode();
  EXPECT_TRUE(touched_node->IsTextNode());
  EXPECT_FALSE(web_view_impl->BestTapNode(targeted_event));

  web_view_impl->EnableTapHighlightAtPoint(targeted_event);
  EXPECT_FALSE(GetLinkHighlightImpl());
}

}  // namespace blink

"""

```