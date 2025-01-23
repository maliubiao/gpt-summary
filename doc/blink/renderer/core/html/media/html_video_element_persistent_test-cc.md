Response:
My thinking process for analyzing the provided C++ test file went something like this:

1. **Understand the Purpose:** The filename `html_video_element_persistent_test.cc` immediately suggests this file contains tests related to the "persistent" state of an HTML video element. The word "persistent" implies something that survives changes or remains active across events.

2. **Identify Key Classes and Concepts:** I scanned the `#include` directives and the class definitions to identify the main components being tested. Key classes include:
    * `HTMLVideoElement`: The central class under test.
    * `Fullscreen`:  Indicates interaction with the fullscreen API.
    * `FullscreenMockChromeClient`: A mock object for simulating the browser's fullscreen behavior.
    * `HTMLDivElement`: Used as a container element.
    * `PageTestBase`: The base class for the test fixture, providing a simulated web page environment.

3. **Analyze the Test Fixture (`HTMLVideoElementPersistentTest`):** I looked at the `SetUp` method to understand the initial state of the test environment. It creates a simple HTML structure with a `<div>` containing a `<video>` element. The `VideoElement()` and `DivElement()` helper methods provide easy access to these elements. The `FullscreenElement()` method retrieves the currently fullscreen element. The `SimulateDidEnterFullscreen()`, `SimulateDidExitFullscreen()`, and `SimulateBecamePersistentVideo()` methods are crucial for controlling the test's state transitions.

4. **Examine Individual Test Cases:** I went through each `TEST_F` function to understand the specific scenarios being tested. For each test case, I focused on:
    * **Initial Setup:** What's the initial state before the test begins?
    * **Actions Performed:** What methods are called or events are simulated?
    * **Assertions Made:** What `EXPECT_EQ`, `EXPECT_TRUE`, and `EXPECT_FALSE` statements are used to verify the expected outcomes?
    * **Mock Expectations:**  What `EXPECT_CALL` statements are used to verify interactions with the `FullscreenMockChromeClient`?

5. **Infer Functionality from Test Cases:** Based on the test cases, I started to deduce the functionalities being tested:
    * **Persistence without Fullscreen:**  Tests whether setting the `persistent` state has any effect when the video is not in fullscreen.
    * **Persistence when Video is Fullscreen:** Tests if setting the `persistent` state works when the video element itself is in fullscreen.
    * **Persistence when Container is Fullscreen:**  The core scenario, testing the behavior when a parent element of the video is in fullscreen and the video's persistence is toggled.
    * **Exiting Fullscreen before Persistence:** Checks what happens when fullscreen is exited *after* setting the persistence flag.
    * **CSS Interaction (Internal Pseudo-classes):**  Verifies that the internal pseudo-classes related to persistence are only applied by the user-agent stylesheet and cannot be queried directly.
    * **Element Removal During Persistence:** Tests what happens when the parent container or the video element itself is removed from the DOM while the video is marked as persistent.
    * **Persistence Scoping:** Checks if the `ContainsPersistentVideo()` method is scoped correctly within the fullscreen element.

6. **Relate to Web Technologies (JavaScript, HTML, CSS):** I considered how the tested functionalities relate to web development:
    * **JavaScript:** The tests implicitly involve JavaScript because the properties and methods being tested are accessible and controllable via JavaScript. The fullscreen API itself is a JavaScript API.
    * **HTML:** The tests directly manipulate HTML elements (`<video>`, `<div>`). The concept of a video element and its containing elements is fundamental to HTML.
    * **CSS:** The test regarding internal pseudo-classes directly examines the interaction between JavaScript (the test code) and CSS selectors, especially regarding the scope of UA stylesheets.

7. **Identify Logic and Assumptions:** I looked for patterns in the test cases to infer the underlying logic. The core logic seems to be about managing the "persistent" state of a video element when its containing element is in fullscreen. The assumption is that this "persistent" state might be used for specific browser behaviors when transitioning out of fullscreen.

8. **Pinpoint Potential User/Programming Errors:** Based on the tested scenarios, I identified common mistakes developers might make, such as:
    * Assuming `IsPersistent()` or `ContainsPersistentVideo()` works when the video isn't in a fullscreen parent.
    * Trying to query or style elements using the internal pseudo-classes from their own stylesheets.
    * Not considering the impact of removing elements from the DOM while a video is in a persistent fullscreen state.

9. **Structure the Explanation:** Finally, I organized my findings into a clear and structured explanation covering the functionality, relationships to web technologies, logic, and potential errors, using the provided headings as a guide. I also ensured to provide concrete examples for each point.
这个C++源代码文件 `html_video_element_persistent_test.cc` 是 Chromium Blink 引擎中的一个测试文件。它的主要功能是**测试 `HTMLVideoElement` 的持久化 (persistent) 状态在不同场景下的行为，特别是与全屏 API 的交互**。

以下是更详细的分析：

**1. 主要功能：**

* **测试 `HTMLVideoElement::SetPersistentState(bool)` 方法:**  该方法用于设置 video 元素是否处于“持久化”状态。这个状态可能影响浏览器在离开全屏后如何处理视频，例如，在某些平台上，持久化的视频可能会继续以画中画 (Picture-in-Picture) 模式播放。
* **测试全屏 API 的交互:**  测试文件模拟了进入和退出全屏的场景，并检查在这些过程中设置视频的持久化状态会产生什么影响。
* **测试 `Element::ContainsPersistentVideo()` 方法:** 该方法用于检查一个元素是否包含持久化的视频元素。
* **测试在不同 DOM 结构下的持久化行为:** 测试了当视频元素本身全屏，或者包含视频的父元素全屏时，设置持久化状态的效果。
* **测试在设置持久化状态后移除元素的影响:**  测试了在视频被标记为持久化后，移除其父元素或自身，持久化状态会如何变化。
* **测试内部 CSS 伪类的行为:** 验证了与持久化状态相关的内部 CSS 伪类 `:internal-video-persistent` 和 `:-internal-video-persistent-ancestor` 的行为，确保它们只能在 User-Agent 样式表中使用，不能被开发者直接查询。

**2. 与 JavaScript, HTML, CSS 的关系：**

* **HTML:**  该测试文件直接操作 HTML 元素，例如 `<video>` 和 `<div>`。它通过 `GetDocument().body()->setInnerHTML()` 创建了一个包含这些元素的简单 HTML 结构。测试的重点是 `<video>` 元素的 `persistent` 状态以及其父元素是否包含持久化的视频。
    * **例子:** 测试用例中创建了 `<video>` 元素，并将其嵌入到 `<div>` 中，模拟了常见的 HTML 结构。
* **JavaScript:**  尽管这个文件是 C++ 代码，但它测试的功能是可以通过 JavaScript API 访问和操作的。
    *  `HTMLVideoElement` 在 JavaScript 中可以通过 `document.querySelector('video')` 等方法获取，并且可以通过 JavaScript 设置全屏状态 (例如使用 `videoElement.requestFullscreen()`)。
    *  虽然 JavaScript 中没有直接设置 "persistent" 状态的 API (从测试代码推断，这可能是 Blink 引擎内部的状态)，但这个状态的变化可能会影响 JavaScript 可观察的行为，例如全屏 API 的事件或者其他媒体相关的 API 行为。
* **CSS:** 测试文件涉及了 CSS 伪类。
    * **例子:** 测试用例 `internalPseudoClassOnlyUAStyleSheet` 验证了开发者不能直接使用 `matches()` 方法查询 `:-internal-video-persistent` 和 `:-internal-video-persistent-ancestor` 伪类。这表明这些伪类是浏览器内部使用的，用于在 User-Agent 样式表中应用特定的样式，开发者不能在自己的 CSS 中使用或查询它们。这些伪类可能用于实现与持久化视频相关的视觉效果或交互行为。

**3. 逻辑推理与假设输入/输出：**

测试文件中的每个 `TEST_F` 都是一个独立的测试用例，可以看作是一个逻辑推理。

* **假设输入:**  测试用例通过调用 `SimulateBecamePersistentVideo(true/false)` 来模拟设置视频元素的持久化状态。同时，通过 `Fullscreen::RequestFullscreen()` 和模拟事件 `SimulateDidEnterFullscreen()`, `SimulateDidExitFullscreen()` 来模拟全屏状态的改变。
* **逻辑推理:**  每个测试用例都包含一系列操作，然后通过 `EXPECT_EQ`, `EXPECT_TRUE`, `EXPECT_FALSE` 等断言来验证操作后的状态是否符合预期。例如，当一个 `<div>` 元素全屏，并且其包含的 `<video>` 元素被设置为持久化时，预期 `DivElement()->ContainsPersistentVideo()` 和 `VideoElement()->IsPersistent()` 都应该返回 `true`。
* **输出:** 测试用例的输出是断言的结果。如果所有断言都通过，则测试用例通过，表明被测试的功能按照预期工作。如果断言失败，则表明代码存在 bug。

**举例说明（一个测试用例的逻辑推理）：**

**测试用例：`divIsFullscreen`**

* **假设输入:**
    1. 初始化状态：页面包含一个 `<div>` 和一个 `<video>`。
    2. 操作：
        * 请求 `<div>` 元素进入全屏。
        * 模拟进入全屏成功。
        * 将 `<video>` 元素设置为持久化。
        * 再次将 `<video>` 元素设置为持久化（验证重复设置）。
        * 将 `<video>` 元素设置为非持久化。
* **逻辑推理 (断言):**
    * 在 `<div>` 全屏后，`FullscreenElement()` 应该返回 `DivElement()`。
    * 在将 `<video>` 设置为持久化后，`VideoElement()->IsPersistent()`、`DivElement()->ContainsPersistentVideo()` 和 `VideoElement()->ContainsPersistentVideo()` 应该都为 `true`。
    * 重复设置持久化状态不应该有副作用。
    * 在将 `<video>` 设置为非持久化后，`VideoElement()->IsPersistent()`、`DivElement()->ContainsPersistentVideo()` 和 `VideoElement()->ContainsPersistentVideo()` 应该都为 `false`。

**4. 用户或编程常见的使用错误：**

* **错误地认为在非全屏状态下设置持久化状态会立即生效:**  从测试用例 `nothingIsFullscreen` 可以看出，在没有元素全屏的情况下，设置视频的持久化状态是无效的。开发者可能会错误地认为无论视频是否在全屏状态，都可以随意设置其持久化状态。
    * **例子:**  开发者可能写出这样的 JavaScript 代码：`videoElement.persistent = true;` 并期望视频在任何情况下都具有持久化的特性，但这可能只在特定的全屏场景下才有效。
* **尝试使用 JavaScript 查询内部 CSS 伪类:** 测试用例 `internalPseudoClassOnlyUAStyleSheet` 明确禁止使用 `matches()` 方法查询 `:-internal-video-persistent` 等伪类。开发者可能会尝试使用这些伪类来直接控制样式或行为，但这将导致错误。
    * **例子:**  开发者可能会尝试使用 `document.querySelector('video:-internal-video-persistent')` 来选择持久化的视频元素，但这不会生效。
* **在设置持久化状态后，没有考虑到移除元素的影响:** 测试用例 `removeContainerWhilePersisting`, `removeVideoWhilePersisting`, `removeVideoWithLayerWhilePersisting` 演示了在视频被标记为持久化后，移除其父元素或自身会导致持久化状态被清除。开发者需要注意在操作 DOM 结构时，持久化状态可能会发生变化。
    * **例子:**  开发者可能在一个全屏的 `<div>` 中将 `<video>` 设置为持久化，然后由于某种原因移除了这个 `<div>`，而没有意识到视频的持久化状态也会被清除。

总而言之，这个测试文件的目的是确保 `HTMLVideoElement` 的持久化状态功能在各种场景下都能正确地工作，并且能够与全屏 API 和 DOM 操作正确地交互。它也揭示了一些开发者可能会犯的关于持久化状态使用的错误。

### 提示词
```
这是目录为blink/renderer/core/html/media/html_video_element_persistent_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/html/media/html_video_element.h"

#include <memory>

#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_fullscreen_options.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/fullscreen/fullscreen.h"
#include "third_party/blink/renderer/core/html/html_div_element.h"
#include "third_party/blink/renderer/core/loader/empty_clients.h"
#include "third_party/blink/renderer/core/testing/page_test_base.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"

namespace blink {

namespace {

class FullscreenMockChromeClient : public EmptyChromeClient {
 public:
  MOCK_METHOD3(EnterFullscreen,
               void(LocalFrame&,
                    const FullscreenOptions*,
                    FullscreenRequestType));
  MOCK_METHOD1(ExitFullscreen, void(LocalFrame&));
};

using testing::_;
using testing::Sequence;

}  // anonymous namespace

class HTMLVideoElementPersistentTest : public PageTestBase {
 protected:
  void SetUp() override {
    chrome_client_ = MakeGarbageCollected<FullscreenMockChromeClient>();
    PageTestBase::SetupPageWithClients(chrome_client_);
    GetDocument().body()->setInnerHTML(
        "<body><div><video></video></div></body>");
  }

  HTMLVideoElement* VideoElement() {
    return To<HTMLVideoElement>(
        GetDocument().QuerySelector(AtomicString("video")));
  }

  HTMLDivElement* DivElement() {
    return To<HTMLDivElement>(GetDocument().QuerySelector(AtomicString("div")));
  }

  Element* FullscreenElement() {
    return Fullscreen::FullscreenElementFrom(GetDocument());
  }

  FullscreenMockChromeClient& GetMockChromeClient() { return *chrome_client_; }

  void SimulateDidEnterFullscreen() {
    Fullscreen::DidResolveEnterFullscreenRequest(GetDocument(),
                                                 true /* granted */);
  }

  void SimulateDidExitFullscreen() {
    Fullscreen::DidExitFullscreen(GetDocument());
  }

  void SimulateBecamePersistentVideo(bool value) {
    VideoElement()->SetPersistentState(value);
  }

 private:
  Persistent<FullscreenMockChromeClient> chrome_client_;
};

TEST_F(HTMLVideoElementPersistentTest, nothingIsFullscreen) {
  Sequence s;

  EXPECT_EQ(FullscreenElement(), nullptr);

  // Making the video persistent should be a no-op.
  SimulateBecamePersistentVideo(true);
  EXPECT_EQ(FullscreenElement(), nullptr);
  EXPECT_FALSE(VideoElement()->IsPersistent());
  EXPECT_FALSE(DivElement()->ContainsPersistentVideo());
  EXPECT_FALSE(VideoElement()->ContainsPersistentVideo());

  // Making the video not persitent should also be a no-op.
  SimulateBecamePersistentVideo(false);
  EXPECT_EQ(FullscreenElement(), nullptr);
  EXPECT_FALSE(VideoElement()->IsPersistent());
  EXPECT_FALSE(DivElement()->ContainsPersistentVideo());
  EXPECT_FALSE(VideoElement()->ContainsPersistentVideo());
}

TEST_F(HTMLVideoElementPersistentTest, videoIsFullscreen) {
  EXPECT_EQ(FullscreenElement(), nullptr);

  EXPECT_CALL(GetMockChromeClient(), EnterFullscreen(_, _, _)).Times(1);
  EXPECT_CALL(GetMockChromeClient(), ExitFullscreen(_)).Times(0);

  LocalFrame::NotifyUserActivation(
      GetDocument().GetFrame(), mojom::UserActivationNotificationType::kTest);
  Fullscreen::RequestFullscreen(*VideoElement());
  SimulateDidEnterFullscreen();
  EXPECT_EQ(FullscreenElement(), VideoElement());

  // This should be no-op.
  SimulateBecamePersistentVideo(true);
  EXPECT_EQ(FullscreenElement(), VideoElement());
  EXPECT_FALSE(VideoElement()->IsPersistent());
  EXPECT_FALSE(DivElement()->ContainsPersistentVideo());
  EXPECT_FALSE(VideoElement()->ContainsPersistentVideo());

  // This should be no-op.
  SimulateBecamePersistentVideo(false);
  EXPECT_EQ(FullscreenElement(), VideoElement());
  EXPECT_FALSE(VideoElement()->IsPersistent());
  EXPECT_FALSE(DivElement()->ContainsPersistentVideo());
  EXPECT_FALSE(VideoElement()->ContainsPersistentVideo());
}

TEST_F(HTMLVideoElementPersistentTest, divIsFullscreen) {
  EXPECT_EQ(FullscreenElement(), nullptr);

  EXPECT_CALL(GetMockChromeClient(), EnterFullscreen(_, _, _)).Times(1);
  EXPECT_CALL(GetMockChromeClient(), ExitFullscreen(_)).Times(0);

  LocalFrame::NotifyUserActivation(
      GetDocument().GetFrame(), mojom::UserActivationNotificationType::kTest);
  Fullscreen::RequestFullscreen(*DivElement());
  SimulateDidEnterFullscreen();
  EXPECT_EQ(FullscreenElement(), DivElement());

  // Make the video persistent.
  SimulateBecamePersistentVideo(true);
  EXPECT_EQ(FullscreenElement(), DivElement());
  EXPECT_TRUE(VideoElement()->IsPersistent());
  EXPECT_TRUE(DivElement()->ContainsPersistentVideo());
  EXPECT_TRUE(VideoElement()->ContainsPersistentVideo());

  // This should be no-op.
  SimulateBecamePersistentVideo(true);
  EXPECT_EQ(FullscreenElement(), DivElement());
  EXPECT_TRUE(VideoElement()->IsPersistent());
  EXPECT_TRUE(DivElement()->ContainsPersistentVideo());
  EXPECT_TRUE(VideoElement()->ContainsPersistentVideo());

  // Make the video not persistent.
  SimulateBecamePersistentVideo(false);
  EXPECT_EQ(FullscreenElement(), DivElement());
  EXPECT_FALSE(VideoElement()->IsPersistent());
  EXPECT_FALSE(DivElement()->ContainsPersistentVideo());
  EXPECT_FALSE(VideoElement()->ContainsPersistentVideo());
}

TEST_F(HTMLVideoElementPersistentTest, exitFullscreenBeforePersistence) {
  EXPECT_EQ(FullscreenElement(), nullptr);

  EXPECT_CALL(GetMockChromeClient(), EnterFullscreen(_, _, _)).Times(1);
  EXPECT_CALL(GetMockChromeClient(), ExitFullscreen(_)).Times(1);

  LocalFrame::NotifyUserActivation(
      GetDocument().GetFrame(), mojom::UserActivationNotificationType::kTest);
  Fullscreen::RequestFullscreen(*DivElement());
  SimulateDidEnterFullscreen();
  EXPECT_EQ(FullscreenElement(), DivElement());

  SimulateBecamePersistentVideo(true);

  Fullscreen::FullyExitFullscreen(GetDocument());
  SimulateDidExitFullscreen();
  EXPECT_EQ(FullscreenElement(), nullptr);

  // Video persistence states should still apply.
  EXPECT_TRUE(VideoElement()->IsPersistent());
  EXPECT_TRUE(DivElement()->ContainsPersistentVideo());
  EXPECT_TRUE(VideoElement()->ContainsPersistentVideo());

  // Make the video not persistent, cleaned up.
  SimulateBecamePersistentVideo(false);
  EXPECT_FALSE(VideoElement()->IsPersistent());
  EXPECT_FALSE(DivElement()->ContainsPersistentVideo());
  EXPECT_FALSE(VideoElement()->ContainsPersistentVideo());
}

TEST_F(HTMLVideoElementPersistentTest, internalPseudoClassOnlyUAStyleSheet) {
  EXPECT_EQ(FullscreenElement(), nullptr);

  EXPECT_CALL(GetMockChromeClient(), EnterFullscreen(_, _, _)).Times(1);
  EXPECT_CALL(GetMockChromeClient(), ExitFullscreen(_)).Times(0);

  EXPECT_FALSE(DivElement()->matches(AtomicString(":fullscreen")));

  {
    DummyExceptionStateForTesting exception_state;
    EXPECT_FALSE(DivElement()->matches(
        AtomicString(":-internal-video-persistent-ancestor"), exception_state));
    EXPECT_TRUE(exception_state.HadException());
  }
  {
    DummyExceptionStateForTesting exception_state;
    EXPECT_FALSE(VideoElement()->matches(
        AtomicString(":-internal-video-persistent"), exception_state));
    EXPECT_TRUE(exception_state.HadException());
  }
  {
    DummyExceptionStateForTesting exception_state;
    EXPECT_FALSE(VideoElement()->matches(
        AtomicString(":-internal-video-persistent-ancestor"), exception_state));
    EXPECT_TRUE(exception_state.HadException());
  }

  LocalFrame::NotifyUserActivation(
      GetDocument().GetFrame(), mojom::UserActivationNotificationType::kTest);
  Fullscreen::RequestFullscreen(*DivElement());
  SimulateDidEnterFullscreen();
  SimulateBecamePersistentVideo(true);

  EXPECT_EQ(FullscreenElement(), DivElement());
  EXPECT_TRUE(VideoElement()->IsPersistent());
  EXPECT_TRUE(DivElement()->ContainsPersistentVideo());
  EXPECT_TRUE(VideoElement()->ContainsPersistentVideo());

  {
    DummyExceptionStateForTesting exception_state;
    // The :internal-* rules apply only from the UA stylesheet.
    EXPECT_TRUE(DivElement()->matches(AtomicString(":fullscreen")));
    EXPECT_FALSE(DivElement()->matches(
        AtomicString(":-internal-video-persistent-ancestor"), exception_state));
    EXPECT_TRUE(exception_state.HadException());
  }
  {
    DummyExceptionStateForTesting exception_state;
    EXPECT_FALSE(VideoElement()->matches(
        AtomicString(":-internal-video-persistent"), exception_state));
    EXPECT_TRUE(exception_state.HadException());
  }
  {
    DummyExceptionStateForTesting exception_state;
    EXPECT_FALSE(VideoElement()->matches(
        AtomicString(":-internal-video-persistent-ancestor"), exception_state));
    EXPECT_TRUE(exception_state.HadException());
  }
}

TEST_F(HTMLVideoElementPersistentTest, removeContainerWhilePersisting) {
  EXPECT_EQ(FullscreenElement(), nullptr);

  EXPECT_CALL(GetMockChromeClient(), EnterFullscreen(_, _, _)).Times(1);
  EXPECT_CALL(GetMockChromeClient(), ExitFullscreen(_)).Times(1);

  LocalFrame::NotifyUserActivation(
      GetDocument().GetFrame(), mojom::UserActivationNotificationType::kTest);
  Fullscreen::RequestFullscreen(*DivElement());
  SimulateDidEnterFullscreen();
  EXPECT_EQ(FullscreenElement(), DivElement());

  SimulateBecamePersistentVideo(true);
  Persistent<HTMLDivElement> div = DivElement();
  Persistent<HTMLVideoElement> video = VideoElement();
  GetDocument().body()->RemoveChild(DivElement());

  EXPECT_FALSE(video->IsPersistent());
  EXPECT_FALSE(div->ContainsPersistentVideo());
  EXPECT_FALSE(video->ContainsPersistentVideo());
}

TEST_F(HTMLVideoElementPersistentTest, removeVideoWhilePersisting) {
  EXPECT_EQ(FullscreenElement(), nullptr);

  EXPECT_CALL(GetMockChromeClient(), EnterFullscreen(_, _, _)).Times(1);
  EXPECT_CALL(GetMockChromeClient(), ExitFullscreen(_)).Times(0);

  LocalFrame::NotifyUserActivation(
      GetDocument().GetFrame(), mojom::UserActivationNotificationType::kTest);
  Fullscreen::RequestFullscreen(*DivElement());
  SimulateDidEnterFullscreen();
  EXPECT_EQ(FullscreenElement(), DivElement());

  SimulateBecamePersistentVideo(true);
  Persistent<HTMLVideoElement> video = VideoElement();
  DivElement()->RemoveChild(VideoElement());

  EXPECT_FALSE(video->IsPersistent());
  EXPECT_FALSE(DivElement()->ContainsPersistentVideo());
  EXPECT_FALSE(video->ContainsPersistentVideo());
}

TEST_F(HTMLVideoElementPersistentTest, removeVideoWithLayerWhilePersisting) {
  EXPECT_EQ(FullscreenElement(), nullptr);

  // Inserting a <span> between the <div> and <video>.
  Persistent<Element> span =
      GetDocument().CreateRawElement(html_names::kSpanTag);
  DivElement()->AppendChild(span);
  span->AppendChild(VideoElement());

  EXPECT_CALL(GetMockChromeClient(), EnterFullscreen(_, _, _)).Times(1);
  EXPECT_CALL(GetMockChromeClient(), ExitFullscreen(_)).Times(0);

  LocalFrame::NotifyUserActivation(
      GetDocument().GetFrame(), mojom::UserActivationNotificationType::kTest);
  Fullscreen::RequestFullscreen(*DivElement());
  SimulateDidEnterFullscreen();
  EXPECT_EQ(FullscreenElement(), DivElement());

  SimulateBecamePersistentVideo(true);
  Persistent<HTMLVideoElement> video = VideoElement();
  span->RemoveChild(VideoElement());

  EXPECT_FALSE(video->IsPersistent());
  EXPECT_FALSE(DivElement()->ContainsPersistentVideo());
  EXPECT_FALSE(video->ContainsPersistentVideo());
  EXPECT_FALSE(span->ContainsPersistentVideo());
}

TEST_F(HTMLVideoElementPersistentTest, containsPersistentVideoScopedToFS) {
  EXPECT_EQ(FullscreenElement(), nullptr);

  EXPECT_CALL(GetMockChromeClient(), EnterFullscreen(_, _, _)).Times(1);
  EXPECT_CALL(GetMockChromeClient(), ExitFullscreen(_)).Times(0);

  LocalFrame::NotifyUserActivation(
      GetDocument().GetFrame(), mojom::UserActivationNotificationType::kTest);
  Fullscreen::RequestFullscreen(*DivElement());
  SimulateDidEnterFullscreen();
  EXPECT_EQ(FullscreenElement(), DivElement());

  SimulateBecamePersistentVideo(true);
  EXPECT_FALSE(GetDocument().body()->ContainsPersistentVideo());
}

}  // namespace blink
```