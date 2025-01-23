Response:
Let's break down the thought process for analyzing this C++ test file.

1. **Identify the Core Subject:** The file name `screen_orientation_controller_test.cc` and the inclusion of `screen_orientation_controller.h` immediately tell us this file tests the `ScreenOrientationController` class.

2. **Understand the Testing Framework:** The presence of `#include "testing/gtest/include/gtest/gtest.h"` indicates this file uses Google Test. This means we should look for `TEST_F` macros defining individual test cases.

3. **Analyze the Test Fixture:**  The class `ScreenOrientationControllerTest` inherits from `PageTestBase`. This suggests the tests interact with a simulated web page environment provided by `PageTestBase`. The `SetUp` and `TearDown` methods are standard GTest setup and cleanup. Note the binding of `device::mojom::blink::ScreenOrientation` – this signals interaction with a Mojo interface for screen orientation, likely communicating with a browser process component.

4. **Examine Helper Classes:** The `MockLockOrientationCallback` is a crucial element. It implements `blink::WebLockOrientationCallback`. This tells us it's simulating the callback mechanism used when JavaScript code (or internal Blink code) attempts to lock the screen orientation. The `LockOrientationResultHolder` structure within it stores the success/failure and error information, making it easy to check the outcome of asynchronous lock operations.

5. **Deconstruct Individual Tests:** Go through each `TEST_F` case one by one:
    * **`CancelPending_Unlocking`:**  This tests what happens when `unlock()` is called after a `lock()`. It expects the lock to be canceled.
    * **`CancelPending_DoubleLock`:** This checks the scenario of calling `lock()` twice in a row. The first lock should be canceled.
    * **`LockRequest_Error`:** This iterates through various `LockResult` error codes and verifies that the callback reports the correct `WebLockOrientationError`.
    * **`LockRequest_Success`:** This verifies that a successful lock result is correctly reported by the callback.
    * **`RaceScenario`:** This simulates a race condition where a second lock request comes in before the first one completes. It checks that the first request is canceled and the second remains pending.
    * **`PageVisibilityCrash`:**  This test involves creating iframes and toggling page visibility. The key is the comment about preventing a crash when the iframe's `ScreenOrientationController` hasn't been explicitly accessed. This indicates a potential lazy initialization or race condition issue being tested.
    * **`OrientationChangePropagationToGrandchild`:** This test deals with how orientation changes are propagated through iframes. It checks if a change in the main frame's orientation is correctly reflected in a grandchild frame, even if the intermediate parent frame doesn't have an active `ScreenOrientationController`.

6. **Identify Relationships to Web Technologies:**
    * **JavaScript:** The core functionality being tested (`lockOrientation`, `unlock`) directly corresponds to the JavaScript Screen Orientation API. The `WebLockOrientationCallback` interface hints at how Blink communicates the results of these JS calls back to the rendering engine.
    * **HTML:** The `PageVisibilityCrash` and `OrientationChangePropagationToGrandchild` tests explicitly load HTML files (`single_iframe.html`, `visible_iframe.html`, `page_with_grandchild.html`). This shows that the screen orientation locking can be affected by the structure of the web page (e.g., iframe usage).
    * **CSS:** While not directly tested in the *logic* of this file, the concept of screen orientation is tightly coupled with CSS media queries (e.g., `@media (orientation: portrait)` or `@media (orientation: landscape)`). The tests ensure the underlying mechanism for controlling orientation is working, which in turn affects how CSS is applied.

7. **Infer Logical Reasoning:** For each test, identify the "input" (what actions are performed) and the expected "output" (the state of the `callback_results`). This demonstrates the test's logical flow. For instance, in `CancelPending_Unlocking`, the input is "lock then unlock," and the expected output is the callback reporting a cancellation error.

8. **Consider User and Programming Errors:**
    * **User:**  A common user error is attempting to lock screen orientation without being in fullscreen mode, which the `LockRequest_Error` test with `SCREEN_ORIENTATION_LOCK_RESULT_ERROR_FULLSCREEN_REQUIRED` addresses.
    * **Programming:**  Developers might mistakenly call `lock()` multiple times without realizing the first call will be canceled, as tested by `CancelPending_DoubleLock`. They might also fail to handle the `Canceled` error appropriately.

9. **Trace User Actions (Debugging Clues):**  Imagine a user encountering an issue with screen orientation locking on a webpage. The tests provide clues on how to reproduce and debug:
    * Is the page in an iframe? The `PageVisibilityCrash` and `OrientationChangePropagationToGrandchild` tests suggest issues can arise with iframe interactions.
    * Is the user rapidly trying to lock and unlock the orientation? The `CancelPending_Unlocking` test highlights potential problems with quick sequences of actions.
    * Is the error a "Not Available" or "Fullscreen Required" error? The `LockRequest_Error` test helps understand the different reasons for lock failure.

10. **Structure the Explanation:** Organize the information logically. Start with a general overview of the file's purpose. Then, explain the role of the test fixture and helper classes. Go through each test case, explaining its function and linking it to web technologies where applicable. Finally, discuss logical reasoning, user/programming errors, and debugging clues.
这个文件是 Chromium Blink 引擎中 `blink/renderer/modules/screen_orientation/screen_orientation_controller_test.cc` 的源代码文件，它是一个单元测试文件，专门用于测试 `ScreenOrientationController` 类的功能。

以下是该文件的详细功能说明：

**核心功能：测试 `ScreenOrientationController` 类的各种操作和场景。**

`ScreenOrientationController` 负责管理和协调屏幕方向的锁定和解锁操作，并将这些操作与底层平台进行交互。这个测试文件模拟了各种不同的调用顺序和情景，以确保 `ScreenOrientationController` 能够正确处理这些情况。

**与 JavaScript, HTML, CSS 功能的关系：**

`ScreenOrientationController` 是 Blink 引擎中实现 Web Screen Orientation API 的关键部分。这个 API 允许 JavaScript 代码控制设备的屏幕方向。

* **JavaScript:**  JavaScript 代码可以通过 `screen.orientation` 对象来调用 `lock()` 和 `unlock()` 方法来请求锁定或解锁屏幕方向。  `ScreenOrientationController` 负责处理这些来自 JavaScript 的请求。
    * **示例 JavaScript 代码:**
      ```javascript
      screen.orientation.lock("portrait-primary")
        .then(() => console.log("Screen locked to portrait"))
        .catch((error) => console.error("Error locking screen:", error));

      screen.orientation.unlock();
      ```
      这个测试文件中的测试用例，例如 `CancelPending_Unlocking` 和 `CancelPending_DoubleLock`，模拟了 JavaScript 调用 `lock()` 和 `unlock()` 的场景，并验证 `ScreenOrientationController` 的行为是否符合预期。

* **HTML:**  HTML 页面可以通过 JavaScript 调用 Screen Orientation API。该测试文件中的一些测试用例（如 `PageVisibilityCrash` 和 `OrientationChangePropagationToGrandchild`) 加载了包含 iframe 的 HTML 文件，这表明测试也考虑了在更复杂的页面结构中屏幕方向控制的行为。

* **CSS:** CSS 可以使用媒体查询 `@media` 来根据屏幕方向应用不同的样式。虽然这个测试文件本身不直接测试 CSS 的行为，但它测试了底层控制屏幕方向的机制。当 JavaScript 成功锁定屏幕方向时，相应的 CSS 媒体查询可能会被激活或失效。

**逻辑推理的假设输入与输出：**

以下是一些测试用例的假设输入和输出示例：

* **测试用例：`CancelPending_Unlocking`**
    * **假设输入:**
        1. JavaScript (或测试代码模拟) 调用 `screen.orientation.lock("portrait-primary")`。
        2. 随后，JavaScript (或测试代码模拟) 调用 `screen.orientation.unlock()`。
    * **预期输出:**
        1. 第一次 `lock()` 操作的回调应该被调用，并指示操作被取消 (错误类型为 `kWebLockOrientationErrorCanceled`)。

* **测试用例：`CancelPending_DoubleLock`**
    * **假设输入:**
        1. JavaScript (或测试代码模拟) 调用 `screen.orientation.lock("portrait-primary")`。
        2. 随后，JavaScript (或测试代码模拟) 再次调用 `screen.orientation.lock("portrait-primary")`。
    * **预期输出:**
        1. 第一次 `lock()` 操作的回调应该被调用，并指示操作被取消 (错误类型为 `kWebLockOrientationErrorCanceled`)。

* **测试用例：`LockRequest_Success`**
    * **假设输入:**
        1. JavaScript (或测试代码模拟) 调用 `screen.orientation.lock("portrait-primary")`。
        2. 模拟底层平台返回锁定成功的消息。
    * **预期输出:**
        1. `lock()` 操作的回调应该被调用，并指示操作成功。

**涉及用户或编程常见的使用错误：**

* **用户操作错误：**
    * **尝试在不允许的情况下锁定屏幕方向:** 用户可能在一个没有获得必要权限的上下文中尝试锁定屏幕方向（例如，不在全屏模式下）。测试用例 `LockRequest_Error` 涵盖了 `kWebLockOrientationErrorFullscreenRequired` 这种情况。用户操作可能是在非全屏模式的网页上点击了触发屏幕锁定的按钮。

* **编程错误：**
    * **未处理锁定失败的情况:** 开发者可能没有正确处理 `lock()` 方法返回的 Promise 的 `catch` 块，导致在锁定失败时没有给出合适的反馈。
    * **多次调用 `lock()` 而不 `unlock()`:** 开发者可能在没有解锁之前再次调用 `lock()`，这会导致之前的锁定请求被取消。测试用例 `CancelPending_DoubleLock` 模拟了这种情况。
    * **假设锁定总是成功:** 开发者可能没有考虑到屏幕方向锁定可能会因为各种原因失败（例如，设备不支持，用户拒绝权限）。

**用户操作是如何一步步的到达这里，作为调试线索：**

假设用户在使用某个网页时遇到了屏幕方向锁定的问题，例如，他们尝试锁定到横屏，但页面仍然是竖屏的。以下是可能的调试线索，以及如何一步步到达 `ScreenOrientationControllerTest`：

1. **用户操作:** 用户访问了一个包含屏幕方向锁定功能的网页。
2. **JavaScript 执行:** 网页上的 JavaScript 代码调用了 `screen.orientation.lock()` 方法，试图锁定屏幕方向。
3. **Blink 引擎处理:** 浏览器的渲染引擎 (Blink) 接收到这个 JavaScript 调用。
4. **`ScreenOrientationController` 介入:** Blink 引擎中的 `ScreenOrientationController` 类负责处理这个锁定请求。
5. **与底层平台交互:** `ScreenOrientationController` 通过 Mojo 接口与浏览器进程或操作系统进行通信，请求锁定屏幕方向。
6. **可能出现问题:** 在这个过程中，可能会因为各种原因导致锁定失败，例如：
    * 浏览器或操作系统不支持屏幕方向锁定。
    * 当前页面不在全屏模式下。
    * 用户拒绝了锁定屏幕方向的权限。
    * 代码逻辑错误导致重复锁定或解锁。
7. **调试线索:**
    * **控制台错误:** 开发者可能会在浏览器的开发者工具的控制台中看到与屏幕方向锁定相关的错误信息。
    * **断点调试:** 开发者可以在他们的 JavaScript 代码中设置断点，查看 `screen.orientation.lock()` 的返回值和错误信息。
    * **Blink 源码调试:** 如果问题非常底层，Blink 工程师可能会需要查看 `ScreenOrientationController` 的代码，甚至运行 `ScreenOrientationControllerTest` 中的相关测试用例来重现和诊断问题。例如，如果怀疑是多次锁定的问题，他们可能会运行 `CancelPending_DoubleLock` 测试。
    * **测试用例的价值:** `ScreenOrientationControllerTest` 中的测试用例覆盖了各种可能的场景和错误情况，可以帮助开发者理解 `ScreenOrientationController` 的行为，并找到潜在的 bug。通过查看这些测试用例，开发者可以了解在什么情况下锁定会失败，以及 `ScreenOrientationController` 如何处理这些失败情况。

总而言之，`blink/renderer/modules/screen_orientation/screen_orientation_controller_test.cc` 是一个至关重要的测试文件，它确保了 Blink 引擎中处理屏幕方向锁定的核心逻辑的正确性和健壮性，并为开发者提供了调试相关问题的线索。

### 提示词
```
这是目录为blink/renderer/modules/screen_orientation/screen_orientation_controller_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/screen_orientation/screen_orientation_controller.h"

#include <memory>
#include <tuple>

#include "base/memory/raw_ptr.h"
#include "mojo/public/cpp/bindings/associated_remote.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/web/web_local_frame.h"
#include "third_party/blink/renderer/core/frame/frame_test_helpers.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/web_frame_widget_impl.h"
#include "third_party/blink/renderer/core/frame/web_local_frame_impl.h"
#include "third_party/blink/renderer/core/testing/page_test_base.h"
#include "third_party/blink/renderer/modules/screen_orientation/screen_orientation.h"
#include "third_party/blink/renderer/modules/screen_orientation/web_lock_orientation_callback.h"
#include "third_party/blink/renderer/platform/mojo/heap_mojo_associated_remote.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/url_test_helpers.h"
#include "third_party/blink/renderer/platform/wtf/hash_map.h"

namespace blink {

using LockOrientationCallback =
    device::mojom::blink::ScreenOrientation::LockOrientationCallback;
using LockResult = device::mojom::blink::ScreenOrientationLockResult;

// MockLockOrientationCallback is an implementation of
// WebLockOrientationCallback and takes a LockOrientationResultHolder* as a
// parameter when being constructed. The |results_| pointer is owned by the
// caller and not by the callback object. The intent being that as soon as the
// callback is resolved, it will be killed so we use the
// LockOrientationResultHolder to know in which state the callback object is at
// any time.
class MockLockOrientationCallback : public blink::WebLockOrientationCallback {
 public:
  struct LockOrientationResultHolder {
    LockOrientationResultHolder() : succeeded_(false), failed_(false) {}

    bool succeeded_;
    bool failed_;
    blink::WebLockOrientationError error_;
  };

  explicit MockLockOrientationCallback(LockOrientationResultHolder* results)
      : results_(results) {}

  void OnSuccess() override { results_->succeeded_ = true; }

  void OnError(blink::WebLockOrientationError error) override {
    results_->failed_ = true;
    results_->error_ = error;
  }

 private:
  raw_ptr<LockOrientationResultHolder> results_;
};

class ScreenOrientationControllerTest : public PageTestBase {
 protected:
  void SetUp() override {
    PageTestBase::SetUp(gfx::Size());
    HeapMojoAssociatedRemote<device::mojom::blink::ScreenOrientation>
        screen_orientation(GetFrame().DomWindow());
    std::ignore = screen_orientation.BindNewEndpointAndPassDedicatedReceiver();
    Controller()->SetScreenOrientationAssociatedRemoteForTests(
        std::move(screen_orientation));
  }

  void TearDown() override {
    HeapMojoAssociatedRemote<device::mojom::blink::ScreenOrientation>
        screen_orientation(GetFrame().DomWindow());
    Controller()->SetScreenOrientationAssociatedRemoteForTests(
        std::move(screen_orientation));
  }

  ScreenOrientationController* Controller() {
    return ScreenOrientationController::From(*GetFrame().DomWindow());
  }

  void LockOrientation(
      device::mojom::ScreenOrientationLockType orientation,
      std::unique_ptr<blink::WebLockOrientationCallback> callback) {
    Controller()->lock(orientation, std::move(callback));
  }

  void UnlockOrientation() { Controller()->unlock(); }

  int GetRequestId() { return Controller()->GetRequestIdForTests(); }

  void RunLockResultCallback(int request_id, LockResult result) {
    Controller()->OnLockOrientationResult(request_id, result);
  }
};

// Test that calling lockOrientation() followed by unlockOrientation() cancel
// the lockOrientation().
TEST_F(ScreenOrientationControllerTest, CancelPending_Unlocking) {
  MockLockOrientationCallback::LockOrientationResultHolder callback_results;

  LockOrientation(
      device::mojom::ScreenOrientationLockType::PORTRAIT_PRIMARY,
      std::make_unique<MockLockOrientationCallback>(&callback_results));
  UnlockOrientation();

  EXPECT_FALSE(callback_results.succeeded_);
  EXPECT_TRUE(callback_results.failed_);
  EXPECT_EQ(blink::kWebLockOrientationErrorCanceled, callback_results.error_);
}

// Test that calling lockOrientation() twice cancel the first lockOrientation().
TEST_F(ScreenOrientationControllerTest, CancelPending_DoubleLock) {
  MockLockOrientationCallback::LockOrientationResultHolder callback_results;
  // We create the object to prevent leaks but never actually use it.
  MockLockOrientationCallback::LockOrientationResultHolder callback_results2;

  LockOrientation(
      device::mojom::ScreenOrientationLockType::PORTRAIT_PRIMARY,
      std::make_unique<MockLockOrientationCallback>(&callback_results));

  LockOrientation(
      device::mojom::ScreenOrientationLockType::PORTRAIT_PRIMARY,
      std::make_unique<MockLockOrientationCallback>(&callback_results2));

  EXPECT_FALSE(callback_results.succeeded_);
  EXPECT_TRUE(callback_results.failed_);
  EXPECT_EQ(blink::kWebLockOrientationErrorCanceled, callback_results.error_);
}

// Test that when a LockError message is received, the request is set as failed
// with the correct values.
TEST_F(ScreenOrientationControllerTest, LockRequest_Error) {
  HashMap<LockResult, blink::WebLockOrientationError> errors;
  errors.insert(LockResult::SCREEN_ORIENTATION_LOCK_RESULT_ERROR_NOT_AVAILABLE,
                blink::kWebLockOrientationErrorNotAvailable);
  errors.insert(
      LockResult::SCREEN_ORIENTATION_LOCK_RESULT_ERROR_FULLSCREEN_REQUIRED,
      blink::kWebLockOrientationErrorFullscreenRequired);
  errors.insert(LockResult::SCREEN_ORIENTATION_LOCK_RESULT_ERROR_CANCELED,
                blink::kWebLockOrientationErrorCanceled);

  for (auto it = errors.begin(); it != errors.end(); ++it) {
    MockLockOrientationCallback::LockOrientationResultHolder callback_results;
    LockOrientation(
        device::mojom::ScreenOrientationLockType::PORTRAIT_PRIMARY,
        std::make_unique<MockLockOrientationCallback>(&callback_results));
    RunLockResultCallback(GetRequestId(), it->key);
    EXPECT_FALSE(callback_results.succeeded_);
    EXPECT_TRUE(callback_results.failed_);
    EXPECT_EQ(it->value, callback_results.error_);
  }
}

// Test that when a LockSuccess message is received, the request is set as
// succeeded.
TEST_F(ScreenOrientationControllerTest, LockRequest_Success) {
  MockLockOrientationCallback::LockOrientationResultHolder callback_results;
  LockOrientation(
      device::mojom::ScreenOrientationLockType::PORTRAIT_PRIMARY,
      std::make_unique<MockLockOrientationCallback>(&callback_results));

  RunLockResultCallback(GetRequestId(),
                        LockResult::SCREEN_ORIENTATION_LOCK_RESULT_SUCCESS);

  EXPECT_TRUE(callback_results.succeeded_);
  EXPECT_FALSE(callback_results.failed_);
}

// Test the following scenario:
// - request1 is received by the delegate;
// - request2 is received by the delegate;
// - request1 is rejected;
// - request1 success response is received.
// Expected: request1 is still rejected, request2 has not been set as succeeded.
TEST_F(ScreenOrientationControllerTest, RaceScenario) {
  MockLockOrientationCallback::LockOrientationResultHolder callback_results1;
  MockLockOrientationCallback::LockOrientationResultHolder callback_results2;

  LockOrientation(
      device::mojom::ScreenOrientationLockType::PORTRAIT_PRIMARY,
      std::make_unique<MockLockOrientationCallback>(&callback_results1));
  int request_id1 = GetRequestId();

  LockOrientation(
      device::mojom::ScreenOrientationLockType::LANDSCAPE_PRIMARY,
      std::make_unique<MockLockOrientationCallback>(&callback_results2));

  // callback_results1 must be rejected, tested in CancelPending_DoubleLock.

  RunLockResultCallback(request_id1,
                        LockResult::SCREEN_ORIENTATION_LOCK_RESULT_SUCCESS);

  // First request is still rejected.
  EXPECT_FALSE(callback_results1.succeeded_);
  EXPECT_TRUE(callback_results1.failed_);
  EXPECT_EQ(blink::kWebLockOrientationErrorCanceled, callback_results1.error_);

  // Second request is still pending.
  EXPECT_FALSE(callback_results2.succeeded_);
  EXPECT_FALSE(callback_results2.failed_);
}

class ScreenInfoWebFrameWidget : public frame_test_helpers::TestWebFrameWidget {
 public:
  template <typename... Args>
  explicit ScreenInfoWebFrameWidget(Args&&... args)
      : frame_test_helpers::TestWebFrameWidget(std::forward<Args>(args)...) {
    screen_info_.orientation_angle = 1234;
  }
  ~ScreenInfoWebFrameWidget() override = default;

  // frame_test_helpers::TestWebFrameWidget overrides.
  display::ScreenInfo GetInitialScreenInfo() override { return screen_info_; }

 private:
  display::ScreenInfo screen_info_;
};

TEST_F(ScreenOrientationControllerTest, PageVisibilityCrash) {
  std::string base_url("http://internal.test/");
  std::string test_url("single_iframe.html");
  url_test_helpers::RegisterMockedURLLoadFromBase(
      WebString::FromUTF8(base_url), test::CoreTestDataPath(),
      WebString::FromUTF8(test_url));
  url_test_helpers::RegisterMockedURLLoadFromBase(
      WebString::FromUTF8(base_url), test::CoreTestDataPath(),
      WebString::FromUTF8("visible_iframe.html"));

  frame_test_helpers::CreateTestWebFrameWidgetCallback create_widget_callback =
      WTF::BindRepeating(
          &frame_test_helpers::WebViewHelper::CreateTestWebFrameWidget<
              ScreenInfoWebFrameWidget>);
  frame_test_helpers::WebViewHelper web_view_helper(create_widget_callback);
  web_view_helper.InitializeAndLoad(base_url + test_url, nullptr, nullptr);

  Page* page = web_view_helper.GetWebView()->GetPage();
  LocalFrame* frame = To<LocalFrame>(page->MainFrame());

  // Fully set up on an orientation and a controller in the main frame, but not
  // the iframe. Prepare an orientation change, then toggle visibility. When
  // set to visible, propagating the orientation change events shouldn't crash
  // just because the ScreenOrientationController in the iframe was never
  // referenced before this.
  ScreenOrientation::Create(frame->DomWindow());
  page->SetVisibilityState(mojom::blink::PageVisibilityState::kHidden, false);
  web_view_helper.LocalMainFrame()->SendOrientationChangeEvent();
  page->SetVisibilityState(mojom::blink::PageVisibilityState::kVisible, false);

  // When the iframe's orientation is initialized, it should be properly synced.
  auto* child_orientation = ScreenOrientation::Create(
      To<LocalFrame>(frame->Tree().FirstChild())->DomWindow());
  EXPECT_EQ(child_orientation->angle(), 1234);

  url_test_helpers::UnregisterAllURLsAndClearMemoryCache();
  web_view_helper.Reset();
}

TEST_F(ScreenOrientationControllerTest,
       OrientationChangePropagationToGrandchild) {
  std::string base_url("http://internal.test/");
  std::string test_url("page_with_grandchild.html");
  url_test_helpers::RegisterMockedURLLoadFromBase(
      WebString::FromUTF8(base_url), test::CoreTestDataPath(),
      WebString::FromUTF8(test_url));
  url_test_helpers::RegisterMockedURLLoadFromBase(
      WebString::FromUTF8(base_url), test::CoreTestDataPath(),
      WebString::FromUTF8("single_iframe.html"));
  url_test_helpers::RegisterMockedURLLoadFromBase(
      WebString::FromUTF8(base_url), test::CoreTestDataPath(),
      WebString::FromUTF8("visible_iframe.html"));

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url + test_url, nullptr, nullptr);

  Page* page = web_view_helper.GetWebView()->GetPage();
  LocalFrame* frame = To<LocalFrame>(page->MainFrame());

  // Fully set up on an orientation and a controller in the main frame and
  // the grandchild, but not the child.
  ScreenOrientation::Create(frame->DomWindow());
  Frame* grandchild = frame->Tree().FirstChild()->Tree().FirstChild();
  auto* grandchild_orientation =
      ScreenOrientation::Create(To<LocalFrame>(grandchild)->DomWindow());

  // Update the screen info and ensure it propagated to the grandchild.
  display::ScreenInfos screen_infos((display::ScreenInfo()));
  screen_infos.mutable_current().orientation_angle = 90;
  auto* web_frame_widget_base =
      static_cast<WebFrameWidgetImpl*>(frame->GetWidgetForLocalRoot());
  web_frame_widget_base->UpdateScreenInfo(screen_infos);
  EXPECT_EQ(grandchild_orientation->angle(), 90);

  url_test_helpers::UnregisterAllURLsAndClearMemoryCache();
  web_view_helper.Reset();
}

}  // namespace blink
```