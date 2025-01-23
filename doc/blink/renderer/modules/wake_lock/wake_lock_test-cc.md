Response:
Let's break down the thought process for analyzing this C++ test file for the Blink Wake Lock API.

**1. Understanding the Goal:**

The core request is to analyze the functionality of the `wake_lock_test.cc` file, focusing on its relationship with JavaScript, HTML, and CSS, providing examples, reasoning, identifying potential errors, and describing the user journey to trigger the tested code.

**2. Initial Code Scan and Keyword Identification:**

My first step is to quickly scan the code for prominent keywords and patterns. I'm looking for:

* **`TEST` macros:** These immediately signal that this is a test file.
* **Class names:**  `WakeLock`, `MockWakeLockService`, `WakeLockTestingContext`, `ScriptPromise`, `DOMException`. These indicate the components being tested and the testing framework used.
* **Method names:** `DoRequest`, `WaitForRequest`, `WaitForCancelation`, `SetPermissionResponse`, `SetVisibilityState`. These reveal the actions being tested.
* **Namespaces:** `blink`. This confirms the code belongs to the Blink rendering engine.
* **Enums/Constants:** `V8WakeLockType::Enum::kScreen`, `V8WakeLockType::Enum::kSystem`, `mojom::blink::PermissionStatus::GRANTED`, `mojom::blink::PageVisibilityState::kHidden`. These indicate the different types of wake locks and states being tested.
* **Assertions:** `EXPECT_TRUE`, `EXPECT_FALSE`, `EXPECT_NE`, `EXPECT_EQ`, `ASSERT_NE`. These are the core of the test logic, verifying expected outcomes.

**3. Deconstructing Individual Tests:**

Next, I examine each `TEST` function individually:

* **`RequestWakeLockGranted`:**  The name suggests a successful wake lock request. I see `SetPermissionResponse(GRANTED)`, `DoRequest`, `WaitForRequest`, `WaitForPromiseFulfillment`, and checks for a non-null `WakeLockSentinel` and `is_acquired()`. This confirms the test verifies a successful request when permission is granted.

* **`RequestWakeLockDenied`:**  The name suggests a failed request. I see `SetPermissionResponse(DENIED)`, `DoRequest`, `WaitForPromiseRejection`, checks for `kRejected` promise state, `is_acquired()` being false, and importantly, verification of a `NotAllowedError` `DOMException`. This confirms the test verifies a denied request and the correct error.

* **`LossOfDocumentActivity`:** The comment refers to handling document loss. I see multiple wake lock requests (`kScreen` and `kSystem`), followed by `FrameDestroyed()`, and then `WaitForCancelation` for both lock types. The assertions confirm the locks are no longer acquired. This test confirms that closing the document releases wake locks.

* **`PageVisibilityHidden`:** The comment refers to handling loss of visibility. It involves acquiring both screen and system locks, then setting `VisibilityState` to `kHidden`. The screen lock is canceled, but the system lock remains. Changing back to `kVisible` and requesting a new screen lock shows it can be re-acquired. This demonstrates the behavior of wake locks when the page is hidden.

* **`PageVisibilityHiddenBeforeLockAcquisition`:** Similar to the previous test, but the visibility is set to `kHidden` *before* the screen lock can be fully acquired. This results in the screen lock promise being rejected with a `NotAllowedError`, while the system lock still succeeds. This tests the behavior when visibility changes during the request process.

**4. Identifying Relationships with Web Technologies (JavaScript, HTML, CSS):**

Now, I connect the C++ test code to the web technologies:

* **JavaScript API:** The `WakeLock` class and its `request()` method (though not explicitly shown in this test, it's the underlying mechanism being tested) are JavaScript APIs. The tests use `ScriptPromise` which directly maps to JavaScript Promises. The resolution of the promise with a `WakeLockSentinel` is also a JavaScript concept. The `navigator.wakeLock` access point is pure JavaScript.
* **HTML:** The concept of "document activity" and "page visibility" directly relates to the HTML document and its lifecycle events (like `visibilitychange`). Closing the browser tab or minimizing the window (making the page hidden) are user actions affecting the HTML document.
* **CSS:** While CSS doesn't directly interact with the Wake Lock API's *functionality*, it can influence user behavior. For example, a full-screen application using CSS might make the user more likely to want a screen wake lock. However, in terms of *this test file*, there's no direct interaction with CSS.

**5. Constructing Examples and Scenarios:**

Based on the tests, I create concrete examples of how these scenarios would play out in a web browser:

* **Granted:**  User navigates to a page, JavaScript requests a screen wake lock, permission is granted, screen stays on.
* **Denied:** User navigates to a page, JavaScript requests a system wake lock, permission is denied (or browser policy prevents it), the promise is rejected, the screen can dim/sleep.
* **Loss of Activity:** User has a page with a wake lock open, then closes the tab/window. The wake lock is released.
* **Visibility Hidden:** User has a page with wake locks open, then minimizes the window or switches to another tab. Screen wake locks are released, system wake locks may persist.

**6. Identifying Potential Errors:**

I analyze the tests to find common usage errors:

* **Requesting System Locks Without Permission:** The "Denied" test explicitly shows this.
* **Assuming Wake Locks Persist Indefinitely:** The "Loss of Activity" and "Visibility Hidden" tests highlight that wake locks are tied to the document/page lifecycle.
* **Not Handling Promise Rejections:**  The tests show that requests can fail, and developers need to handle these cases.

**7. Tracing the User Journey (Debugging Perspective):**

I think about how a developer might end up looking at this test file during debugging:

* **Bug Report:** A user reports that the screen doesn't stay on as expected.
* **Developer Investigation:** The developer looks at the Wake Lock implementation and then at the tests to understand how it's *supposed* to work.
* **Test as Documentation:** The tests serve as documentation of the expected behavior in different scenarios.
* **Debugging Specific Scenarios:** If a bug is related to page visibility or document closure, the corresponding tests (`PageVisibilityHidden`, `LossOfDocumentActivity`) become key resources.

**8. Structuring the Answer:**

Finally, I organize the information into a clear and structured answer, covering each aspect of the original request: functionality, relation to web technologies, examples, reasoning, potential errors, and the debugging perspective. I use clear headings and bullet points to improve readability.

This iterative process of code analysis, concept connection, example creation, and error identification helps in fully understanding the purpose and implications of the given C++ test file.
这个文件 `wake_lock_test.cc` 是 Chromium Blink 引擎中关于 Wake Lock API 的单元测试文件。它的主要功能是：

**功能:**

1. **测试 Wake Lock API 的核心功能:**  验证 `blink::WakeLock` 类的各种行为，包括请求（request）、释放（release，虽然在这个文件中没有直接测试 release，但相关的生命周期管理被测试了）Wake Lock。
2. **模拟不同场景下的 Wake Lock 行为:**  通过模拟权限授予/拒绝、页面可见性状态变化、文档生命周期结束等情况，测试 Wake Lock API 在这些场景下的正确性。
3. **验证与 JavaScript 的交互:**  虽然是 C++ 代码，但测试的是通过 JavaScript API 调用的功能，因此间接地验证了 JavaScript 到 C++ 的绑定是否正确。
4. **提供回归测试:**  确保对 Wake Lock API 的修改不会引入新的 bug 或破坏现有功能。

**与 JavaScript, HTML, CSS 的关系以及举例说明:**

虽然 `wake_lock_test.cc` 是 C++ 文件，但它直接测试了 JavaScript Wake Lock API 的实现。

* **JavaScript:**
    * **API Endpoint:**  JavaScript 代码通过 `navigator.wakeLock.request('screen')` 或 `navigator.wakeLock.request('system')` 来请求 Wake Lock。这个 C++ 测试文件模拟了这些请求，并验证了 Blink 引擎对这些请求的处理。
    * **Promises:** Wake Lock 的 `request()` 方法返回一个 Promise。测试文件中使用了 `ScriptPromise` 和 `ScriptPromiseResolver` 来模拟和验证 Promise 的 fulfill (成功获取 Wake Lock) 或 reject (获取 Wake Lock 失败) 状态。
    * **WakeLockSentinel:** 当 Wake Lock 请求成功时，Promise 会 resolve 一个 `WakeLockSentinel` 对象。测试代码会检查 Promise 的 resolution 是否为非空，表示成功获取了 Wake Lock。

    **举例:**  在 JavaScript 中，你可以这样请求一个屏幕 Wake Lock：
    ```javascript
    async function requestScreenWakeLock() {
      try {
        const wakeLock = await navigator.wakeLock.request('screen');
        console.log('Screen Wake Lock is active.');
        wakeLock.addEventListener('release', () => {
          console.log('Screen Wake Lock was released.');
        });
      } catch (err) {
        console.error(`Failed to acquire wake lock: ${err.name}, ${err.message}`);
      }
    }
    ```
    `wake_lock_test.cc` 中的 `RequestWakeLockGranted` 测试就是验证当权限允许时，上述 JavaScript 代码能够成功获取 Wake Lock 并 resolve Promise。

* **HTML:**
    * **页面生命周期:**  Wake Lock 的行为与 HTML 页面的生命周期息息相关。当页面被关闭或卸载时，持有的 Wake Lock 应该被释放。`LossOfDocumentActivity` 测试模拟了页面被销毁的情况，验证了 Wake Lock 的正确释放。
    * **页面可见性:**  当 HTML 页面变为不可见（例如，用户切换到其他标签页或最小化窗口）时，屏幕 Wake Lock 会被释放，但系统 Wake Lock 可能会继续保持。`PageVisibilityHidden` 和 `PageVisibilityHiddenBeforeLockAcquisition` 测试了这些场景。

    **举例:**  HTML 页面的 `visibilitychange` 事件可以用来监听页面可见性变化，这与 Wake Lock 的行为紧密相关。
    ```html
    <!DOCTYPE html>
    <html>
    <head>
      <title>Wake Lock Example</title>
    </head>
    <body>
      <script>
        document.addEventListener('visibilitychange', () => {
          if (document.visibilityState === 'hidden') {
            console.log('Page is now hidden.');
            // 屏幕 Wake Lock 会被自动释放
          } else {
            console.log('Page is now visible.');
            // 可以重新请求屏幕 Wake Lock
          }
        });
      </script>
    </body>
    </html>
    ```
    `PageVisibilityHidden` 测试验证了当页面变为 hidden 状态时，屏幕 Wake Lock 会被取消。

* **CSS:**
    * **间接影响:** CSS 本身不直接与 Wake Lock API 交互。但是，页面的布局和状态（例如，是否全屏）可能会影响用户是否需要或期望使用 Wake Lock。例如，一个全屏播放视频的应用可能更需要屏幕 Wake Lock。

**逻辑推理，假设输入与输出:**

**测试用例: `RequestWakeLockGranted`**

* **假设输入:**
    1. 模拟的权限服务 (`MockPermissionService`) 返回 `GRANTED` 状态 עבור `V8WakeLockType::Enum::kScreen`。
    2. JavaScript 代码调用 `navigator.wakeLock.request('screen')`。
* **逻辑推理:**
    1. `WakeLock::DoRequest` 被调用，尝试获取屏幕 Wake Lock。
    2. 权限检查通过，因为模拟服务返回 `GRANTED`。
    3. `MockWakeLockService` 记录了一个屏幕 Wake Lock 请求。
    4. 返回的 Promise 应该被 fulfill。
* **预期输出:**
    1. `screen_lock.is_acquired()` 为 `true`。
    2. `screen_promise` 被 resolve，且 resolution 是一个非空的 `WakeLockSentinel` 对象。

**测试用例: `RequestWakeLockDenied`**

* **假设输入:**
    1. 模拟的权限服务返回 `DENIED` 状态 עבור `V8WakeLockType::Enum::kSystem`。
    2. JavaScript 代码调用 `navigator.wakeLock.request('system')`。
* **逻辑推理:**
    1. `WakeLock::DoRequest` 被调用，尝试获取系统 Wake Lock。
    2. 权限检查失败，因为模拟服务返回 `DENIED`。
    3. 返回的 Promise 应该被 reject。
    4. 由于系统 Wake Lock 默认不被允许，Promise 应该被 reject，并返回一个 `NotAllowedError` 类型的 `DOMException`。
* **预期输出:**
    1. `system_lock.is_acquired()` 为 `false`。
    2. `system_promise` 的状态为 `v8::Promise::kRejected`。
    3. `ScriptPromiseUtils::GetPromiseResolutionAsDOMException` 返回一个非空的 `DOMException` 对象，且其 `name()` 为 "NotAllowedError"。

**用户或编程常见的使用错误:**

1. **未处理 Promise 的 rejection:**  如果 Wake Lock 请求失败（例如，权限被拒绝），`request()` 方法返回的 Promise 会被 reject。开发者需要正确处理这种情况，例如向用户显示错误信息。
    ```javascript
    navigator.wakeLock.request('screen')
      .then(wakeLock => {
        // Wake Lock 获取成功
      })
      .catch(err => {
        console.error('Failed to acquire wake lock:', err); // 应该处理错误
      });
    ```
2. **假设 Wake Lock 会一直有效:**  开发者需要意识到 Wake Lock 可能会因为多种原因被释放，例如页面不可见、文档被卸载、用户主动释放等。应该监听 `release` 事件来处理 Wake Lock 被释放的情况。
    ```javascript
    navigator.wakeLock.request('screen')
      .then(wakeLock => {
        wakeLock.addEventListener('release', () => {
          console.log('Wake Lock was released.');
          // 进行相应的处理，例如尝试重新获取
        });
      });
    ```
3. **在不需要时仍然持有 Wake Lock:**  Wake Lock 会消耗资源（例如，阻止屏幕关闭，可能导致电量消耗增加）。开发者应该在不再需要时主动释放 Wake Lock。虽然浏览器会自动释放，但显式释放是良好的实践。 (*注意：这个测试文件没有直接测试 release 操作，但其背后的逻辑是相关的*)
4. **错误地认为系统 Wake Lock 总是可用:** 系统 Wake Lock 的使用通常需要特定的权限，并且可能受到浏览器或操作系统的限制。开发者应该处理请求系统 Wake Lock 失败的情况。

**用户操作是如何一步步的到达这里，作为调试线索。**

假设用户在使用一个网页应用，该应用使用了 Wake Lock API 来防止屏幕在用户操作过程中熄灭。以下是可能导致开发者需要查看 `wake_lock_test.cc` 的用户操作和调试过程：

1. **用户操作:**
    * 用户打开了一个需要保持屏幕常亮的网页应用（例如，在线演示文稿、视频播放器）。
    * 网页应用中的 JavaScript 代码调用了 `navigator.wakeLock.request('screen')`。
    * **场景 1 (成功):**  浏览器成功获取了屏幕 Wake Lock，屏幕保持常亮。
    * **场景 2 (失败):** 浏览器未能获取屏幕 Wake Lock，屏幕在一段时间后熄灭。
    * **场景 3 (意外释放):**  屏幕 Wake Lock 在用户仍然需要的时候被意外释放了。

2. **开发者调试:**
    * **用户报告问题:** 用户反馈屏幕在应该保持常亮的时候熄灭了。
    * **开发者检查 JavaScript 代码:** 开发者会检查网页应用中调用 Wake Lock API 的代码，确认调用逻辑是否正确。
    * **浏览器开发者工具:** 开发者可能会使用浏览器开发者工具的网络面板查看是否有权限相关的错误，或者查看控制台是否有 Promise rejection 的日志。
    * **Blink 引擎代码调查:** 如果 JavaScript 代码逻辑看起来没有问题，开发者可能会怀疑是 Blink 引擎的 Wake Lock 实现存在问题。
    * **查看 `wake_lock_test.cc`:** 开发者可能会搜索 Blink 引擎的源代码，找到 `wake_lock_test.cc` 文件，来了解 Wake Lock API 的预期行为和各种边界情况。
    * **查看相关的测试用例:**
        * 如果用户报告无法获取 Wake Lock，开发者可能会关注 `RequestWakeLockDenied` 测试，以了解权限被拒绝时的行为。
        * 如果用户报告 Wake Lock 被意外释放，开发者可能会关注 `LossOfDocumentActivity` 和 `PageVisibilityHidden` 测试，以了解页面生命周期和可见性变化对 Wake Lock 的影响。
    * **运行本地测试:** 开发者可以在本地编译并运行 `wake_lock_test.cc` 中的测试用例，以验证 Wake Lock API 在不同条件下的行为是否符合预期。如果本地测试失败，则表明 Blink 引擎的实现可能存在 bug。
    * **添加调试日志:** 开发者可能会在 `blink/renderer/modules/wake_lock/wake_lock.cc` 等相关文件中添加调试日志，以便更深入地了解 Wake Lock 请求和释放的流程。

总而言之，`wake_lock_test.cc` 是一个关键的调试工具，它可以帮助开发者理解 Wake Lock API 的工作原理，验证其在各种场景下的正确性，并定位潜在的 bug。 用户遇到的问题，最终可能会引导开发者深入研究这些测试代码，以找出根本原因。

### 提示词
```
这是目录为blink/renderer/modules/wake_lock/wake_lock_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/wake_lock/wake_lock.h"

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/navigator.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/modules/wake_lock/wake_lock_test_utils.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "v8/include/v8.h"

namespace blink {

TEST(WakeLockTest, RequestWakeLockGranted) {
  test::TaskEnvironment task_environment;
  MockWakeLockService wake_lock_service;
  WakeLockTestingContext context(&wake_lock_service);

  context.GetPermissionService().SetPermissionResponse(
      V8WakeLockType::Enum::kScreen, mojom::blink::PermissionStatus::GRANTED);

  auto* screen_resolver =
      MakeGarbageCollected<ScriptPromiseResolver<WakeLockSentinel>>(
          context.GetScriptState());
  auto screen_promise = screen_resolver->Promise();

  auto* wake_lock = WakeLock::wakeLock(*context.DomWindow()->navigator());
  wake_lock->DoRequest(V8WakeLockType::Enum::kScreen, screen_resolver);

  MockWakeLock& screen_lock =
      wake_lock_service.get_wake_lock(V8WakeLockType::Enum::kScreen);
  MockPermissionService& permission_service = context.GetPermissionService();

  permission_service.WaitForPermissionRequest(V8WakeLockType::Enum::kScreen);
  screen_lock.WaitForRequest();
  context.WaitForPromiseFulfillment(screen_promise);

  EXPECT_NE(nullptr,
            ScriptPromiseUtils::GetPromiseResolutionAsWakeLockSentinel(
                context.GetScriptState()->GetIsolate(), screen_promise));
  EXPECT_TRUE(screen_lock.is_acquired());
}

TEST(WakeLockTest, RequestWakeLockDenied) {
  test::TaskEnvironment task_environment;
  MockWakeLockService wake_lock_service;
  WakeLockTestingContext context(&wake_lock_service);

  context.GetPermissionService().SetPermissionResponse(
      V8WakeLockType::Enum::kSystem, mojom::blink::PermissionStatus::DENIED);

  auto* system_resolver =
      MakeGarbageCollected<ScriptPromiseResolver<WakeLockSentinel>>(
          context.GetScriptState());
  auto system_promise = system_resolver->Promise();

  auto* wake_lock = WakeLock::wakeLock(*context.DomWindow()->navigator());
  wake_lock->DoRequest(V8WakeLockType::Enum::kSystem, system_resolver);

  MockWakeLock& system_lock =
      wake_lock_service.get_wake_lock(V8WakeLockType::Enum::kSystem);
  MockPermissionService& permission_service = context.GetPermissionService();

  permission_service.WaitForPermissionRequest(V8WakeLockType::Enum::kSystem);
  context.WaitForPromiseRejection(system_promise);

  EXPECT_EQ(v8::Promise::kRejected,
            ScriptPromiseUtils::GetPromiseState(system_promise));
  EXPECT_FALSE(system_lock.is_acquired());

  // System locks are not allowed by default, so the promise should have been
  // rejected with a NotAllowedError DOMException.
  DOMException* dom_exception =
      ScriptPromiseUtils::GetPromiseResolutionAsDOMException(
          context.GetScriptState()->GetIsolate(), system_promise);
  ASSERT_NE(dom_exception, nullptr);
  EXPECT_EQ("NotAllowedError", dom_exception->name());
}

// https://w3c.github.io/screen-wake-lock/#handling-document-loss-of-full-activity
TEST(WakeLockTest, LossOfDocumentActivity) {
  test::TaskEnvironment task_environment;
  MockWakeLockService wake_lock_service;
  WakeLockTestingContext context(&wake_lock_service);

  MockWakeLock& screen_lock =
      wake_lock_service.get_wake_lock(V8WakeLockType::Enum::kScreen);
  MockWakeLock& system_lock =
      wake_lock_service.get_wake_lock(V8WakeLockType::Enum::kSystem);
  context.GetPermissionService().SetPermissionResponse(
      V8WakeLockType::Enum::kScreen, mojom::blink::PermissionStatus::GRANTED);
  context.GetPermissionService().SetPermissionResponse(
      V8WakeLockType::Enum::kSystem, mojom::blink::PermissionStatus::GRANTED);

  // First, acquire a handful of locks of different types.
  auto* screen_resolver1 =
      MakeGarbageCollected<ScriptPromiseResolver<WakeLockSentinel>>(
          context.GetScriptState());
  auto* screen_resolver2 =
      MakeGarbageCollected<ScriptPromiseResolver<WakeLockSentinel>>(
          context.GetScriptState());
  auto* system_resolver1 =
      MakeGarbageCollected<ScriptPromiseResolver<WakeLockSentinel>>(
          context.GetScriptState());

  auto* wake_lock = WakeLock::wakeLock(*context.DomWindow()->navigator());
  wake_lock->DoRequest(V8WakeLockType::Enum::kScreen, screen_resolver1);
  wake_lock->DoRequest(V8WakeLockType::Enum::kScreen, screen_resolver2);
  screen_lock.WaitForRequest();
  wake_lock->DoRequest(V8WakeLockType::Enum::kSystem, system_resolver1);
  system_lock.WaitForRequest();

  // Now shut down our Document and make sure all [[ActiveLocks]] slots have
  // been cleared. We cannot check that the promises have been rejected because
  // ScriptPromiseResolverBase::Reject() will bail out if we no longer have a
  // valid execution context.
  context.Frame()->DomWindow()->FrameDestroyed();
  screen_lock.WaitForCancelation();
  system_lock.WaitForCancelation();

  EXPECT_FALSE(screen_lock.is_acquired());
  EXPECT_FALSE(system_lock.is_acquired());
}

// https://w3c.github.io/screen-wake-lock/#handling-document-loss-of-visibility
TEST(WakeLockTest, PageVisibilityHidden) {
  test::TaskEnvironment task_environment;
  MockWakeLockService wake_lock_service;
  WakeLockTestingContext context(&wake_lock_service);

  context.GetPermissionService().SetPermissionResponse(
      V8WakeLockType::Enum::kScreen, mojom::blink::PermissionStatus::GRANTED);
  context.GetPermissionService().SetPermissionResponse(
      V8WakeLockType::Enum::kSystem, mojom::blink::PermissionStatus::GRANTED);

  MockWakeLock& screen_lock =
      wake_lock_service.get_wake_lock(V8WakeLockType::Enum::kScreen);
  auto* screen_resolver =
      MakeGarbageCollected<ScriptPromiseResolver<WakeLockSentinel>>(
          context.GetScriptState());
  auto screen_promise = screen_resolver->Promise();

  MockWakeLock& system_lock =
      wake_lock_service.get_wake_lock(V8WakeLockType::Enum::kSystem);
  auto* system_resolver =
      MakeGarbageCollected<ScriptPromiseResolver<WakeLockSentinel>>(
          context.GetScriptState());
  auto system_promise = system_resolver->Promise();

  auto* wake_lock = WakeLock::wakeLock(*context.DomWindow()->navigator());
  wake_lock->DoRequest(V8WakeLockType::Enum::kScreen, screen_resolver);
  screen_lock.WaitForRequest();
  wake_lock->DoRequest(V8WakeLockType::Enum::kSystem, system_resolver);
  system_lock.WaitForRequest();

  context.WaitForPromiseFulfillment(screen_promise);
  context.WaitForPromiseFulfillment(system_promise);

  context.Frame()->GetPage()->SetVisibilityState(
      mojom::blink::PageVisibilityState::kHidden, false);

  screen_lock.WaitForCancelation();

  EXPECT_FALSE(screen_lock.is_acquired());
  EXPECT_TRUE(system_lock.is_acquired());

  context.Frame()->GetPage()->SetVisibilityState(
      mojom::blink::PageVisibilityState::kVisible, false);

  auto* other_resolver =
      MakeGarbageCollected<ScriptPromiseResolver<WakeLockSentinel>>(
          context.GetScriptState());
  auto other_promise = other_resolver->Promise();
  wake_lock->DoRequest(V8WakeLockType::Enum::kScreen, other_resolver);
  screen_lock.WaitForRequest();
  context.WaitForPromiseFulfillment(other_promise);
  EXPECT_TRUE(screen_lock.is_acquired());
}

// https://w3c.github.io/screen-wake-lock/#handling-document-loss-of-visibility
TEST(WakeLockTest, PageVisibilityHiddenBeforeLockAcquisition) {
  test::TaskEnvironment task_environment;

  MockWakeLockService wake_lock_service;
  WakeLockTestingContext context(&wake_lock_service);

  context.GetPermissionService().SetPermissionResponse(
      V8WakeLockType::Enum::kScreen, mojom::blink::PermissionStatus::GRANTED);
  context.GetPermissionService().SetPermissionResponse(
      V8WakeLockType::Enum::kSystem, mojom::blink::PermissionStatus::GRANTED);

  MockWakeLock& screen_lock =
      wake_lock_service.get_wake_lock(V8WakeLockType::Enum::kScreen);
  auto* screen_resolver =
      MakeGarbageCollected<ScriptPromiseResolver<WakeLockSentinel>>(
          context.GetScriptState());
  auto screen_promise = screen_resolver->Promise();

  MockWakeLock& system_lock =
      wake_lock_service.get_wake_lock(V8WakeLockType::Enum::kSystem);
  auto* system_resolver =
      MakeGarbageCollected<ScriptPromiseResolver<WakeLockSentinel>>(
          context.GetScriptState());
  auto system_promise = system_resolver->Promise();

  auto* wake_lock = WakeLock::wakeLock(*context.DomWindow()->navigator());
  wake_lock->DoRequest(V8WakeLockType::Enum::kScreen, screen_resolver);
  wake_lock->DoRequest(V8WakeLockType::Enum::kSystem, system_resolver);
  context.Frame()->GetPage()->SetVisibilityState(
      mojom::blink::PageVisibilityState::kHidden, false);

  context.WaitForPromiseRejection(screen_promise);
  system_lock.WaitForRequest();
  context.WaitForPromiseFulfillment(system_promise);

  EXPECT_EQ(v8::Promise::kRejected,
            ScriptPromiseUtils::GetPromiseState(screen_promise));
  DOMException* dom_exception =
      ScriptPromiseUtils::GetPromiseResolutionAsDOMException(
          context.GetScriptState()->GetIsolate(), screen_promise);
  ASSERT_NE(dom_exception, nullptr);
  EXPECT_EQ("NotAllowedError", dom_exception->name());

  EXPECT_FALSE(screen_lock.is_acquired());
  EXPECT_TRUE(system_lock.is_acquired());
}

}  // namespace blink
```