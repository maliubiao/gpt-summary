Response:
Let's break down the thought process for analyzing the provided C++ test file.

**1. Understanding the Goal:**

The core request is to analyze a Chromium Blink engine test file (`interactive_detector_test.cc`) and explain its purpose, its relationship to web technologies (JavaScript, HTML, CSS), its internal logic, potential user/developer errors it tests, and how a user might trigger the tested code.

**2. Initial Scan and High-Level Understanding:**

* **File Name:** `interactive_detector_test.cc` strongly suggests this file tests something called `InteractiveDetector`. The `_test.cc` convention confirms it's a unit test file.
* **Includes:** The included headers provide vital clues:
    * `"third_party/blink/renderer/core/loader/interactive_detector.h"`:  Confirms the tested class is `InteractiveDetector` and its location within the Blink rendering engine (loader component).
    * `"testing/gtest/include/gtest/gtest.h"`: Indicates it uses the Google Test framework.
    * Headers related to `Document`, `Event`, `MessageEvent`: Suggests `InteractiveDetector` interacts with the DOM and events.
    * Headers related to `ukm`:  Implies the detector records user metrics (User Keyed Metrics).
    * Headers related to `platform`, `scheduler`:  Suggests interaction with the underlying platform and task scheduling.
    * `"third_party/blink/renderer/core/testing/dummy_page_holder.h"`, `"third_party/blink/renderer/core/testing/page_test_base.h"`: Indicate it's using Blink's testing infrastructure for creating a minimal page environment.
* **Namespace:** `namespace blink { ... }` confirms this is Blink-specific code.
* **Test Class:** `InteractiveDetectorTest` inherits from `testing::Test` and `ScopedMockOverlayScrollbars`, further reinforcing its role as a test fixture.

**3. Identifying Key Components and Functionality:**

* **`NetworkActivityCheckerForTest`:**  A mock/stub implementation of `InteractiveDetector::NetworkActivityChecker`. This immediately tells us that `InteractiveDetector` depends on some way to track network activity. The `SetActiveConnections` and `GetActiveConnections` methods confirm its role.
* **`InteractiveDetectorTest` Class Setup:** The constructor initializes the test environment:
    * Advances the clock.
    * Creates a `DummyPageHolder` to simulate a basic page.
    * Creates an `InteractiveDetector` instance, injecting the mock network checker.
    * *Crucially*, it uses `Supplement<Document>::ProvideTo` to associate the test detector with the dummy document. This is important for the tests to interact with the correct detector.
* **Helper Methods in `InteractiveDetectorTest`:** These are the core of the test logic:
    * `SimulateNavigationStart`, `SimulateDOMContentLoadedEnd`, `SimulateFCPDetected`, `SimulateLongTask`, `SimulateResourceLoadBegin`, `SimulateResourceLoadEnd`, `SimulateInteractiveInvalidatingInput`: These methods mimic the timing and occurrence of key browser lifecycle events and activities. They directly interact with the `InteractiveDetector`'s methods.
    * `RunTillTimestamp`:  A utility to advance the test clock.
    * `GetInteractiveTime`, `SetTimeToInteractive`, `GetTotalBlockingTime`:  Methods to access and manipulate the state of the `InteractiveDetector`.
    * `DummyTaskWithDuration`: Simulates a main thread task.
    * `HandleForInputDelay`: Tests the calculation of First Input Delay.
* **Test Cases (using `TEST_F`)**: Each `TEST_F` function focuses on a specific scenario, often named to reflect the order of simulated events (e.g., `FCP_DCL_FcpDetect`). This methodical naming helps understand the test's focus.

**4. Connecting to Web Technologies:**

* **JavaScript:** The concept of "interactive" and events strongly links to JavaScript. JavaScript handles user interactions and can cause long-running tasks. The tests involving `SimulateLongTask` and `InvalidatingUserInput` directly relate to this.
* **HTML:** The `DOMContentLoaded` event is a core HTML lifecycle event, indicating the HTML structure is parsed. The tests simulating `DOMContentLoadedEnd` highlight this connection.
* **CSS:** While not directly tested in the provided *code*, CSS rendering can contribute to the timing of First Contentful Paint (FCP). The tests around FCP implicitly acknowledge this. Further, large CSS files can block rendering and potentially contribute to long tasks.
* **Network:**  The `NetworkActivityChecker` is explicitly designed to track network requests, a fundamental part of loading web pages (HTML, CSS, JavaScript, images, etc.).

**5. Analyzing Logic and Scenarios:**

* **TTI Calculation:** The core functionality revolves around determining when a page becomes "interactive" (Time To Interactive). The tests explore various factors influencing this: FCP, DOMContentLoaded, long tasks, and network activity.
* **Quiet Window:** The concept of a "quiet window" (5 seconds in these tests) after certain events is crucial. The tests verify that interactivity is reached after such a period of no long tasks and no network activity.
* **Long Tasks:** The tests meticulously simulate long-running main thread tasks and how they delay interactivity.
* **Network Activity:** The tests demonstrate how ongoing network requests can prevent the page from being considered interactive, even if the main thread is idle.
* **First Input Delay (FID):** Specific tests focus on calculating FID by simulating pointer down/up and mouse down/up events, taking into account event handling delays.

**6. Identifying Potential Errors and User Actions:**

* **Developer Errors:**
    * Writing JavaScript that causes long-running, blocking tasks.
    * Not optimizing resource loading, leading to prolonged network activity.
* **User Actions:**
    * The tests simulating user input (`SimulateInteractiveInvalidatingInput`) and the FID tests directly relate to user actions like clicks and taps. The sequence of user actions leading to the code is: User navigates to a page -> Browser starts loading resources -> Browser parses HTML and executes JavaScript -> User interacts with the page (e.g., clicks an element).

**7. Structuring the Explanation:**

Finally, organize the findings into a clear and structured explanation, using headings, bullet points, and examples to make it easy to understand. Start with a high-level summary and then delve into the details of each aspect.

**Self-Correction/Refinement During Analysis:**

* **Initial thought:** "This just tests some timers."  **Correction:**  It's more nuanced. It tests the logic of combining different signals (events, network, main thread activity) to determine a complex metric like "interactive."
* **Realization:** The `NetworkActivityCheckerForTest` is a *mock*. This is a common testing pattern to isolate the `InteractiveDetector`'s logic from the real network implementation.
* **Focus on the "Why":**  Don't just describe what the code does; explain *why* it's doing it. For example, why is there a 5-second quiet window? What user experience problems are these tests trying to prevent?

By following this structured approach, combining code analysis with knowledge of web technologies and testing principles, it's possible to generate a comprehensive and insightful explanation of the given test file.
这个文件 `interactive_detector_test.cc` 是 Chromium Blink 引擎中用于测试 `InteractiveDetector` 类的单元测试文件。 `InteractiveDetector` 的主要功能是**检测网页何时变得可交互 (Interactive)**，也就是 Time To Interactive (TTI)。

以下是它的具体功能和相关说明：

**1. 测试 `InteractiveDetector` 的核心功能：检测网页何时变得可交互**

* **功能说明:**  `InteractiveDetector` 负责监控网页加载过程中的关键事件和状态，例如：
    * **First Contentful Paint (FCP):**  浏览器首次渲染任何文本、图像、非空白 canvas 或 SVG 的时间点。
    * **DOMContentLoaded (DCL):**  初始 HTML 文档被完全加载和解析完成之后，不必等待样式表、图像和子框架的完成加载。
    * **Long Tasks:**  在主线程上运行超过 50 毫秒的任务。
    * **Network Activity:**  正在进行的网络请求的数量。
* **测试目的:**  `interactive_detector_test.cc` 通过模拟各种事件发生的顺序和时间点，来验证 `InteractiveDetector` 是否能正确计算出网页的 TTI。

**与 JavaScript, HTML, CSS 的关系：**

`InteractiveDetector` 的功能与这三者都有密切关系，因为它监控的事件和状态都与它们相关：

* **HTML:** `DOMContentLoaded` 事件直接与 HTML 文档的加载和解析完成相关。`InteractiveDetector` 监听此事件以作为判断交互性的一个因素。
    * **举例:** 测试用例 `TEST_F(InteractiveDetectorTest, FCP_DCL_FcpDetect)` 模拟了 FCP 和 DCL 事件的发生，验证在特定情况下 TTI 是否正确计算。
* **CSS:** 虽然 CSS 加载完成本身不是 `InteractiveDetector` 直接监控的事件，但 CSS 的加载会影响渲染，从而影响 FCP 的时间。此外，大型或阻塞的 CSS 文件可能会导致主线程忙碌，形成 Long Tasks，进而延迟 TTI。
    * **举例:** 虽然测试代码中没有直接模拟 CSS 加载，但 FCP 的发生时间会受到 CSS 的影响。如果 CSS 加载很慢，FCP 就会延后。
* **JavaScript:** JavaScript 的执行会占用主线程，导致 Long Tasks。`InteractiveDetector` 会监控 Long Tasks，并将其作为影响 TTI 的重要因素。用户与网页的交互（例如点击、输入）通常会触发 JavaScript 代码的执行。
    * **举例:** 测试用例 `TEST_F(InteractiveDetectorTest, LongTaskBeforeFCPDoesNotAffectTTI)` 和其他包含 `SimulateLongTask` 的用例，都在测试 Long Tasks 对 TTI 的影响。`TEST_F(InteractiveDetectorTest, InvalidatingUserInput)` 测试了用户输入事件对 TTI 的影响。

**逻辑推理和假设输入与输出：**

大部分测试用例都在进行逻辑推理，基于不同的事件发生顺序和时间点，预测 `InteractiveDetector` 计算出的 TTI。

**假设输入与输出示例：**

* **测试用例:** `TEST_F(InteractiveDetectorTest, FCP_DCL_FcpDetect)`
    * **假设输入:**
        * `SimulateNavigationStart(t0)`: 模拟导航开始。
        * `SimulateDOMContentLoadedEnd(t0 + base::Seconds(3))`: 模拟 DCL 事件发生在 t0 + 3 秒。
        * `SimulateFCPDetected(/* fcp_time */ t0 + base::Seconds(5), /* detection_time */ t0 + base::Seconds(7))`: 模拟 FCP 发生在 t0 + 5 秒，并在 t0 + 7 秒被检测到。
        * 网络空闲。
    * **逻辑推理:** 在 FCP 发生后，有 5 秒的安静窗口（没有 Long Task，网络空闲），因此 TTI 应该发生在 FCP 时间点。
    * **预期输出:** `EXPECT_EQ(GetInteractiveTime(), t0 + base::Seconds(5))`，即 TTI 被计算为 FCP 的时间点。

* **测试用例:** `TEST_F(InteractiveDetectorTest, DCL_FCP_LT_FcpDetect)`
    * **假设输入:**
        * `SimulateNavigationStart(t0)`
        * `SimulateDOMContentLoadedEnd(t0 + base::Seconds(3))`
        * `SimulateLongTask(t0 + base::Seconds(7), t0 + base::Seconds(7.1))`：模拟一个 Long Task 从 t0 + 7 秒开始，持续 0.1 秒。
        * `SimulateFCPDetected(/* fcp_time */ t0 + base::Seconds(3), /* detection_time */ t0 + base::Seconds(5))`
        * 网络空闲。
    * **逻辑推理:**  虽然 FCP 发生在 DCL 之后，但在 FCP 之后出现了一个 Long Task。TTI 需要等待 FCP 之后 5 秒的安静窗口，但由于 Long Task 的存在，这个窗口被打破，TTI 将发生在 Long Task 结束之后 5 秒。
    * **预期输出:** `EXPECT_EQ(GetInteractiveTime(), t0 + base::Seconds(7.1))`，即 TTI 被计算为 Long Task 结束的时间点。

**涉及用户或者编程常见的使用错误：**

这个测试文件主要关注 `InteractiveDetector` 自身的逻辑是否正确，而不是直接测试用户或编程错误。但是，我们可以从测试场景中推断出一些可能导致网页交互性不佳的常见问题：

* **过长的 JavaScript 执行时间 (Long Tasks):** 多个测试用例都模拟了 Long Tasks 对 TTI 的影响，这表明开发者编写效率低下的 JavaScript 代码，导致主线程长时间阻塞，是影响用户体验的关键因素。
* **过多的网络请求:**  `TEST_F(InteractiveDetectorTest, NetworkBusyBlocksTTIEvenWhenMainThreadQuiet)` 等测试用例展示了即使主线程空闲，持续的网络活动也会阻止页面进入可交互状态。这提示开发者应该优化资源加载策略，减少不必要的网络请求。
* **用户输入响应延迟:** `TEST_F(InteractiveDetectorTest, FirstInputDelayForClickOnMobile)` 和相关测试用例模拟了用户输入事件的处理延迟，这与 JavaScript 代码的执行效率和主线程的繁忙程度有关。

**用户操作是如何一步步的到达这里，作为调试线索：**

虽然 `interactive_detector_test.cc` 是一个单元测试文件，用户不会直接 "到达" 这里，但我们可以推断出用户操作如何触发 `InteractiveDetector` 及其相关功能：

1. **用户在浏览器中输入网址或点击链接，开始导航到一个新的网页。**
2. **浏览器开始请求 HTML 文档。**
3. **浏览器接收并解析 HTML 文档，触发 `DOMContentLoaded` 事件。** `InteractiveDetector` 会监听并记录这个时间点。
4. **浏览器开始加载 HTML 中引用的资源，例如 CSS 样式表、JavaScript 文件、图片等。** `InteractiveDetector` 会监控网络活动，记录资源加载的开始和结束时间。
5. **浏览器开始渲染页面内容。** 当浏览器首次渲染出内容时，触发 **First Contentful Paint (FCP)** 事件。 `InteractiveDetector` 会监听并记录 FCP 的发生时间和被检测到的时间。
6. **JavaScript 代码开始执行。** 如果 JavaScript 代码执行时间过长（超过 50 毫秒），就会形成 **Long Tasks**。 `InteractiveDetector` 会监控并记录 Long Tasks 的开始和结束时间。
7. **用户与网页进行交互，例如点击按钮、输入文本等。** 这些交互会触发事件，并可能执行 JavaScript 代码。`InteractiveDetector` 可以记录用户输入事件的时间，用于计算 First Input Delay (FID)。
8. **`InteractiveDetector` 根据收集到的事件和状态信息，按照其内部逻辑判断网页是否达到了可交互状态 (TTI)。**  判断的依据包括 FCP、DCL、Long Tasks 和网络活动等。

**作为调试线索:**

如果开发者发现某个网页的 TTI 指标不佳，`InteractiveDetector` 的内部逻辑和这些测试用例可以作为调试线索：

* **检查 Long Tasks:**  使用浏览器的开发者工具（例如 Chrome DevTools 的 Performance 面板）分析主线程的活动，找出导致 Long Tasks 的 JavaScript 代码，并进行优化。
* **分析网络请求:**  检查网络面板，找出耗时过长的网络请求，优化资源加载顺序，使用缓存等策略减少网络请求。
* **关注 FCP 和 DCL:**  分析影响 FCP 和 DCL 的因素，例如优化关键渲染路径，减少阻塞渲染的资源。
* **利用 UKM (User Keyed Metrics):**  `interactive_detector_test.cc` 中包含了对 UKM 的使用，表明 `InteractiveDetector` 会将 TTI 等指标上报到 Chromium 的数据收集系统。开发者可以通过分析 UKM 数据，了解实际用户的 TTI 体验，并定位性能瓶颈。

总而言之，`interactive_detector_test.cc` 是一个至关重要的测试文件，它确保了 Chromium 浏览器能够准确地衡量网页的交互性，从而为开发者优化网页性能提供依据。通过模拟各种场景，它验证了 `InteractiveDetector` 在不同情况下都能正确工作，这直接关系到用户浏览网页的流畅度和体验。

### 提示词
```
这是目录为blink/renderer/core/loader/interactive_detector_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#include "third_party/blink/renderer/core/loader/interactive_detector.h"

#include "base/functional/callback_helpers.h"
#include "base/task/single_thread_task_runner.h"
#include "base/test/scoped_feature_list.h"
#include "base/time/time.h"
#include "components/ukm/test_ukm_recorder.h"
#include "services/metrics/public/cpp/ukm_builders.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/events/event.h"
#include "third_party/blink/renderer/core/events/message_event.h"
#include "third_party/blink/renderer/core/testing/dummy_page_holder.h"
#include "third_party/blink/renderer/core/testing/page_test_base.h"
#include "third_party/blink/renderer/core/testing/scoped_mock_overlay_scrollbars.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/scheduler/main_thread/main_thread_scheduler_impl.h"
#include "third_party/blink/renderer/platform/scheduler/public/post_cross_thread_task.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/testing/testing_platform_support_with_mock_scheduler.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_functional.h"

namespace blink {

using PageLoad = ukm::builders::PageLoad;

class NetworkActivityCheckerForTest
    : public InteractiveDetector::NetworkActivityChecker {
 public:
  NetworkActivityCheckerForTest(Document* document)
      : InteractiveDetector::NetworkActivityChecker(document) {}

  virtual void SetActiveConnections(int active_connections) {
    active_connections_ = active_connections;
  }
  int GetActiveConnections() override;

 private:
  int active_connections_ = 0;
};

int NetworkActivityCheckerForTest::GetActiveConnections() {
  return active_connections_;
}

class InteractiveDetectorTest : public testing::Test,
                                public ScopedMockOverlayScrollbars {
 public:
  InteractiveDetectorTest() {
    platform_->AdvanceClockSeconds(1);

    auto test_task_runner = platform_->test_task_runner();
    auto* tick_clock = test_task_runner->GetMockTickClock();
    dummy_page_holder_ = std::make_unique<DummyPageHolder>(
        gfx::Size(), nullptr, nullptr, base::NullCallback(), tick_clock);

    Document* document = &dummy_page_holder_->GetDocument();
    detector_ = MakeGarbageCollected<InteractiveDetector>(
        *document, std::make_unique<NetworkActivityCheckerForTest>(document));
    detector_->SetTaskRunnerForTesting(test_task_runner);
    detector_->SetTickClockForTesting(tick_clock);

    // By this time, the DummyPageHolder has created an InteractiveDetector, and
    // sent DOMContentLoadedEnd. We overwrite it with our new
    // InteractiveDetector, which won't have received any timestamps.
    Supplement<Document>::ProvideTo(*document, detector_.Get());

    // Ensure the document is using the injected InteractiveDetector.
    DCHECK_EQ(detector_, InteractiveDetector::From(*document));
  }

  // Public because it's executed on a task queue.
  void DummyTaskWithDuration(double duration_seconds) {
    platform_->AdvanceClockSeconds(duration_seconds);
    dummy_task_end_time_ = Now();
  }

 protected:
  InteractiveDetector* GetDetector() { return detector_; }

  base::TimeTicks GetDummyTaskEndTime() { return dummy_task_end_time_; }

  NetworkActivityCheckerForTest* GetNetworkActivityChecker() {
    // We know in this test context that network_activity_checker_ is an
    // instance of NetworkActivityCheckerForTest, so this static_cast is safe.
    return static_cast<NetworkActivityCheckerForTest*>(
        detector_->network_activity_checker_.get());
  }

  void SimulateNavigationStart(base::TimeTicks nav_start_time) {
    RunTillTimestamp(nav_start_time);
    detector_->SetNavigationStartTime(nav_start_time);
  }

  void SimulateLongTask(base::TimeTicks start, base::TimeTicks end) {
    CHECK(end - start >= base::Seconds(0.05));
    RunTillTimestamp(end);
    detector_->OnLongTaskDetected(start, end);
  }

  void SimulateDOMContentLoadedEnd(base::TimeTicks dcl_time) {
    RunTillTimestamp(dcl_time);
    detector_->OnDomContentLoadedEnd(dcl_time);
  }

  void SimulateFCPDetected(base::TimeTicks fcp_time,
                           base::TimeTicks detection_time) {
    RunTillTimestamp(detection_time);
    detector_->OnFirstContentfulPaint(fcp_time);
  }

  void SimulateInteractiveInvalidatingInput(base::TimeTicks timestamp) {
    RunTillTimestamp(timestamp);
    detector_->OnInvalidatingInputEvent(timestamp);
  }

  void RunTillTimestamp(base::TimeTicks target_time) {
    base::TimeTicks current_time = Now();
    platform_->RunForPeriod(
        std::max(base::TimeDelta(), target_time - current_time));
  }

  int GetActiveConnections() {
    return GetNetworkActivityChecker()->GetActiveConnections();
  }

  void SetActiveConnections(int active_connections) {
    GetNetworkActivityChecker()->SetActiveConnections(active_connections);
  }

  void SimulateResourceLoadBegin(base::TimeTicks load_begin_time) {
    RunTillTimestamp(load_begin_time);
    detector_->OnResourceLoadBegin(load_begin_time);
    // ActiveConnections is incremented after detector runs OnResourceLoadBegin;
    SetActiveConnections(GetActiveConnections() + 1);
  }

  void SimulateResourceLoadEnd(base::TimeTicks load_finish_time) {
    RunTillTimestamp(load_finish_time);
    int active_connections = GetActiveConnections();
    SetActiveConnections(active_connections - 1);
    detector_->OnResourceLoadEnd(load_finish_time);
  }

  base::TimeTicks Now() { return platform_->test_task_runner()->NowTicks(); }

  base::TimeTicks GetInteractiveTime() { return detector_->interactive_time_; }

  void SetTimeToInteractive(base::TimeTicks interactive_time) {
    detector_->interactive_time_ = interactive_time;
  }

  base::TimeDelta GetTotalBlockingTime() {
    return detector_->ComputeTotalBlockingTime();
  }

  scoped_refptr<base::SingleThreadTaskRunner> GetTaskRunner() {
    return dummy_page_holder_->GetDocument().GetTaskRunner(
        TaskType::kUserInteraction);
  }

  test::TaskEnvironment task_environment_;
  ScopedTestingPlatformSupport<TestingPlatformSupportWithMockScheduler>
      platform_;

 private:
  Persistent<InteractiveDetector> detector_;
  std::unique_ptr<DummyPageHolder> dummy_page_holder_;
  base::TimeTicks dummy_task_end_time_;
};

// Note: The tests currently assume kTimeToInteractiveWindowSeconds is 5
// seconds. The window size is unlikely to change, and this makes the test
// scenarios significantly easier to write.

// Note: Some of the tests are named W_X_Y_Z, where W, X, Y, Z can any of the
// following events:
// FCP: First Contentful Paint
// DCL: DomContentLoadedEnd
// FcpDetect: Detection of FCP. FCP is a presentation timestamp.
// LT: Long Task
// The name shows the ordering of these events in the test.

TEST_F(InteractiveDetectorTest, FCP_DCL_FcpDetect) {
  base::TimeTicks t0 = Now();
  SimulateNavigationStart(t0);
  // Network is forever quiet for this test.
  SetActiveConnections(1);
  SimulateDOMContentLoadedEnd(t0 + base::Seconds(3));
  SimulateFCPDetected(
      /* fcp_time */ t0 + base::Seconds(5),
      /* detection_time */ t0 + base::Seconds(7));
  // Run until 5 seconds after FCP.
  RunTillTimestamp((t0 + base::Seconds(5)) + base::Seconds(5.0 + 0.1));
  // Reached TTI at FCP.
  EXPECT_EQ(GetInteractiveTime(), t0 + base::Seconds(5));
}

TEST_F(InteractiveDetectorTest, DCL_FCP_FcpDetect) {
  base::TimeTicks t0 = Now();
  SimulateNavigationStart(t0);
  // Network is forever quiet for this test.
  SetActiveConnections(1);
  SimulateDOMContentLoadedEnd(t0 + base::Seconds(5));
  SimulateFCPDetected(
      /* fcp_time */ t0 + base::Seconds(3),
      /* detection_time */ t0 + base::Seconds(7));
  // Run until 5 seconds after FCP.
  RunTillTimestamp((t0 + base::Seconds(3)) + base::Seconds(5.0 + 0.1));
  // Reached TTI at DCL.
  EXPECT_EQ(GetInteractiveTime(), t0 + base::Seconds(5));
}

TEST_F(InteractiveDetectorTest, InstantDetectionAtFcpDetectIfPossible) {
  base::TimeTicks t0 = Now();
  SimulateNavigationStart(t0);
  // Network is forever quiet for this test.
  SetActiveConnections(1);
  SimulateDOMContentLoadedEnd(t0 + base::Seconds(5));
  SimulateFCPDetected(
      /* fcp_time */ t0 + base::Seconds(3),
      /* detection_time */ t0 + base::Seconds(10));
  // Although we just detected FCP, the FCP timestamp is more than
  // kTimeToInteractiveWindowSeconds earlier. We should instantaneously
  // detect that we reached TTI at DCL.
  EXPECT_EQ(GetInteractiveTime(), t0 + base::Seconds(5));
}

TEST_F(InteractiveDetectorTest, FcpDetectFiresAfterLateLongTask) {
  base::TimeTicks t0 = Now();
  SimulateNavigationStart(t0);
  // Network is forever quiet for this test.
  SetActiveConnections(1);
  SimulateDOMContentLoadedEnd(t0 + base::Seconds(3));
  SimulateLongTask(t0 + base::Seconds(9), t0 + base::Seconds(9.1));
  SimulateFCPDetected(
      /* fcp_time */ t0 + base::Seconds(3),
      /* detection_time */ t0 + base::Seconds(10));
  // There is a 5 second quiet window after fcp_time - the long task is 6s
  // seconds after fcp_time. We should instantly detect we reached TTI at FCP.
  EXPECT_EQ(GetInteractiveTime(), t0 + base::Seconds(3));
}

TEST_F(InteractiveDetectorTest, FCP_FcpDetect_DCL) {
  base::TimeTicks t0 = Now();
  SimulateNavigationStart(t0);
  // Network is forever quiet for this test.
  SetActiveConnections(1);
  SimulateFCPDetected(
      /* fcp_time */ t0 + base::Seconds(3),
      /* detection_time */ t0 + base::Seconds(5));
  SimulateDOMContentLoadedEnd(t0 + base::Seconds(9));
  // TTI reached at DCL.
  EXPECT_EQ(GetInteractiveTime(), t0 + base::Seconds(9));
}

TEST_F(InteractiveDetectorTest, LongTaskBeforeFCPDoesNotAffectTTI) {
  base::TimeTicks t0 = Now();
  SimulateNavigationStart(t0);
  // Network is forever quiet for this test.
  SetActiveConnections(1);
  SimulateDOMContentLoadedEnd(t0 + base::Seconds(3));
  SimulateLongTask(t0 + base::Seconds(5.1), t0 + base::Seconds(5.2));
  SimulateFCPDetected(
      /* fcp_time */ t0 + base::Seconds(8),
      /* detection_time */ t0 + base::Seconds(9));
  // Run till 5 seconds after FCP.
  RunTillTimestamp((t0 + base::Seconds(8)) + base::Seconds(5.0 + 0.1));
  // TTI reached at FCP.
  EXPECT_EQ(GetInteractiveTime(), t0 + base::Seconds(8));
}

TEST_F(InteractiveDetectorTest, DCLDoesNotResetTimer) {
  base::TimeTicks t0 = Now();
  SimulateNavigationStart(t0);
  // Network is forever quiet for this test.
  SetActiveConnections(1);
  SimulateFCPDetected(
      /* fcp_time */ t0 + base::Seconds(3),
      /* detection_time */ t0 + base::Seconds(4));
  SimulateLongTask(t0 + base::Seconds(5), t0 + base::Seconds(5.1));
  SimulateDOMContentLoadedEnd(t0 + base::Seconds(8));
  // Run till 5 seconds after long task end.
  RunTillTimestamp((t0 + base::Seconds(5.1)) + base::Seconds(5.0 + 0.1));
  // TTI Reached at DCL.
  EXPECT_EQ(GetInteractiveTime(), t0 + base::Seconds(8));
}

TEST_F(InteractiveDetectorTest, DCL_FCP_FcpDetect_LT) {
  base::TimeTicks t0 = Now();
  SimulateNavigationStart(t0);
  // Network is forever quiet for this test.
  SetActiveConnections(1);
  SimulateDOMContentLoadedEnd(t0 + base::Seconds(3));
  SimulateFCPDetected(
      /* fcp_time */ t0 + base::Seconds(4),
      /* detection_time */ t0 + base::Seconds(5));
  SimulateLongTask(t0 + base::Seconds(7), t0 + base::Seconds(7.1));
  // Run till 5 seconds after long task end.
  RunTillTimestamp((t0 + base::Seconds(7.1)) + base::Seconds(5.0 + 0.1));
  // TTI reached at long task end.
  EXPECT_EQ(GetInteractiveTime(), t0 + base::Seconds(7.1));
}

TEST_F(InteractiveDetectorTest, DCL_FCP_LT_FcpDetect) {
  base::TimeTicks t0 = Now();
  SimulateNavigationStart(t0);
  // Network is forever quiet for this test.
  SetActiveConnections(1);
  SimulateDOMContentLoadedEnd(t0 + base::Seconds(3));
  SimulateLongTask(t0 + base::Seconds(7), t0 + base::Seconds(7.1));
  SimulateFCPDetected(
      /* fcp_time */ t0 + base::Seconds(3),
      /* detection_time */ t0 + base::Seconds(5));
  // Run till 5 seconds after long task end.
  RunTillTimestamp((t0 + base::Seconds(7.1)) + base::Seconds(5.0 + 0.1));
  // TTI reached at long task end.
  EXPECT_EQ(GetInteractiveTime(), t0 + base::Seconds(7.1));
}

TEST_F(InteractiveDetectorTest, FCP_FcpDetect_LT_DCL) {
  base::TimeTicks t0 = Now();
  SimulateNavigationStart(t0);
  // Network is forever quiet for this test.
  SetActiveConnections(1);
  SimulateFCPDetected(
      /* fcp_time */ t0 + base::Seconds(3),
      /* detection_time */ t0 + base::Seconds(4));
  SimulateLongTask(t0 + base::Seconds(7), t0 + base::Seconds(7.1));
  SimulateDOMContentLoadedEnd(t0 + base::Seconds(8));
  // Run till 5 seconds after long task end.
  RunTillTimestamp((t0 + base::Seconds(7.1)) + base::Seconds(5.0 + 0.1));
  // TTI reached at DCL. Note that we do not need to wait for DCL + 5 seconds.
  EXPECT_EQ(GetInteractiveTime(), t0 + base::Seconds(8));
}

TEST_F(InteractiveDetectorTest, DclIsMoreThan5sAfterFCP) {
  base::TimeTicks t0 = Now();
  SimulateNavigationStart(t0);
  // Network is forever quiet for this test.
  SetActiveConnections(1);
  SimulateFCPDetected(
      /* fcp_time */ t0 + base::Seconds(3),
      /* detection_time */ t0 + base::Seconds(4));
  SimulateLongTask(t0 + base::Seconds(7),
                   t0 + base::Seconds(7.1));  // Long task 1.
  SimulateDOMContentLoadedEnd(t0 + base::Seconds(10));
  // Have not reached TTI yet.
  EXPECT_EQ(GetInteractiveTime(), base::TimeTicks());
  SimulateLongTask(t0 + base::Seconds(11),
                   t0 + base::Seconds(11.1));  // Long task 2.
  // Run till long task 2 end + 5 seconds.
  RunTillTimestamp((t0 + base::Seconds(11.1)) + base::Seconds(5.0 + 0.1));
  // TTI reached at long task 2 end.
  EXPECT_EQ(GetInteractiveTime(), (t0 + base::Seconds(11.1)));
}

TEST_F(InteractiveDetectorTest, NetworkBusyBlocksTTIEvenWhenMainThreadQuiet) {
  base::TimeTicks t0 = Now();
  SimulateNavigationStart(t0);
  SetActiveConnections(1);
  SimulateDOMContentLoadedEnd(t0 + base::Seconds(2));
  SimulateResourceLoadBegin(t0 + base::Seconds(3.4));  // Request 2 start.
  SimulateResourceLoadBegin(
      t0 + base::Seconds(3.5));  // Request 3 start. Network busy.
  SimulateFCPDetected(
      /* fcp_time */ t0 + base::Seconds(3),
      /* detection_time */ t0 + base::Seconds(4));
  SimulateLongTask(t0 + base::Seconds(7),
                   t0 + base::Seconds(7.1));          // Long task 1.
  SimulateResourceLoadEnd(t0 + base::Seconds(12.2));  // Network quiet.
  // Network busy kept page from reaching TTI..
  EXPECT_EQ(GetInteractiveTime(), base::TimeTicks());
  SimulateLongTask(t0 + base::Seconds(13),
                   t0 + base::Seconds(13.1));  // Long task 2.
  // Run till 5 seconds after long task 2 end.
  RunTillTimestamp((t0 + base::Seconds(13.1)) + base::Seconds(5.0 + 0.1));
  EXPECT_EQ(GetInteractiveTime(), (t0 + base::Seconds(13.1)));
}

// FCP is a presentation timestamp, which is computed by another process and
// thus received asynchronously by the renderer process. Therefore, there can be
// some delay between the time in which FCP occurs and the time in which FCP is
// detected by the renderer.
TEST_F(InteractiveDetectorTest, LongEnoughQuietWindowBetweenFCPAndFcpDetect) {
  base::TimeTicks t0 = Now();
  SimulateNavigationStart(t0);
  SetActiveConnections(1);
  SimulateDOMContentLoadedEnd(t0 + base::Seconds(2));
  SimulateLongTask(t0 + base::Seconds(2.1),
                   t0 + base::Seconds(2.2));  // Long task 1.
  SimulateLongTask(t0 + base::Seconds(8.2),
                   t0 + base::Seconds(8.3));           // Long task 2.
  SimulateResourceLoadBegin(t0 + base::Seconds(8.4));  // Request 2 start.
  SimulateResourceLoadBegin(
      t0 + base::Seconds(8.5));  // Request 3 start. Network busy.
  SimulateFCPDetected(
      /* fcp_time */ t0 + base::Seconds(3),
      /* detection_time */ t0 + base::Seconds(10));
  // Even though network is currently busy and we have long task finishing
  // recently, we should be able to detect that the page already achieved TTI at
  // FCP.
  EXPECT_EQ(GetInteractiveTime(), t0 + base::Seconds(3));
}

TEST_F(InteractiveDetectorTest, NetworkBusyEndIsNotTTI) {
  base::TimeTicks t0 = Now();
  SimulateNavigationStart(t0);
  SetActiveConnections(1);
  SimulateDOMContentLoadedEnd(t0 + base::Seconds(2));
  SimulateResourceLoadBegin(t0 + base::Seconds(3.4));  // Request 2 start.
  SimulateResourceLoadBegin(
      t0 + base::Seconds(3.5));  // Request 3 start. Network busy.
  SimulateFCPDetected(
      /* fcp_time */ t0 + base::Seconds(3),
      /* detection_time */ t0 + base::Seconds(4));
  SimulateLongTask(t0 + base::Seconds(7),
                   t0 + base::Seconds(7.1));  // Long task 1.
  SimulateLongTask(t0 + base::Seconds(13),
                   t0 + base::Seconds(13.1));       // Long task 2.
  SimulateResourceLoadEnd(t0 + base::Seconds(14));  // Network quiet.
  // Run till 5 seconds after network busy end.
  RunTillTimestamp((t0 + base::Seconds(14)) + base::Seconds(5.0 + 0.1));
  // TTI reached at long task 2 end, NOT at network busy end.
  EXPECT_EQ(GetInteractiveTime(), t0 + base::Seconds(13.1));
}

TEST_F(InteractiveDetectorTest, LateLongTaskWithLateFCPDetection) {
  base::TimeTicks t0 = Now();
  SimulateNavigationStart(t0);
  SetActiveConnections(1);
  SimulateDOMContentLoadedEnd(t0 + base::Seconds(2));
  SimulateResourceLoadBegin(t0 + base::Seconds(3.4));  // Request 2 start.
  SimulateResourceLoadBegin(
      t0 + base::Seconds(3.5));  // Request 3 start. Network busy.
  SimulateLongTask(t0 + base::Seconds(7),
                   t0 + base::Seconds(7.1));       // Long task 1.
  SimulateResourceLoadEnd(t0 + base::Seconds(8));  // Network quiet.
  SimulateLongTask(t0 + base::Seconds(14),
                   t0 + base::Seconds(14.1));  // Long task 2.
  SimulateFCPDetected(
      /* fcp_time */ t0 + base::Seconds(3),
      /* detection_time */ t0 + base::Seconds(20));
  // TTI reached at long task 1 end, NOT at long task 2 end.
  EXPECT_EQ(GetInteractiveTime(), t0 + base::Seconds(7.1));
}

TEST_F(InteractiveDetectorTest, IntermittentNetworkBusyBlocksTTI) {
  base::TimeTicks t0 = Now();
  SimulateNavigationStart(t0);
  SetActiveConnections(1);
  SimulateDOMContentLoadedEnd(t0 + base::Seconds(2));
  SimulateFCPDetected(
      /* fcp_time */ t0 + base::Seconds(3),
      /* detection_time */ t0 + base::Seconds(4));
  SimulateLongTask(t0 + base::Seconds(7),
                   t0 + base::Seconds(7.1));           // Long task 1.
  SimulateResourceLoadBegin(t0 + base::Seconds(7.9));  // Active connections: 2
  // Network busy start.
  SimulateResourceLoadBegin(t0 + base::Seconds(8));  // Active connections: 3.
  // Network busy end.
  SimulateResourceLoadEnd(t0 + base::Seconds(8.5));  // Active connections: 2.
  // Network busy start.
  SimulateResourceLoadBegin(t0 + base::Seconds(11));  // Active connections: 3.
  // Network busy end.
  SimulateResourceLoadEnd(t0 + base::Seconds(12));  // Active connections: 2.
  SimulateLongTask(t0 + base::Seconds(14),
                   t0 + base::Seconds(14.1));  // Long task 2.
  // Run till 5 seconds after long task 2 end.
  RunTillTimestamp((t0 + base::Seconds(14.1)) + base::Seconds(5.0 + 0.1));
  // TTI reached at long task 2 end.
  EXPECT_EQ(GetInteractiveTime(), t0 + base::Seconds(14.1));
}

TEST_F(InteractiveDetectorTest, InvalidatingUserInput) {
  base::TimeTicks t0 = Now();
  SimulateNavigationStart(t0);
  // Network is forever quiet for this test.
  SetActiveConnections(1);
  SimulateDOMContentLoadedEnd(t0 + base::Seconds(2));
  SimulateFCPDetected(
      /* fcp_time */ t0 + base::Seconds(3),
      /* detection_time */ t0 + base::Seconds(4));
  SimulateInteractiveInvalidatingInput(t0 + base::Seconds(5));
  SimulateLongTask(t0 + base::Seconds(7),
                   t0 + base::Seconds(7.1));  // Long task 1.
  // Run till 5 seconds after long task 2 end.
  RunTillTimestamp((t0 + base::Seconds(7.1)) + base::Seconds(5.0 + 0.1));
  // We still detect interactive time on the blink side even if there is an
  // invalidating user input. Page Load Metrics filters out this value in the
  // browser process for UMA reporting.
  EXPECT_EQ(GetInteractiveTime(), t0 + base::Seconds(7.1));
}

TEST_F(InteractiveDetectorTest, TaskLongerThan5sBlocksTTI) {
  base::TimeTicks t0 = Now();
  GetDetector()->SetNavigationStartTime(t0);

  SimulateDOMContentLoadedEnd(t0 + base::Seconds(2));
  SimulateFCPDetected(t0 + base::Seconds(3), t0 + base::Seconds(4));

  // Post a task with 6 seconds duration.
  GetTaskRunner()->PostTask(
      FROM_HERE, WTF::BindOnce(&InteractiveDetectorTest::DummyTaskWithDuration,
                               WTF::Unretained(this), 6.0));

  platform_->RunUntilIdle();

  // We should be able to detect TTI 5s after the end of long task.
  platform_->RunForPeriodSeconds(5.1);
  EXPECT_EQ(GetInteractiveTime(), GetDummyTaskEndTime());
}

TEST_F(InteractiveDetectorTest, LongTaskAfterTTIDoesNothing) {
  base::TimeTicks t0 = Now();
  GetDetector()->SetNavigationStartTime(t0);

  SimulateDOMContentLoadedEnd(t0 + base::Seconds(2));
  SimulateFCPDetected(t0 + base::Seconds(3), t0 + base::Seconds(4));

  // Long task 1.
  GetTaskRunner()->PostTask(
      FROM_HERE, WTF::BindOnce(&InteractiveDetectorTest::DummyTaskWithDuration,
                               WTF::Unretained(this), 0.1));

  platform_->RunUntilIdle();

  base::TimeTicks long_task_1_end_time = GetDummyTaskEndTime();
  // We should be able to detect TTI 5s after the end of long task.
  platform_->RunForPeriodSeconds(5.1);
  EXPECT_EQ(GetInteractiveTime(), long_task_1_end_time);

  // Long task 2.
  GetTaskRunner()->PostTask(
      FROM_HERE, WTF::BindOnce(&InteractiveDetectorTest::DummyTaskWithDuration,
                               WTF::Unretained(this), 0.1));

  platform_->RunUntilIdle();
  // Wait 5 seconds to see if TTI time changes.
  platform_->RunForPeriodSeconds(5.1);
  // TTI time should not change.
  EXPECT_EQ(GetInteractiveTime(), long_task_1_end_time);
}

// In tests for Total Blocking Time (TBT) we call SetTimeToInteractive() instead
// of allowing TimeToInteractive to occur because the computation is gated
// behind tracing being enabled, which means that they won't run by default. In
// addition, further complication stems from the fact that the vector of
// longtasks is cleared at the end of OnTimeToInteractiveDetected(). Therefore,
// the simplest solution is to manually set all of the relevant variables and
// check the correctness of the method ComputeTotalBlockingTime(). This can be
// revisited if we move TBT computations to occur outside of the trace event.
TEST_F(InteractiveDetectorTest, TotalBlockingTimeZero) {
  base::TimeTicks t0 = Now();
  SimulateNavigationStart(t0);
  // Set a high number of active connections, so that
  // OnTimeToInteractiveDetected() is not called by accident.
  SetActiveConnections(5);
  SimulateFCPDetected(
      /* fcp_time */ t0 + base::Milliseconds(100),
      /* detection_time */ t0 + base::Milliseconds(100));

  // Longtask of duration 51ms, but only 50ms occur after FCP.
  SimulateLongTask(t0 + base::Milliseconds(99), t0 + base::Milliseconds(150));
  // Longtask of duration 59ms, but only 49ms occur before TTI.
  SimulateLongTask(t0 + base::Milliseconds(201), t0 + base::Milliseconds(260));
  SetTimeToInteractive(t0 + base::Milliseconds(250));
  EXPECT_EQ(GetTotalBlockingTime(), base::TimeDelta());
}

TEST_F(InteractiveDetectorTest, TotalBlockingTimeNonZero) {
  base::TimeTicks t0 = Now();
  SimulateNavigationStart(t0);
  // Set a high number of active connections, so that
  // OnTimeToInteractiveDetected() is not called by accident.
  SetActiveConnections(5);
  SimulateFCPDetected(
      /* fcp_time */ t0 + base::Milliseconds(100),
      /* detection_time */ t0 + base::Milliseconds(100));

  // Longtask fully before FCP.
  SimulateLongTask(t0 + base::Milliseconds(30), t0 + base::Milliseconds(89));
  // Longtask of duration 70ms, 60 ms of which occur after FCP. +10ms to TBT.
  SimulateLongTask(t0 + base::Milliseconds(90), t0 + base::Milliseconds(160));
  // Longtask of duration 80ms between FCP and TTI. +30ms to TBT.
  SimulateLongTask(t0 + base::Milliseconds(200), t0 + base::Milliseconds(280));
  // Longtask of duration 90ms, 70ms of which occur before TTI. +20ms to TBT.
  SimulateLongTask(t0 + base::Milliseconds(300), t0 + base::Milliseconds(390));
  // Longtask fully after TTI.
  SimulateLongTask(t0 + base::Milliseconds(371), t0 + base::Milliseconds(472));
  SetTimeToInteractive(t0 + base::Milliseconds(370));
  EXPECT_EQ(GetTotalBlockingTime(), base::Milliseconds(60));
}

TEST_F(InteractiveDetectorTest, TotalBlockingSingleTask) {
  base::TimeTicks t0 = Now();
  SimulateNavigationStart(t0);
  // Set a high number of active connections, so that
  // OnTimeToInteractiveDetected() is not called by accident.
  SetActiveConnections(5);
  SimulateFCPDetected(
      /* fcp_time */ t0 + base::Milliseconds(100),
      /* detection_time */ t0 + base::Milliseconds(100));

  // Longtask of duration 1s, from navigation start.
  SimulateLongTask(t0, t0 + base::Seconds(1));
  SetTimeToInteractive(t0 + base::Milliseconds(500));
  // Truncated longtask is of length 400. So TBT is 400 - 50 = 350
  EXPECT_EQ(GetTotalBlockingTime(), base::Milliseconds(350));
}

TEST_F(InteractiveDetectorTest, FirstInputDelayForClickOnMobile) {
  auto* detector = GetDetector();
  base::TimeTicks t0 = Now();
  // Pointerdown
  Event* pointerdown = MakeGarbageCollected<Event>(
      event_type_names::kPointerdown, MessageEvent::Bubbles::kYes,
      MessageEvent::Cancelable::kYes, MessageEvent::ComposedMode::kComposed,
      t0);
  pointerdown->SetTrusted(true);
  detector->HandleForInputDelay(*pointerdown, t0, t0 + base::Milliseconds(17));
  EXPECT_FALSE(detector->GetFirstInputDelay().has_value());
  // Pointerup
  Event* pointerup = MakeGarbageCollected<Event>(
      event_type_names::kPointerup, MessageEvent::Bubbles::kYes,
      MessageEvent::Cancelable::kYes, MessageEvent::ComposedMode::kComposed,
      t0 + base::Milliseconds(20));
  pointerup->SetTrusted(true);
  detector->HandleForInputDelay(*pointerup, t0 + base::Milliseconds(20),
                                t0 + base::Milliseconds(50));
  EXPECT_TRUE(detector->GetFirstInputDelay().has_value());
  EXPECT_EQ(detector->GetFirstInputDelay().value(), base::Milliseconds(17));
}

TEST_F(InteractiveDetectorTest,
       FirstInputDelayForClickOnDesktopWithFixEnabled) {
  base::test::ScopedFeatureList feature_list;
  auto* detector = GetDetector();
  base::TimeTicks t0 = Now();
  // Pointerdown
  Event* pointerdown = MakeGarbageCollected<Event>(
      event_type_names::kPointerdown, MessageEvent::Bubbles::kYes,
      MessageEvent::Cancelable::kYes, MessageEvent::ComposedMode::kComposed,
      t0);
  pointerdown->SetTrusted(true);
  detector->HandleForInputDelay(*pointerdown, t0, t0 + base::Milliseconds(17));
  EXPECT_FALSE(detector->GetFirstInputDelay().has_value());
  // Mousedown
  Event* mousedown = MakeGarbageCollected<Event>(
      event_type_names::kMousedown, MessageEvent::Bubbles::kYes,
      MessageEvent::Cancelable::kYes, MessageEvent::ComposedMode::kComposed,
      t0);
  mousedown->SetTrusted(true);
  detector->HandleForInputDelay(*mousedown, t0, t0 + base::Milliseconds(13));
  EXPECT_FALSE(detector->GetFirstInputDelay().has_value());
  // Pointerup
  Event* pointerup = MakeGarbageCollected<Event>(
      event_type_names::kPointerup, MessageEvent::Bubbles::kYes,
      MessageEvent::Cancelable::kYes, MessageEvent::ComposedMode::kComposed,
      t0 + base::Milliseconds(20));
  pointerup->SetTrusted(true);
  detector->HandleForInputDelay(*pointerup, t0 + base::Milliseconds(20),
                                t0 + base::Milliseconds(50));
  EXPECT_TRUE(detector->GetFirstInputDelay().has_value());
  EXPECT_EQ(detector->GetFirstInputDelay().value(), base::Milliseconds(17));
}

}  // namespace blink
```