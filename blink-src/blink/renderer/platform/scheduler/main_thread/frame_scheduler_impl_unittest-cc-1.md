Response: The user wants a summary of the functionality of the provided C++ code snippet, which is part of a larger test file for the Blink rendering engine. The focus is on `FrameSchedulerImpl` and its interactions with features like background throttling and back/forward cache.

Here's a breakdown of the thought process to generate the summary:

1. **Identify the Core Subject:** The code primarily deals with testing the `FrameSchedulerImpl` class.

2. **Scan for Key Functionality Areas:** Look for recurring themes and keywords. In this snippet, prominent themes include:
    * **Task Scheduling & Prioritization:**  Keywords like `TaskType`, `WebSchedulingTaskQueue`, `priority`.
    * **Background Throttling:** Concepts like "throttled", "hidden", "intensive wake up throttling", `SetPageVisible`.
    * **Back/Forward Cache:**  Keywords like `BackForwardCacheOptOut`, `RegisterFeature`, `DidCommitProvisionalLoad`.
    * **Frame Visibility and User Interaction:**  `SetFrameVisible`, `SetVisibleAreaLarge`, `SetHadUserActivation`.
    * **Performance Metrics:** `OnFirstMeaningfulPaint`, `OnFirstContentfulPaintInMainFrame`.

3. **Group Related Tests:**  Notice patterns in the `TEST_F` and `TEST_P` macros. For example, several tests relate to `BackForwardCacheOptOut`, and several relate to different aspects of background throttling.

4. **Analyze Individual Tests:**  For each test, determine its purpose.
    * Tests with `EXPECT_EQ` or `EXPECT_THAT` are assertions about the state or behavior of `FrameSchedulerImpl`.
    * Look for setup actions (e.g., registering features, posting tasks) and expected outcomes.

5. **Connect to Web Concepts (if applicable):**  Consider how the tested functionality relates to web development concepts:
    * **JavaScript Timers:** Tests involving `TaskType::kJavascriptTimerDelayed*` directly relate to `setTimeout` and `setInterval`.
    * **Back/Forward Cache:**  This directly impacts user experience when navigating back and forth in browser history. Features opting out prevent the page from being stored in the cache.
    * **WebSockets and WebRTC:** These are examples of features that can opt out of the back/forward cache.
    * **Page Visibility API:** Tests using `SetPageVisible` relate to how browsers manage background tabs.
    * **User Activation:**  This is a browser mechanism to prevent disruptive background actions.

6. **Infer Logical Reasoning (if applicable):** Look for scenarios where the code sets up a condition and checks the resulting state. For instance, registering a feature that disables back/forward cache should result in that feature being tracked.

7. **Identify Potential User/Programming Errors (if applicable):** While this is primarily *testing* code, consider the implications of the tested features. For instance, incorrectly registering features that disable the back/forward cache could negatively impact performance.

8. **Synthesize the Summary:**  Combine the observations from the previous steps into a concise summary. Use clear and descriptive language. Group related functionalities together.

9. **Address Specific Instructions:** Ensure the summary addresses the user's specific requests:
    * Listing functionalities.
    * Relating to JavaScript, HTML, and CSS (though the direct connection here is more about the *underlying implementation* of web features).
    * Providing examples for web concepts.
    * Identifying assumptions and outputs.
    * Highlighting potential errors.
    * Noting it's part 2 of 3.

10. **Refine and Organize:** Review the summary for clarity, accuracy, and completeness. Organize it logically, perhaps by grouping related functionalities.

Applying this process to the provided code snippet leads to the detailed summary provided in the initial example response. The key is to systematically break down the code, understand the *intent* of each test, and then synthesize that information into a coherent overview.
Based on the provided C++ code snippet, here's a summary of the functionalities being tested in this part of `frame_scheduler_impl_unittest.cc`:

**Core Focus: Back/Forward Cache Opt-Out and Feature Registration**

This section primarily tests how the `FrameSchedulerImpl` manages features that can opt a page out of the back/forward cache. It verifies the registration, tracking, and clearing of these features under various conditions, including navigation and frame destruction.

**Specific Functionalities Tested:**

* **Registering Features for Back/Forward Cache Opt-Out:**
    *  Tests the basic registration of features using `RegisterFeature` and verifies that these active features are tracked using `GetActiveFeaturesTrackedForBackForwardCacheMetrics()`.
    * Demonstrates how multiple features can be registered and tracked simultaneously.
    * Shows that releasing the `FeatureHandle` (when a feature is no longer active) correctly removes the feature from the tracked list.

* **Sticky Features for Back/Forward Cache Opt-Out:**
    * Tests the registration of "sticky" features using `RegisterStickyFeature`. Sticky features remain active even after same-document navigations.
    * Verifies that both regular and sticky features are tracked.

* **Impact of Navigation on Back/Forward Cache Opt-Out:**
    * **Same-document navigations:** Tests that same-document navigations (where the URL hash changes but the document remains the same) do *not* clear the registered back/forward cache opt-out features.
    * **Regular navigations:** Tests that regular navigations (loading a new document) *do* clear all registered back/forward cache opt-out features.
    * Shows that resetting a `FeatureHandle` after a full navigation has no effect, as the features are already cleared.

* **Delayed Feature Upload:**
    * Tests that registering sticky features triggers an asynchronous upload of these features to the delegate (`FrameSchedulerDelegateForTesting`). This upload is intentionally delayed.
    * Verifies that the delegate's `UpdateBackForwardCacheDisablingFeatures` method is called with the correct information about the registered features.

* **Feature Upload Cancellation on Frame Destruction:**
    * Tests that if a frame is destroyed before the delayed feature upload occurs, the upload is cancelled, preventing unnecessary work.

**Relationship to Javascript, HTML, and CSS:**

While this code is C++ and tests the underlying rendering engine, the features being tested directly impact how web pages behave:

* **Back/Forward Cache:**  This feature directly affects the user experience when navigating back and forth in browser history using the browser's back and forward buttons. If a page opts out of the back/forward cache (e.g., due to using WebSockets or `Cache-Control: no-store`), the browser will have to fully reload the page instead of restoring it from the cache, potentially leading to a slower experience.
    * **Example (Javascript):** A Javascript application might use WebSockets for real-time communication. Registering the `kWebSocket` feature for back/forward cache opt-out ensures that when the user navigates away and back, the application's state is correctly re-established (as the cached state might be stale).
    * **Example (HTML Header):** An HTML page with the header `<meta http-equiv="Cache-Control" content="no-store">` will trigger the `kMainResourceHasCacheControlNoStore` feature, causing the page to opt out of the back/forward cache.

**Logical Reasoning (Assumption and Output):**

* **Assumption:** When a feature is registered for back/forward cache opt-out, the `FrameSchedulerImpl` needs to track it to inform the browser about the page's eligibility for the cache.
* **Input:** Calling `frame_scheduler_->RegisterFeature(SchedulingPolicy::Feature::kWebSocket, {SchedulingPolicy::DisableBackForwardCache()});`
* **Output:** `frame_scheduler_->GetActiveFeaturesTrackedForBackForwardCacheMetrics()` will contain `SchedulingPolicy::Feature::kWebSocket`.

**User or Programming Common Usage Errors:**

* **Incorrectly registering features:** A developer might accidentally register a feature for back/forward cache opt-out, leading to unnecessary reloads for users. For example, registering `kWebSocket` even when WebSockets are only used on a small part of the site could unnecessarily disable the cache for the entire page.
* **Not understanding the difference between regular and sticky features:** A developer might use `RegisterFeature` when they intend for a feature's opt-out to persist across same-document navigations, leading to unexpected behavior. Using `RegisterStickyFeature` in such cases would be the correct approach.
* **Not cleaning up feature registrations:** While the `FeatureHandle` helps with automatic cleanup when it goes out of scope, in complex scenarios, developers need to be mindful of when features are no longer needed to avoid unnecessary back/forward cache opt-outs.

**Summary of Functionality (Part 2):**

This part of the `FrameSchedulerImplTest` focuses on verifying the mechanisms within the `FrameSchedulerImpl` for managing and tracking features that can disable the browser's back/forward cache. It ensures that features are correctly registered, tracked, and cleared based on different events like navigation and frame destruction, and that these actions interact correctly with the `FrameSchedulerDelegate`.

Prompt: 
```
这是目录为blink/renderer/platform/scheduler/main_thread/frame_scheduler_impl_unittest.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能

"""
es("high", "low", "best_effort"));

TEST_P(FrameSchedulerImplLowPriorityAsyncScriptExecutionTest,
       LowPriorityScriptExecutionHasBestEffortPriority) {
  EXPECT_EQ(
      GetExpectedPriority(),
      GetTaskQueue(TaskType::kLowPriorityScriptExecution)->GetQueuePriority())
      << specified_priority();
}

TEST_F(FrameSchedulerImplTest, BackForwardCacheOptOut) {
  EXPECT_THAT(
      frame_scheduler_->GetActiveFeaturesTrackedForBackForwardCacheMetrics(),
      testing::UnorderedElementsAre());

  auto feature_handle1 = frame_scheduler_->RegisterFeature(
      SchedulingPolicy::Feature::kWebSocket,
      {SchedulingPolicy::DisableBackForwardCache()});

  EXPECT_THAT(
      frame_scheduler_->GetActiveFeaturesTrackedForBackForwardCacheMetrics(),
      testing::UnorderedElementsAre(SchedulingPolicy::Feature::kWebSocket));

  auto feature_handle2 = frame_scheduler_->RegisterFeature(
      SchedulingPolicy::Feature::kWebRTC,
      {SchedulingPolicy::DisableBackForwardCache()});

  EXPECT_THAT(
      frame_scheduler_->GetActiveFeaturesTrackedForBackForwardCacheMetrics(),
      testing::UnorderedElementsAre(SchedulingPolicy::Feature::kWebSocket,
                                    SchedulingPolicy::Feature::kWebRTC));

  feature_handle1.reset();

  EXPECT_THAT(
      frame_scheduler_->GetActiveFeaturesTrackedForBackForwardCacheMetrics(),
      testing::UnorderedElementsAre(SchedulingPolicy::Feature::kWebRTC));

  feature_handle2.reset();

  EXPECT_THAT(
      frame_scheduler_->GetActiveFeaturesTrackedForBackForwardCacheMetrics(),
      testing::UnorderedElementsAre());
}

TEST_F(FrameSchedulerImplTest, BackForwardCacheOptOut_FrameNavigated) {
  EXPECT_THAT(
      frame_scheduler_->GetActiveFeaturesTrackedForBackForwardCacheMetrics(),
      testing::UnorderedElementsAre());

  auto feature_handle = frame_scheduler_->RegisterFeature(
      SchedulingPolicy::Feature::kWebSocket,
      {SchedulingPolicy::DisableBackForwardCache()});

  EXPECT_THAT(
      frame_scheduler_->GetActiveFeaturesTrackedForBackForwardCacheMetrics(),
      testing::UnorderedElementsAre(SchedulingPolicy::Feature::kWebSocket));

  frame_scheduler_->RegisterStickyFeature(
      SchedulingPolicy::Feature::kMainResourceHasCacheControlNoStore,
      {SchedulingPolicy::DisableBackForwardCache()});

  EXPECT_THAT(
      frame_scheduler_->GetActiveFeaturesTrackedForBackForwardCacheMetrics(),
      testing::UnorderedElementsAre(
          SchedulingPolicy::Feature::kWebSocket,
          SchedulingPolicy::Feature::kMainResourceHasCacheControlNoStore));

  // Same document navigations don't affect anything.
  frame_scheduler_->DidCommitProvisionalLoad(
      false, FrameScheduler::NavigationType::kSameDocument);
  EXPECT_THAT(
      frame_scheduler_->GetActiveFeaturesTrackedForBackForwardCacheMetrics(),
      testing::UnorderedElementsAre(
          SchedulingPolicy::Feature::kWebSocket,
          SchedulingPolicy::Feature::kMainResourceHasCacheControlNoStore));

  // Regular navigations reset all features.
  frame_scheduler_->DidCommitProvisionalLoad(
      false, FrameScheduler::NavigationType::kOther);
  EXPECT_THAT(
      frame_scheduler_->GetActiveFeaturesTrackedForBackForwardCacheMetrics(),
      testing::UnorderedElementsAre());

  // Resetting a feature handle after navigation shouldn't do anything.
  feature_handle.reset();

  EXPECT_THAT(
      frame_scheduler_->GetActiveFeaturesTrackedForBackForwardCacheMetrics(),
      testing::UnorderedElementsAre());
}

TEST_F(FrameSchedulerImplTest, FeatureUpload) {
  ResetFrameScheduler(/*is_in_embedded_frame_tree=*/false,
                      FrameScheduler::FrameType::kMainFrame);

  frame_scheduler_->GetTaskRunner(TaskType::kJavascriptTimerImmediate)
      ->PostTask(
          FROM_HERE,
          base::BindOnce(
              [](FrameSchedulerImpl* frame_scheduler,
                 testing::StrictMock<FrameSchedulerDelegateForTesting>*
                     delegate) {
                frame_scheduler->RegisterStickyFeature(
                    SchedulingPolicy::Feature::
                        kMainResourceHasCacheControlNoStore,
                    {SchedulingPolicy::DisableBackForwardCache()});
                frame_scheduler->RegisterStickyFeature(
                    SchedulingPolicy::Feature::
                        kMainResourceHasCacheControlNoCache,
                    {SchedulingPolicy::DisableBackForwardCache()});
                // Ensure that the feature upload is delayed.
                testing::Mock::VerifyAndClearExpectations(delegate);
                EXPECT_CALL(*delegate, UpdateBackForwardCacheDisablingFeatures(
                                           BlockingDetailsHasCCNS()));
              },
              frame_scheduler_.get(), frame_scheduler_delegate_.get()));

  base::RunLoop().RunUntilIdle();

  testing::Mock::VerifyAndClearExpectations(frame_scheduler_delegate_.get());
}

TEST_F(FrameSchedulerImplTest, FeatureUpload_FrameDestruction) {
  ResetFrameScheduler(/*is_in_embedded_frame_tree=*/false,
                      FrameScheduler::FrameType::kMainFrame);

  FeatureHandle feature_handle(frame_scheduler_->RegisterFeature(
      SchedulingPolicy::Feature::kWebSocket,
      {SchedulingPolicy::DisableBackForwardCache()}));

  frame_scheduler_->GetTaskRunner(TaskType::kJavascriptTimerImmediate)
      ->PostTask(
          FROM_HERE,
          base::BindOnce(
              [](FrameSchedulerImpl* frame_scheduler,
                 testing::StrictMock<FrameSchedulerDelegateForTesting>*
                     delegate,
                 FeatureHandle* feature_handle) {
                // Ensure that the feature upload is delayed.
                testing::Mock::VerifyAndClearExpectations(delegate);
                EXPECT_CALL(*delegate,
                            UpdateBackForwardCacheDisablingFeatures(
                                BlockingDetailsHasWebSocket(feature_handle)));
              },
              frame_scheduler_.get(), frame_scheduler_delegate_.get(),
              &feature_handle));
  frame_scheduler_->GetTaskRunner(TaskType::kJavascriptTimerImmediate)
      ->PostTask(FROM_HERE,
                 base::BindOnce(
                     [](FrameSchedulerImpl* frame_scheduler,
                        testing::StrictMock<FrameSchedulerDelegateForTesting>*
                            delegate,
                        FeatureHandle* feature_handle) {
                       feature_handle->reset();
                       ResetForNavigation(frame_scheduler);
                       // Ensure that we don't upload the features for frame
                       // destruction.
                       testing::Mock::VerifyAndClearExpectations(delegate);
                       EXPECT_CALL(*delegate,
                                   UpdateBackForwardCacheDisablingFeatures(
                                       BlockingDetailsIsEmpty()))
                           .Times(0);
                     },
                     frame_scheduler_.get(), frame_scheduler_delegate_.get(),
                     &feature_handle));

  base::RunLoop().RunUntilIdle();

  testing::Mock::VerifyAndClearExpectations(frame_scheduler_delegate_.get());
}

TEST_F(FrameSchedulerImplTest, TasksRunAfterDetach) {
  int counter = 0;
  scoped_refptr<base::SingleThreadTaskRunner> task_runner =
      frame_scheduler_->GetTaskRunner(TaskType::kJavascriptTimerImmediate);
  task_runner->PostTask(
      FROM_HERE, base::BindOnce(&IncrementCounter, base::Unretained(&counter)));
  task_runner->PostDelayedTask(
      FROM_HERE, base::BindOnce(&IncrementCounter, base::Unretained(&counter)),
      base::Milliseconds(100));
  frame_scheduler_.reset();
  task_environment_.FastForwardBy(base::Milliseconds(100));
  EXPECT_EQ(counter, 2);

  task_runner->PostTask(
      FROM_HERE, base::BindOnce(&IncrementCounter, base::Unretained(&counter)));
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(counter, 2);
}

TEST_F(FrameSchedulerImplTest, DetachedWebSchedulingTaskQueue) {
  // Regression test for crbug.com/1446596. WebSchedulingTaskQueue methods
  // should not crash if the underlying frame scheduler is destroyed and the
  // underlying task queue has not yet been destroyed.
  std::unique_ptr<WebSchedulingTaskQueue> web_scheduling_task_queue =
      frame_scheduler_->CreateWebSchedulingTaskQueue(
          WebSchedulingQueueType::kTaskQueue,
          WebSchedulingPriority::kUserVisiblePriority);
  frame_scheduler_->GetTaskRunner(TaskType::kJavascriptTimerImmediate)
      ->PostTask(FROM_HERE, base::BindLambdaForTesting([&]() {
                   frame_scheduler_.reset();
                   web_scheduling_task_queue->SetPriority(
                       WebSchedulingPriority::kBackgroundPriority);
                   web_scheduling_task_queue.reset();
                 }));
  base::RunLoop().RunUntilIdle();
}

class WebSchedulingTaskQueueTest : public FrameSchedulerImplTest,
                                   public WebSchedulingTestHelper::Delegate {
 public:
  void SetUp() override {
    FrameSchedulerImplTest::SetUp();
    web_scheduling_test_helper_ =
        std::make_unique<WebSchedulingTestHelper>(*this);
  }

  void TearDown() override {
    FrameSchedulerImplTest::TearDown();
    web_scheduling_test_helper_.reset();
  }

  FrameOrWorkerScheduler& GetFrameOrWorkerScheduler() override {
    return *frame_scheduler_.get();
  }

  scoped_refptr<base::SingleThreadTaskRunner> GetTaskRunner(
      TaskType task_type) override {
    return frame_scheduler_->GetTaskRunner(task_type);
  }

 protected:
  using TestTaskSpecEntry = WebSchedulingTestHelper::TestTaskSpecEntry;
  using WebSchedulingParams = WebSchedulingTestHelper::WebSchedulingParams;

  std::unique_ptr<WebSchedulingTestHelper> web_scheduling_test_helper_;
};

TEST_F(WebSchedulingTaskQueueTest, TasksRunInPriorityOrder) {
  Vector<String> run_order;
  Vector<TestTaskSpecEntry> test_spec = {
      {.descriptor = "BG1",
       .type_info = WebSchedulingParams(
           {.queue_type = WebSchedulingQueueType::kTaskQueue,
            .priority = WebSchedulingPriority::kBackgroundPriority})},
      {.descriptor = "BG2",
       .type_info = WebSchedulingParams(
           {.queue_type = WebSchedulingQueueType::kTaskQueue,
            .priority = WebSchedulingPriority::kBackgroundPriority})},
      {.descriptor = "UV1",
       .type_info = WebSchedulingParams(
           {.queue_type = WebSchedulingQueueType::kTaskQueue,
            .priority = WebSchedulingPriority::kUserVisiblePriority})},
      {.descriptor = "UV2",
       .type_info = WebSchedulingParams(
           {.queue_type = WebSchedulingQueueType::kTaskQueue,
            .priority = WebSchedulingPriority::kUserVisiblePriority})},
      {.descriptor = "UB1",
       .type_info = WebSchedulingParams(
           {.queue_type = WebSchedulingQueueType::kTaskQueue,
            .priority = WebSchedulingPriority::kUserBlockingPriority})},
      {.descriptor = "UB2",
       .type_info = WebSchedulingParams(
           {.queue_type = WebSchedulingQueueType::kTaskQueue,
            .priority = WebSchedulingPriority::kUserBlockingPriority})}};
  web_scheduling_test_helper_->PostTestTasks(&run_order, test_spec);

  base::RunLoop().RunUntilIdle();
  EXPECT_THAT(run_order,
              testing::ElementsAre("UB1", "UB2", "UV1", "UV2", "BG1", "BG2"));
}

TEST_F(WebSchedulingTaskQueueTest, DynamicTaskPriorityOrder) {
  Vector<String> run_order;
  Vector<TestTaskSpecEntry> test_spec = {
      {.descriptor = "BG1",
       .type_info = WebSchedulingParams(
           {.queue_type = WebSchedulingQueueType::kTaskQueue,
            .priority = WebSchedulingPriority::kBackgroundPriority})},
      {.descriptor = "BG2",
       .type_info = WebSchedulingParams(
           {.queue_type = WebSchedulingQueueType::kTaskQueue,
            .priority = WebSchedulingPriority::kBackgroundPriority})},
      {.descriptor = "UV1",
       .type_info = WebSchedulingParams(
           {.queue_type = WebSchedulingQueueType::kTaskQueue,
            .priority = WebSchedulingPriority::kUserVisiblePriority})},
      {.descriptor = "UV2",
       .type_info = WebSchedulingParams(
           {.queue_type = WebSchedulingQueueType::kTaskQueue,
            .priority = WebSchedulingPriority::kUserVisiblePriority})},
      {.descriptor = "UB1",
       .type_info = WebSchedulingParams(
           {.queue_type = WebSchedulingQueueType::kTaskQueue,
            .priority = WebSchedulingPriority::kUserBlockingPriority})},
      {.descriptor = "UB2",
       .type_info = WebSchedulingParams(
           {.queue_type = WebSchedulingQueueType::kTaskQueue,
            .priority = WebSchedulingPriority::kUserBlockingPriority})}};
  web_scheduling_test_helper_->PostTestTasks(&run_order, test_spec);

  web_scheduling_test_helper_
      ->GetWebSchedulingTaskQueue(WebSchedulingQueueType::kTaskQueue,
                                  WebSchedulingPriority::kUserBlockingPriority)
      ->SetPriority(WebSchedulingPriority::kBackgroundPriority);

  base::RunLoop().RunUntilIdle();
  EXPECT_THAT(run_order,
              testing::ElementsAre("UV1", "UV2", "BG1", "BG2", "UB1", "UB2"));
}

TEST_F(WebSchedulingTaskQueueTest, DynamicTaskPriorityOrderDelayedTasks) {
  Vector<String> run_order;
  Vector<TestTaskSpecEntry> test_spec = {
      {.descriptor = "UB1",
       .type_info = WebSchedulingParams(
           {.queue_type = WebSchedulingQueueType::kTaskQueue,
            .priority = WebSchedulingPriority::kUserBlockingPriority}),
       .delay = base::Milliseconds(5)},
      {.descriptor = "UB2",
       .type_info = WebSchedulingParams(
           {.queue_type = WebSchedulingQueueType::kTaskQueue,
            .priority = WebSchedulingPriority::kUserBlockingPriority}),
       .delay = base::Milliseconds(5)},
      {.descriptor = "UV1",
       .type_info = WebSchedulingParams(
           {.queue_type = WebSchedulingQueueType::kTaskQueue,
            .priority = WebSchedulingPriority::kUserVisiblePriority}),
       .delay = base::Milliseconds(5)},
      {.descriptor = "UV2",
       .type_info = WebSchedulingParams(
           {.queue_type = WebSchedulingQueueType::kTaskQueue,
            .priority = WebSchedulingPriority::kUserVisiblePriority}),
       .delay = base::Milliseconds(5)}};
  web_scheduling_test_helper_->PostTestTasks(&run_order, test_spec);

  web_scheduling_test_helper_
      ->GetWebSchedulingTaskQueue(WebSchedulingQueueType::kTaskQueue,
                                  WebSchedulingPriority::kUserBlockingPriority)
      ->SetPriority(WebSchedulingPriority::kBackgroundPriority);

  task_environment_.FastForwardBy(base::Milliseconds(5));
  EXPECT_THAT(run_order, testing::ElementsAre("UV1", "UV2", "UB1", "UB2"));
}

TEST_F(WebSchedulingTaskQueueTest, TasksAndContinuations) {
  Vector<String> run_order;
  Vector<TestTaskSpecEntry> test_spec = {
      {.descriptor = "BG",
       .type_info = WebSchedulingParams(
           {.queue_type = WebSchedulingQueueType::kTaskQueue,
            .priority = WebSchedulingPriority::kBackgroundPriority})},
      {.descriptor = "BG-C",
       .type_info = WebSchedulingParams(
           {.queue_type = WebSchedulingQueueType::kContinuationQueue,
            .priority = WebSchedulingPriority::kBackgroundPriority})},
      {.descriptor = "UV",
       .type_info = WebSchedulingParams(
           {.queue_type = WebSchedulingQueueType::kTaskQueue,
            .priority = WebSchedulingPriority::kUserVisiblePriority})},
      {.descriptor = "UV-C",
       .type_info = WebSchedulingParams(
           {.queue_type = WebSchedulingQueueType::kContinuationQueue,
            .priority = WebSchedulingPriority::kUserVisiblePriority})},
      {.descriptor = "UB",
       .type_info = WebSchedulingParams(
           {.queue_type = WebSchedulingQueueType::kTaskQueue,
            .priority = WebSchedulingPriority::kUserBlockingPriority})},
      {.descriptor = "UB-C",
       .type_info = WebSchedulingParams(
           {.queue_type = WebSchedulingQueueType::kContinuationQueue,
            .priority = WebSchedulingPriority::kUserBlockingPriority})}};
  web_scheduling_test_helper_->PostTestTasks(&run_order, test_spec);

  base::RunLoop().RunUntilIdle();
  EXPECT_THAT(run_order,
              testing::ElementsAre("UB-C", "UB", "UV-C", "UV", "BG-C", "BG"));
}

TEST_F(WebSchedulingTaskQueueTest, DynamicPriorityContinuations) {
  Vector<String> run_order;
  Vector<TestTaskSpecEntry> test_spec = {
      {.descriptor = "BG-C",
       .type_info = WebSchedulingParams(
           {.queue_type = WebSchedulingQueueType::kContinuationQueue,
            .priority = WebSchedulingPriority::kBackgroundPriority})},
      {.descriptor = "UV-C",
       .type_info = WebSchedulingParams(
           {.queue_type = WebSchedulingQueueType::kContinuationQueue,
            .priority = WebSchedulingPriority::kUserVisiblePriority})},
      {.descriptor = "UB-C",
       .type_info = WebSchedulingParams(
           {.queue_type = WebSchedulingQueueType::kContinuationQueue,
            .priority = WebSchedulingPriority::kUserBlockingPriority})}};
  web_scheduling_test_helper_->PostTestTasks(&run_order, test_spec);

  web_scheduling_test_helper_
      ->GetWebSchedulingTaskQueue(WebSchedulingQueueType::kContinuationQueue,
                                  WebSchedulingPriority::kUserBlockingPriority)
      ->SetPriority(WebSchedulingPriority::kBackgroundPriority);

  base::RunLoop().RunUntilIdle();
  EXPECT_THAT(run_order, testing::ElementsAre("UV-C", "BG-C", "UB-C"));
}

TEST_F(WebSchedulingTaskQueueTest, WebScheduingAndNonWebScheduingTasks) {
  Vector<String> run_order;
  Vector<TestTaskSpecEntry> test_spec = {
      {.descriptor = "Idle",
       .type_info = TaskType::kLowPriorityScriptExecution},
      {.descriptor = "BG",
       .type_info = WebSchedulingParams(
           {.queue_type = WebSchedulingQueueType::kTaskQueue,
            .priority = WebSchedulingPriority::kBackgroundPriority})},
      {.descriptor = "BG-C",
       .type_info = WebSchedulingParams(
           {.queue_type = WebSchedulingQueueType::kContinuationQueue,
            .priority = WebSchedulingPriority::kBackgroundPriority})},
      {.descriptor = "UV",
       .type_info = WebSchedulingParams(
           {.queue_type = WebSchedulingQueueType::kTaskQueue,
            .priority = WebSchedulingPriority::kUserVisiblePriority})},
      {.descriptor = "UV-C",
       .type_info = WebSchedulingParams(
           {.queue_type = WebSchedulingQueueType::kContinuationQueue,
            .priority = WebSchedulingPriority::kUserVisiblePriority})},
      {.descriptor = "UB",
       .type_info = WebSchedulingParams(
           {.queue_type = WebSchedulingQueueType::kTaskQueue,
            .priority = WebSchedulingPriority::kUserBlockingPriority})},
      {.descriptor = "UB-C",
       .type_info = WebSchedulingParams(
           {.queue_type = WebSchedulingQueueType::kContinuationQueue,
            .priority = WebSchedulingPriority::kUserBlockingPriority})},
      {.descriptor = "Timer",
       .type_info = TaskType::kJavascriptTimerDelayedLowNesting},
      {.descriptor = "VH1",
       .type_info = TaskType::kInternalContinueScriptLoading},
      {.descriptor = "VH2",
       .type_info = TaskType::kInternalNavigationCancellation}};
  web_scheduling_test_helper_->PostTestTasks(&run_order, test_spec);

  base::RunLoop().RunUntilIdle();
  EXPECT_THAT(run_order,
              testing::ElementsAre("VH1", "VH2", "UB-C", "UB", "UV-C", "UV",
                                   "Timer", "BG-C", "BG", "Idle"));
}

// Verify that tasks posted with TaskType::kJavascriptTimerDelayed* and
// delayed web scheduling tasks run at the expected time when throttled.
TEST_F(FrameSchedulerImplTest, ThrottledJSTimerTasksRunTime) {
  constexpr TaskType kJavaScriptTimerTaskTypes[] = {
      TaskType::kJavascriptTimerDelayedLowNesting,
      TaskType::kJavascriptTimerDelayedHighNesting,
      TaskType::kWebSchedulingPostedTask};

  // Snap the time to a multiple of 1 second. Otherwise, the exact run time
  // of throttled tasks after hiding the page will vary.
  FastForwardToAlignedTime(base::Seconds(1));
  const base::TimeTicks start = base::TimeTicks::Now();

  // Hide the page to start throttling JS Timers.
  page_scheduler_->SetPageVisible(false);

  std::map<TaskType, std::vector<base::TimeTicks>> run_times;

  // Create the web scheduler task queue outside of the scope of the for loop.
  // This is necessary because otherwise the queue is deleted before tasks run,
  // and this breaks throttling.
  std::unique_ptr<WebSchedulingTaskQueue> web_scheduling_task_queue =
      frame_scheduler_->CreateWebSchedulingTaskQueue(
          WebSchedulingQueueType::kTaskQueue,
          WebSchedulingPriority::kUserVisiblePriority);

  // Post tasks with each Javascript Timer Task Type and with a
  // WebSchedulingTaskQueue.
  for (TaskType task_type : kJavaScriptTimerTaskTypes) {
    const scoped_refptr<base::SingleThreadTaskRunner> task_runner =
        task_type == TaskType::kWebSchedulingPostedTask
            ? web_scheduling_task_queue->GetTaskRunner()
            : frame_scheduler_->GetTaskRunner(task_type);

    // Note: Taking the address of an element in |run_times| is safe because
    // inserting elements in a map does not invalidate references.

    task_runner->PostTask(
        FROM_HERE, base::BindOnce(&RecordRunTime, &run_times[task_type]));
    task_runner->PostDelayedTask(
        FROM_HERE, base::BindOnce(&RecordRunTime, &run_times[task_type]),
        base::Milliseconds(1000));
    task_runner->PostDelayedTask(
        FROM_HERE, base::BindOnce(&RecordRunTime, &run_times[task_type]),
        base::Milliseconds(1002));
    task_runner->PostDelayedTask(
        FROM_HERE, base::BindOnce(&RecordRunTime, &run_times[task_type]),
        base::Milliseconds(1004));
    task_runner->PostDelayedTask(
        FROM_HERE, base::BindOnce(&RecordRunTime, &run_times[task_type]),
        base::Milliseconds(2500));
    task_runner->PostDelayedTask(
        FROM_HERE, base::BindOnce(&RecordRunTime, &run_times[task_type]),
        base::Milliseconds(6000));
  }

  // Make posted tasks run.
  task_environment_.FastForwardBy(base::Hours(1));

  // The effective delay of a throttled task is >= the requested delay, and is
  // within [N * 1000, N * 1000 + 3] ms, where N is an integer. This is because
  // the wake up rate is 1 per second, and the duration of each wake up is 3 ms.
  for (TaskType task_type : kJavaScriptTimerTaskTypes) {
    EXPECT_THAT(run_times[task_type],
                testing::ElementsAre(start + base::Milliseconds(0),
                                     start + base::Milliseconds(1000),
                                     start + base::Milliseconds(1002),
                                     start + base::Milliseconds(2000),
                                     start + base::Milliseconds(3000),
                                     start + base::Milliseconds(6000)));
  }
}

namespace {
class MockMainThreadScheduler : public MainThreadSchedulerImpl {
 public:
  explicit MockMainThreadScheduler(
      base::test::TaskEnvironment& task_environment)
      : MainThreadSchedulerImpl(
            base::sequence_manager::SequenceManagerForTest::Create(
                nullptr,
                task_environment.GetMainThreadTaskRunner(),
                task_environment.GetMockTickClock(),
                base::sequence_manager::SequenceManager::Settings::Builder()
                    .SetPrioritySettings(CreatePrioritySettings())
                    .Build())) {}

  MOCK_METHOD(void, OnMainFramePaint, ());
};
}  // namespace

TEST_F(FrameSchedulerImplTest, ReportFMPAndFCPForMainFrames) {
  MockMainThreadScheduler mock_main_thread_scheduler{task_environment_};
  AgentGroupScheduler* agent_group_scheduler =
      mock_main_thread_scheduler.CreateAgentGroupScheduler();
  std::unique_ptr<PageSchedulerImpl> page_scheduler = CreatePageScheduler(
      nullptr, &mock_main_thread_scheduler, *agent_group_scheduler);

  std::unique_ptr<FrameSchedulerImpl> main_frame_scheduler =
      CreateFrameScheduler(page_scheduler.get(), nullptr,
                           /*is_in_embedded_frame_tree=*/false,
                           FrameScheduler::FrameType::kMainFrame);

  EXPECT_CALL(mock_main_thread_scheduler, OnMainFramePaint).Times(2);

  main_frame_scheduler->OnFirstMeaningfulPaint(base::TimeTicks::Now());
  main_frame_scheduler->OnFirstContentfulPaintInMainFrame();

  main_frame_scheduler = nullptr;
  page_scheduler = nullptr;
  agent_group_scheduler = nullptr;
  mock_main_thread_scheduler.Shutdown();
}

TEST_F(FrameSchedulerImplTest, DontReportFMPAndFCPForSubframes) {
  MockMainThreadScheduler mock_main_thread_scheduler{task_environment_};
  AgentGroupScheduler* agent_group_scheduler =
      mock_main_thread_scheduler.CreateAgentGroupScheduler();
  std::unique_ptr<PageSchedulerImpl> page_scheduler = CreatePageScheduler(
      nullptr, &mock_main_thread_scheduler, *agent_group_scheduler);

  // Test for direct subframes.
  {
    std::unique_ptr<FrameSchedulerImpl> subframe_scheduler =
        CreateFrameScheduler(page_scheduler.get(), nullptr,
                             /*is_in_embedded_frame_tree=*/false,
                             FrameScheduler::FrameType::kSubframe);

    EXPECT_CALL(mock_main_thread_scheduler, OnMainFramePaint).Times(0);

    subframe_scheduler->OnFirstMeaningfulPaint(base::TimeTicks::Now());
  }

  // Now test for embedded main frames.
  {
    std::unique_ptr<FrameSchedulerImpl> subframe_scheduler =
        CreateFrameScheduler(page_scheduler.get(), nullptr,
                             /*is_in_embedded_frame_tree=*/true,
                             FrameScheduler::FrameType::kMainFrame);

    EXPECT_CALL(mock_main_thread_scheduler, OnMainFramePaint).Times(0);

    subframe_scheduler->OnFirstMeaningfulPaint(base::TimeTicks::Now());
  }

  page_scheduler = nullptr;
  agent_group_scheduler = nullptr;
  mock_main_thread_scheduler.Shutdown();
}

// Verify that tasks run at the expected time in a frame that is same-origin
// with the main frame, on a page that isn't loading when hidden ("quick"
// intensive wake up throttling kicks in).
TEST_P(FrameSchedulerImplTestWithIntensiveWakeUpThrottling,
       TaskExecutionSameOriginFrame) {
  ASSERT_FALSE(frame_scheduler_->IsCrossOriginToNearestMainFrame());

  // Throttled TaskRunner to which tasks are posted in this test.
  const scoped_refptr<base::SingleThreadTaskRunner> task_runner =
      GetTaskRunner();

  // Snap the time to a multiple of
  // |kIntensiveThrottledWakeUpInterval|. Otherwise, the time at which
  // tasks can run after throttling is enabled will vary.
  FastForwardToAlignedTime(kIntensiveThrottledWakeUpInterval);
  const base::TimeTicks test_start = base::TimeTicks::Now();

  // Hide the page. This starts the delay to throttle background wake ups.
  EXPECT_FALSE(page_scheduler_->IsLoading());
  EXPECT_TRUE(page_scheduler_->IsPageVisible());
  page_scheduler_->SetPageVisible(false);

  // Initially, wake ups are not intensively throttled.
  {
    const base::TimeTicks scope_start = base::TimeTicks::Now();
    EXPECT_EQ(scope_start, test_start);
    std::vector<base::TimeTicks> run_times;

    for (int i = 0; i < kNumTasks; ++i) {
      task_runner->PostDelayedTask(
          FROM_HERE, base::BindOnce(&RecordRunTime, &run_times),
          kShortDelay + i * kDefaultThrottledWakeUpInterval);
    }

    task_environment_.FastForwardBy(kGracePeriod);
    EXPECT_THAT(run_times,
                testing::ElementsAre(
                    scope_start + kDefaultThrottledWakeUpInterval,
                    scope_start + 2 * kDefaultThrottledWakeUpInterval,
                    scope_start + 3 * kDefaultThrottledWakeUpInterval,
                    scope_start + 4 * kDefaultThrottledWakeUpInterval,
                    scope_start + 5 * kDefaultThrottledWakeUpInterval));
  }

  // After the grace period:

  // Test that wake ups are 1-second aligned if there is no recent wake up.
  {
    const base::TimeTicks scope_start = base::TimeTicks::Now();
    EXPECT_EQ(scope_start, test_start + base::Minutes(1));
    std::vector<base::TimeTicks> run_times;

    // Schedule task to run 1 minute after the last one.
    const base::TimeTicks last_task_run_at = test_start + base::Seconds(5);
    const base::TimeDelta delay =
        last_task_run_at + kIntensiveThrottledWakeUpInterval - scope_start;
    EXPECT_EQ(delay, base::Seconds(5));

    task_runner->PostDelayedTask(
        FROM_HERE, base::BindOnce(&RecordRunTime, &run_times), delay);

    task_environment_.FastForwardBy(delay);
    EXPECT_THAT(run_times, testing::ElementsAre(scope_start + delay));
  }

  // Test that if there is a recent wake up:
  //   TaskType can be intensively throttled:   Wake ups are 1-minute aligned
  //   Otherwise:                               Wake ups are 1-second aligned
  {
    const base::TimeTicks scope_start = base::TimeTicks::Now();
    EXPECT_EQ(scope_start, test_start + base::Minutes(1) + base::Seconds(5));
    std::vector<base::TimeTicks> run_times;

    for (int i = 0; i < kNumTasks; ++i) {
      task_runner->PostDelayedTask(
          FROM_HERE, base::BindOnce(&RecordRunTime, &run_times),
          kShortDelay + i * kDefaultThrottledWakeUpInterval);
    }

    FastForwardToAlignedTime(kIntensiveThrottledWakeUpInterval);

    if (IsIntensiveThrottlingExpected()) {
      const base::TimeTicks aligned_time = scope_start + base::Seconds(55);
      EXPECT_EQ(aligned_time.SnappedToNextTick(
                    base::TimeTicks(), kIntensiveThrottledWakeUpInterval),
                aligned_time);
      EXPECT_THAT(run_times,
                  testing::ElementsAre(aligned_time, aligned_time, aligned_time,
                                       aligned_time, aligned_time));
    } else {
      EXPECT_THAT(run_times,
                  testing::ElementsAre(scope_start + base::Seconds(1),
                                       scope_start + base::Seconds(2),
                                       scope_start + base::Seconds(3),
                                       scope_start + base::Seconds(4),
                                       scope_start + base::Seconds(5)));
    }
  }

  // Post an extra task with a short delay. The wake up should be 1-minute
  // aligned if the TaskType supports intensive throttling, or 1-second aligned
  // otherwise.
  {
    const base::TimeTicks scope_start = base::TimeTicks::Now();
    EXPECT_EQ(scope_start, test_start + base::Minutes(2));
    std::vector<base::TimeTicks> run_times;

    task_runner->PostDelayedTask(FROM_HERE,
                                 base::BindOnce(&RecordRunTime, &run_times),
                                 kDefaultThrottledWakeUpInterval);

    task_environment_.FastForwardBy(kIntensiveThrottledWakeUpInterval);

    EXPECT_THAT(run_times, testing::ElementsAre(scope_start +
                                                GetExpectedWakeUpInterval()));
  }

  // Post an extra task with a delay longer than the intensive throttling wake
  // up interval. The wake up should be 1-second aligned, even if the TaskType
  // supports intensive throttling, because there was no wake up in the last
  // minute.
  {
    const base::TimeTicks scope_start = base::TimeTicks::Now();
    EXPECT_EQ(scope_start, test_start + base::Minutes(3));
    std::vector<base::TimeTicks> run_times;

    const base::TimeDelta kLongDelay =
        kIntensiveThrottledWakeUpInterval * 5 + kDefaultThrottledWakeUpInterval;
    task_runner->PostDelayedTask(
        FROM_HERE, base::BindOnce(&RecordRunTime, &run_times), kLongDelay);

    task_environment_.FastForwardBy(kLongDelay);
    EXPECT_THAT(run_times, testing::ElementsAre(scope_start + kLongDelay));
  }

  // Post tasks with short delays after the page communicated with the user in
  // background. Tasks should be 1-second aligned for 3 seconds. After that, if
  // the TaskType supports intensive throttling, wake ups should be 1-minute
  // aligned.
  {
    const base::TimeTicks scope_start = base::TimeTicks::Now();
    EXPECT_EQ(scope_start,
              test_start + base::Minutes(8) + kDefaultThrottledWakeUpInterval);
    std::vector<base::TimeTicks> run_times;

    page_scheduler_->OnTitleOrFaviconUpdated();
    task_runner->PostDelayedTask(
        FROM_HERE, base::BindLambdaForTesting([&]() {
          RecordRunTime(&run_times);
          for (int i = 0; i < kNumTasks; ++i) {
            task_runner->PostDelayedTask(
                FROM_HERE, base::BindOnce(&RecordRunTime, &run_times),
                kDefaultThrottledWakeUpInterval * (i + 1));
          }
        }),
        kDefaultThrottledWakeUpInterval);

    task_environment_.FastForwardUntilNoTasksRemain();

    if (IsIntensiveThrottlingExpected()) {
      EXPECT_THAT(
          run_times,
          testing::ElementsAre(
              scope_start + base::Seconds(1), scope_start + base::Seconds(2),
              scope_start + base::Seconds(3),
              scope_start - kDefaultThrottledWakeUpInterval + base::Minutes(1),
              scope_start - kDefaultThrottledWakeUpInterval + base::Minutes(1),
              scope_start - kDefaultThrottledWakeUpInterval +
                  base::Minutes(1)));
    } else {
      EXPECT_THAT(
          run_times,
          testing::ElementsAre(
              scope_start + base::Seconds(1), scope_start + base::Seconds(2),
              scope_start + base::Seconds(3), scope_start + base::Seconds(4),
              scope_start + base::Seconds(5), scope_start + base::Seconds(6)));
    }
  }
}

// Verify that tasks run at the expected time in a frame that is cross-origin
// with the main frame with intensive wake up throttling.
TEST_P(FrameSchedulerImplTestWithIntensiveWakeUpThrottling,
       TaskExecutionCrossOriginFrame) {
  frame_scheduler_->SetCrossOriginToNearestMainFrame(true);

  // Throttled TaskRunner to which tasks are posted in this test.
  const scoped_refptr<base::SingleThreadTaskRunner> task_runner =
      GetTaskRunner();

  // Snap the time to a multiple of
  // |kIntensiveThrottledWakeUpInterval|. Otherwise, the time at which
  // tasks can run after throttling is enabled will vary.
  FastForwardToAlignedTime(kIntensiveThrottledWakeUpInterval);
  const base::TimeTicks test_start = base::TimeTicks::Now();

  // Hide the page. This starts the delay to throttle background wake ups.
  EXPECT_TRUE(page_scheduler_->IsPageVisible());
  page_scheduler_->SetPageVisible(false);

  // Initially, wake ups are not intensively throttled.
  {
    const base::TimeTicks scope_start = base::TimeTicks::Now();
    EXPECT_EQ(scope_start, test_start);
    std::vector<base::TimeTicks> run_times;

    for (int i = 0; i < kNumTasks; ++i) {
      task_runner->PostDelayedTask(
          FROM_HERE, base::BindOnce(&RecordRunTime, &run_times),
          kShortDelay + i * kDefaultThrottledWakeUpInterval);
    }

    task_environment_.FastForwardBy(kGracePeriod);
    EXPECT_THAT(run_times,
                testing::ElementsAre(scope_start + base::Seconds(1),
                                     scope_start + base::Seconds(2),
                                     scope_start + base::Seconds(3),
                                     scope_start + base::Seconds(4),
                                     scope_start + base::Seconds(5)));
  }

  // After the grace period:

  // Test posting a task when there is no recent wake up. The wake up should be
  // 1-minute aligned if the TaskType supports intensive throttling (in a main
  // frame, it would have been 1-second aligned since there was no wake up in
  // the last minute). Otherwise, it should be 1-second aligned.
  {
    const base::TimeTicks scope_start = base::TimeTicks::Now();
    EXPECT_EQ(scope_start, test_start + base::Minutes(1));
    std::vector<base::TimeTicks> run_times;

    task_runner->PostDelayedTask(FROM_HERE,
                                 base::BindOnce(&RecordRunTime, &run_times),
                                 kDefaultThrottledWakeUpInterval);

    task_environment_.FastForwardBy(kIntensiveThrottledWakeUpInterval);
    EXPECT_THAT(run_times, testing::ElementsAre(scope_start +
                                                GetExpectedWakeUpInterval()));
  }

  // Test posting many tasks with short delays. Wake ups should be 1-minute
  // aligned if the TaskType supports intensive throttling, or 1-second aligned
  // otherwise.
  {
    const base::TimeTicks scope_start = base::TimeTicks::Now();
    EXPECT_EQ(scope_start, test_start + base::Minutes(2));
    std::vector<base::TimeTicks> run_times;

    for (int i = 0; i < kNumTasks; ++i) {
      task_runner->PostDelayedTask(
          FROM_HERE, base::BindOnce(&RecordRunTime, &run_times),
          kShortDelay + i * kDefaultThrottledWakeUpInterval);
    }

    task_environment_.FastForwardBy(kIntensiveThrottledWakeUpInterval);

    if (IsIntensiveThrottlingExpected()) {
      const base::TimeTicks aligned_time =
          scope_start + kIntensiveThrottledWakeUpInterval;
      EXPECT_THAT(run_times,
                  testing::ElementsAre(aligned_time, aligned_time, aligned_time,
                                       aligned_time, aligned_time));
    } else {
      EXPECT_THAT(run_times,
                  testing::ElementsAre(scope_start + base::Seconds(1),
                                       scope_start + base::Seconds(2),
                                       scope_start + base::Seconds(3),
                                       scope_start + base::Seconds(4),
                                       scope_start + base::Seconds(5)));
    }
  }

  // Post an extra task with a short delay. Wake ups should be 1-minute aligned
  // if the TaskType supports intensive throttling, or 1-second aligned
  // otherwise.
  {
    const base::TimeTicks scope_start = base::TimeTicks::Now();
    EXPECT_EQ(scope_start, test_start + base::Minutes(3));
    std::vector<base::TimeTicks> run_times;

    task_runner->PostDelayedTask(FROM_HERE,
                                 base::BindOnce(&RecordRunTime, &run_times),
                                 kDefaultThrottledWakeUpInterval);

    task_environment_.FastForwardBy(kIntensiveThrottledWakeUpInterval);
    EXPECT_THAT(run_times, testing::ElementsAre(scope_start +
                                                GetExpectedWakeUpInterval()));
  }

  // Post an extra task with a delay longer than the intensive throttling wake
  // up interval. The wake up should be 1-minute aligned if the TaskType
  // supports intensive throttling (in a main frame, it would have been 1-second
  // aligned because there was no wake up in the last minute). Otherwise, it
  // should be 1-second aligned.
  {
    const base::TimeTicks scope_start = base::TimeTicks::Now();
    EXPECT_EQ(scope_start, test_start + base::Minutes(4));
    std::vector<base::TimeTicks> run_times;

    const base::TimeDelta kLongDelay = kIntensiveThrottledWakeUpInterval * 6;
    task_runner->PostDelayedTask(FROM_HERE,
                                 base::BindOnce(&RecordRunTime, &run_times),
                                 kLongDelay - kShortDelay);

    task_environment_.FastForwardBy(kLongDelay);
    EXPECT_THAT(run_times, testing::ElementsAre(scope_start + kLongDelay));
  }

  // Post tasks with short delays after the page communicated with the user in
  // background. Wake ups should be 1-minute aligned if the TaskType supports
  // intensive throttling, since cross-origin frames are not affected by title
  // or favicon update. Otherwise, they should be 1-second aligned.
  {
    const base::TimeTicks scope_start = base::TimeTicks::Now();
    EXPECT_EQ(scope_start, test_start + base::Minutes(10));
    std::vector<base::TimeTicks> run_times;

    page_scheduler_->OnTitleOrFaviconUpdated();
    task_runner->PostDelayedTask(
        FROM_HERE, base::BindLambdaForTesting([&]() {
          RecordRunTime(&run_times);
          for (int i = 0; i < kNumTasks; ++i) {
            task_runner->PostDelayedTask(
                FROM_HERE, base::BindOnce(&RecordRunTime, &run_times),
                kDefaultThrottledWakeUpInterval * (i + 1));
          }
          page_scheduler_->OnTitleOrFaviconUpdated();
        }),
        kDefaultThrottledWakeUpInterval);

    task_environment_.FastForwardUntilNoTasksRemain();

    if (IsIntensiveThrottlingExpected()) {
      EXPECT_THAT(
          run_times,
          testing::ElementsAre(
              scope_start + base::Minutes(1), scope_start + base::Minutes(2),
              scope_start + base::Minutes(2), scope_start + base::Minutes(2),
              scope_start + base::Minutes(2), scope_start + base::Minutes(2)));
    } else {
      EXPECT_THAT(
          run_times,
          testing::ElementsAre(
              scope_start + base::Seconds(1), scope_start + base::Seconds(2),
              scope_start + base::Seconds(3), scope_start + base::Seconds(4),
              scope_start + base::Seconds(5), scope_start + base::Seconds(6)));
    }
  }
}

// Verify that tasks from different frames that are same-origin with the main
// frame run at the expected time.
TEST_P(FrameSchedulerImplTestWithIntensiveWakeUpThrottling,
       ManySameOriginFrames) {
  ASSERT_FALSE(frame_scheduler_->IsCrossOriginToNearestMainFrame());
  const scoped_refptr<base::SingleThreadTaskRunner> task_runner =
      GetTaskRunner();

  // Create a FrameScheduler that is same-origin with the main frame, and an
  // associated throttled TaskRunner.
  std::unique_ptr<FrameSchedulerImpl> other_frame_scheduler =
      CreateFrameScheduler(page_scheduler_.get(),
                           frame_scheduler_delegate_.get(),
                           /*is_in_embedded_frame_tree=*/false,
                           FrameScheduler::FrameType::kSubframe);
  ASSERT_FALSE(other_frame_scheduler->IsCrossOriginToNearestMainFrame());
  const scoped_refptr<base::SingleThreadTaskRunner> other_task_runner =
      GetTaskRunner(other_frame_scheduler.get());

  // Snap the time to a multiple of
  // |kIntensiveThrottledWakeUpInterval|. Otherwise, the time at which
  // tasks can run after throttling is enabled will vary.
  FastForwardToAlignedTime(kIntensiveThrottledWakeUpInterval);

  // Hide the page and wait until the intensive throttling grace period has
  // elapsed.
  EXPECT_TRUE(page_scheduler_->IsPageVisible());
  page_scheduler_->SetPageVisible(false);
  task_environment_.FastForwardBy(kGracePeriod);

  // Post tasks in both frames, with delays shorter than the intensive wake up
  // interval.
  const base::TimeTicks post_time = base::TimeTicks::Now();
  std::vector<base::TimeTicks> run_times;
  task_runner->PostDelayedTask(FROM_HERE,
                               base::BindOnce(&RecordRunTime, &run_times),
                               kDefaultThrottledWakeUpInterval + kShortDelay);
  other_task_runner->PostDelayedTask(
      FROM_HERE, base::BindOnce(&RecordRunTime, &run_times),
      2 * kDefaultThrottledWakeUpInterval + kShortDelay);
  task_environment_.FastForwardUntilNoTasksRemain();

  // The first task is 1-second aligned, because there was no wake up in the
  // last minute. The second task is 1-minute aligned if the TaskType supports
  // intensive throttling, or 1-second aligned otherwise.
  if (IsIntensiveThrottlingExpected()) {
    EXPECT_THAT(run_times, testing::ElementsAre(
                               post_time + 2 * kDefaultThrottledWakeUpInterval,
                               post_time + kIntensiveThrottledWakeUpInterval));
  } else {
    EXPECT_THAT(
        run_times,
        testing::ElementsAre(post_time + 2 * kDefaultThrottledWakeUpInterval,
                             post_time + 3 * kDefaultThrottledWakeUpInterval));
  }
}

// Verify that intensive wake up throttling starts after 5 minutes instead of 1
// minute if the page is loading when hidden.
TEST_P(FrameSchedulerImplTestWithIntensiveWakeUpThrottling,
       TaskExecutionPageLoadingWhenHidden) {
  ASSERT_FALSE(frame_scheduler_->IsCrossOriginToNearestMainFrame());

  // Throttled TaskRunner to which tasks are posted in this test.
  const scoped_refptr<base::SingleThreadTaskRunner> task_runner =
      GetTaskRunner();

  // Snap the time to a multiple of
  // |kIntensiveThrottledWakeUpInterval|. Otherwise, the time at which
  // tasks can run after throttling is enabled will vary.
  FastForwardToAlignedTime(kIntensiveThrottledWakeUpInterval);
  const base::TimeTicks test_start = base::TimeTicks::Now();

  // Create a main frame and simulate a load in it.
  std::unique_ptr<FrameSchedulerImpl> main_frame_scheduler =
      CreateFrameScheduler(page_scheduler_.get(),
                           frame_scheduler_delegate_.get(),
                           /*is_in_embedded_frame_tree=*/false,
                           FrameScheduler::FrameType::kMainFrame);
  main_frame_scheduler->DidCommitProvisionalLoad(
      /*is_web_history_inert_commit=*/false,
      /*navigation_type=*/FrameScheduler::NavigationType::kOther);
  EXPECT_TRUE(page_scheduler_->IsLoading());

  // Hide the page. This starts the delay to throttle background wake ups.
  EXPECT_TRUE(page_scheduler_->IsPageVisible());
  page_scheduler_->SetPageVisible(false);

  // Wake ups are only "intensively" throttled after 5 minutes.
  std::vector<base::TimeTicks> run_times;
  task_runner->PostDelayedTask(
      FROM_HERE, base::BindOnce(&RecordRunTime, &run_times), base::Seconds(59));
  task_runner->PostDelayedTask(FROM_HERE,
                               base::BindOnce(&RecordRunTime, &run_times),
                               base::Seconds(297));
  task_runner->PostDelayedTask(FROM_HERE,
                               base::BindOnce(&RecordRunTime, &run_times),
                               base::Seconds(298));
  task_runner->PostDelayedTask(FROM_HERE,
                               base::BindOnce(&RecordRunTime, &run_times),
                               base::Seconds(300));
  task_runner->PostDelayedTask(FROM_HERE,
                               base::BindOnce(&RecordRunTime, &run_times),
                               base::Seconds(301));

  task_environment_.FastForwardBy(base::Minutes(7));

  if (IsIntensiveThrottlingExpected()) {
    EXPECT_THAT(run_times, testing::ElementsAre(test_start + base::Seconds(59),
                                                test_start + base::Seconds(297),
                                                test_start + base::Seconds(298),
                                                test_start + base::Seconds(300),
                                                test_start + base::Minutes(6)));
  } else {
    EXPECT_THAT(run_times,
                testing::ElementsAre(test_start + base::Seconds(59),
                                     test_start + base::Seconds(297),
                                     test_start + base::Seconds(298),
                                     test_start + base::Seconds(300),
                                     test_start + base::Seconds(301)));
  }
}

// Verify that intensive throttling is disabled when there is an opt-out.
TEST_P(FrameSchedulerImplTestWithIntensiveWakeUpThrottling,
       AggressiveThrottlingOptOut) {
  constexpr int kNumTasks = 3;
  // |task_runner| is throttled.
  const scoped_refptr<base::SingleThreadTaskRunner> task_runner =
      GetTaskRunner();
  // |other_task_runner| is throttled. It belongs to a different frame on the
  // same page.
  const auto other_frame_scheduler = CreateFrameScheduler(
      page_scheduler_.get(), frame_scheduler_delegate_.get(),
      /*is_in_embedded_frame_tree=*/false,
      FrameScheduler::FrameType::kSubframe);
  const scoped_refptr<base::SingleThreadTaskRunner> other_task_runner =
      GetTaskRunner(other_frame_scheduler.get());

  // Fast-forward the time to a multiple of
  // |kIntensiveThrottledWakeUpInterval|. Otherwise,
  // the time at which tasks can run after throttling is enabled will vary.
  FastForwardToAlignedTime(kIntensiveThrottledWakeUpInterval);

  // Hide the page and wait until the intensive throttling grace period has
  // elapsed.
  EXPECT_TRUE(page_scheduler_->IsPageVisible());
  page_scheduler_->SetPageVisible(false);
  task_environment_.FastForwardBy(kGracePeriod);

  {
    // Wake ups are intensively throttled, since there is no throttling opt-out.
    const base::TimeTicks scope_start = base::TimeTicks::Now();
    std::vector<base::TimeTicks> run_times;
    task_runner->PostDelayedTask(
        FROM_HERE, base::BindOnce(&RecordRunTime, &run_times), kShortDelay);
    task_runner->PostDelayedTask(FROM_HERE,
                                 base::BindOnce(&RecordRunTime, &run_times),
                                 kDefaultThrottledWakeUpInterval + kShortDelay);
    task_environment_.FastForwardUntilNoTasksRemain();
    if (IsIntensiveThrottlingExpected()) {
      // Note: Intensive throttling is not applied on the 1st task since there
      // is no recent wake up.
      EXPECT_THAT(run_times,
                  testing::ElementsAre(
                      scope_start + kDefaultThrottledWakeUpInterval,
                      scope_start + kIntensiveThrottledWakeUpInterval));
    } else {
      EXPECT_THAT(run_times,
                  testing::ElementsAre(
                      scope_start + kDefaultThrottledWakeUpInterval,
                      scope_start + 2 * kDefaultThrottledWakeUpInterval));
    }
  }

  {
    // Create an opt-out.
    auto handle = frame_scheduler_->RegisterFeature(
        SchedulingPolicy::Feature::kWebRTC,
        {SchedulingPolicy::DisableAggressiveThrottling()});

    {
      // Tasks should run after |kDefaultThrottledWakeUpInterval|, since
      // aggressive throttling is disabled, but default wake up throttling
      // remains enabled.
      const base::TimeTicks scope_start = base::TimeTicks::Now();
      std::vector<base::TimeTicks> run_times;
      for (int i = 1; i < kNumTasks + 1; ++i) {
        task_runner->PostDelayedTask(FROM_HERE,
                                     base::BindOnce(&RecordRunTime, &run_times),
                                     i * kShortDelay);
      }
      task_environment_.FastForwardUntilNoTasksRemain();
      EXPECT_THAT(
          run_times,
          testing::ElementsAre(scope_start + kDefaultThrottledWakeUpInterval,
                               scope_start + kDefaultThrottledWakeUpInterval,
                               scope_start + kDefaultThrottledWakeUpInterval));
    }

    {
      // Same thing for another frame on the same page.
      const base::TimeTicks scope_start = base::TimeTicks::Now();
      std::vector<base::TimeTicks> run_times;
      for (int i = 1; i < kNumTasks + 1; ++i) {
        other_task_runner->PostDelayedTask(
            FROM_HERE, base::BindOnce(&RecordRunTime, &run_times),
            i * kShortDelay);
      }
      task_environment_.FastForwardUntilNoTasksRemain();
      EXPECT_THAT(
          run_times,
          testing::ElementsAre(scope_start + kDefaultThrottledWakeUpInterval,
                               scope_start + kDefaultThrottledWakeUpInterval,
                               scope_start + kDefaultThrottledWakeUpInterval));
    }
  }

  // Fast-forward so that there is no recent wake up. Then, align the time on
  // |kIntensiveThrottledWakeUpInterval| to simplify expectations.
  task_environment_.FastForwardBy(kIntensiveThrottledWakeUpInterval);
  FastForwardToAlignedTime(kIntensiveThrottledWakeUpInterval);

  {
    // Wake ups are intensively throttled, since there is no throttling opt-out.
    const base::TimeTicks scope_start = base::TimeTicks::Now();
    std::vector<base::TimeTicks> run_times;
    task_runner->PostDelayedTask(
        FROM_HERE, base::BindOnce(&RecordRunTime, &run_times), kShortDelay);
    task_runner->PostDelayedTask(FROM_HERE,
                                 base::BindOnce(&RecordRunTime, &run_times),
                                 kDefaultThrottledWakeUpInterval + kShortDelay);
    task_environment_.FastForwardUntilNoTasksRemain();
    if (IsIntensiveThrottlingExpected()) {
      // Note: Intensive throttling is not applied on the 1st task since there
      // is no recent wake up.
      EXPECT_THAT(run_times,
                  testing::ElementsAre(
                      scope_start + kDefaultThrottledWakeUpInterval,
                      scope_start + kIntensiveThrottledWakeUpInterval));
    } else {
      EXPECT_THAT(run_times,
                  testing::ElementsAre(
                      scope_start + kDefaultThrottledWakeUpInterval,
                      scope_start + 2 * kDefaultThrottledWakeUpInterval));
    }
  }
}

// Verify that tasks run at the same time when a frame switches between being
// same-origin and cross-origin with the main frame.
TEST_P(FrameSchedulerImplTestWithIntensiveWakeUpThrottling,
       FrameChangesOriginType) {
  EXPECT_FALSE(frame_scheduler_->IsCrossOriginToNearestMainFrame());
  const scoped_refptr<base::SingleThreadTaskRunner> task_runner =
      GetTaskRunner();

  // Create a new FrameScheduler that remains cross-origin with the main frame
  // throughout the test.
  std::unique_ptr<FrameSchedulerImpl> cross_origin_frame_scheduler =
      CreateFrameScheduler(page_scheduler_.get(),
                           frame_scheduler_delegate_.get(),
                           /*is_in_embedded_frame_tree=*/false,
                           FrameScheduler::FrameType::kSubframe);
  cross_origin_frame_scheduler->SetCrossOriginToNearestMainFrame(true);
  const scoped_refptr<base::SingleThreadTaskRunner> cross_origin_task_runner =
      GetTaskRunner(cross_origin_frame_scheduler.get());

  // Snap the time to a multiple of
  // |kIntensiveThrottledWakeUpInterval|. Otherwise, the time at which
  // tasks can run after throttling is enabled will vary.
  FastForwardToAlignedTime(kIntensiveThrottledWakeUpInterval);

  // Hide the page and wait until the intensive throttling grace period has
  // elapsed.
  EXPECT_TRUE(page_scheduler_->IsPageVisible());
  page_scheduler_->SetPageVisible(false);
  task_environment_.FastForwardBy(kGracePeriod);

  {
    // Post delayed tasks with short delays to both frames. The
    // main-frame-origin task can run at the desired time, because there is no
    // recent wake up. The cross-origin task must run at an aligned time.
    int counter = 0;
    task_runner->PostDelayedTask(
        FROM_HERE,
        base::BindOnce(&IncrementCounter, base::Unretained(&counter)),
        kDefaultThrottledWakeUpInterval);
    int cross_origin_counter = 0;
    cross_origin_task_runner->PostDelayedTask(
        FROM_HERE,
        base::BindOnce(&IncrementCounter,
                       base::Unretained(&cross_origin_counter)),
        kDefaultThrottledWakeUpInterval);

    // Make the |frame_scheduler_| cross-origin. Its task must now run at an
    // aligned time.
    frame_scheduler_->SetCrossOriginToNearestMainFrame(true);

    task_environment_.FastForwardBy(kDefaultThrottledWakeUpInterval);
    if (IsIntensiveThrottlingExpected()) {
      EXPECT_EQ(0, counter);
      EXPECT_EQ(0, cross_origin_counter);
    } else {
      EXPECT_EQ(1, counter);
      EXPECT_EQ(1, cross_origin_counter);
    }

    FastForwardToAlignedTime(kIntensiveThrottledWakeUpInterval);
    EXPECT_EQ(1, counter);
    EXPECT_EQ(1, cross_origin_counter);
  }

  {
    // Post delayed tasks with long delays that aren't aligned with the wake up
    // interval. They should run at aligned times, since they are cross-origin.
    const base::TimeDelta kLongUnalignedDelay =
        5 * kIntensiveThrottledWakeUpInterval + kDefaultThrottledWakeUpInterval;
    int counter = 0;
    task_runner->PostDelayedTask(
        FROM_HERE,
        base::BindOnce(&IncrementCounter, base::Unretained(&counter)),
        kLongUnalignedDelay);
    int cross_origin_counter = 0;
    cross_origin_task_runner->PostDelayedTask(
        FROM_HERE,
        base::BindOnce(&IncrementCounter,
                       base::Unretained(&cross_origin_counter)),
        kLongUnalignedDelay);

    // Make the |frame_scheduler_| same-origin. Its task can now run at a
    // 1-second aligned time, since there was no wake up in the last minute.
    frame_scheduler_->SetCrossOriginToNearestMainFrame(false);

    task_environment_.FastForwardBy(kLongUnalignedDelay);
    if (IsIntensiveThrottlingExpected()) {
      EXPECT_EQ(1, counter);
      EXPECT_EQ(0, cross_origin_counter);
    } else {
      EXPECT_EQ(1, counter);
      EXPECT_EQ(1, cross_origin_counter);
    }

    FastForwardToAlignedTime(kIntensiveThrottledWakeUpInterval);
    EXPECT_EQ(1, counter);
    EXPECT_EQ(1, cross_origin_counter);
  }
}

INSTANTIATE_TEST_SUITE_P(
    AllTimerTaskTypes,
    FrameSchedulerImplTestWithIntensiveWakeUpThrottling,
    testing::Values(
        IntensiveWakeUpThrottlingTestParam{
            /* task_type=*/TaskType::kJavascriptTimerDelayedLowNesting,
            /* is_intensive_throttling_expected=*/false},
        IntensiveWakeUpThrottlingTestParam{
            /* task_type=*/TaskType::kJavascriptTimerDelayedHighNesting,
            /* is_intensive_throttling_expected=*/true},
        IntensiveWakeUpThrottlingTestParam{
            /* task_type=*/TaskType::kWebSchedulingPostedTask,
            /* is_intensive_throttling_expected=*/true}),
    [](const testing::TestParamInfo<IntensiveWakeUpThrottlingTestParam>& info) {
      return TaskTypeNames::TaskTypeToString(info.param.task_type);
    });

TEST_F(FrameSchedulerImplTestWithIntensiveWakeUpThrottlingPolicyOverride,
       PolicyForceEnable) {
  SetPolicyOverride(/* enabled = */ true);
  EXPECT_TRUE(IsIntensiveWakeUpThrottlingEnabled());

  // The parameters should be the defaults.
  EXPECT_EQ(
      base::Seconds(kIntensiveWakeUpThrottling_GracePeriodSeconds_Default),
      GetIntensiveWakeUpThrottlingGracePeriod(false));
}

TEST_F(FrameSchedulerImplTestWithIntensiveWakeUpThrottlingPolicyOverride,
       PolicyForceDisable) {
  SetPolicyOverride(/* enabled = */ false);
  EXPECT_FALSE(IsIntensiveWakeUpThrottlingEnabled());
}

class FrameSchedulerImplTestQuickIntensiveWakeUpThrottlingEnabled
    : public FrameSchedulerImplTest {
 public:
  FrameSchedulerImplTestQuickIntensiveWakeUpThrottlingEnabled()
      : FrameSchedulerImplTest(
            {features::kQuickIntensiveWakeUpThrottlingAfterLoading},
            {}) {}
};

TEST_F(FrameSchedulerImplTestQuickIntensiveWakeUpThrottlingEnabled,
       LoadingPageGracePeriod) {
  EXPECT_EQ(
      base::Seconds(kIntensiveWakeUpThrottling_GracePeriodSeconds_Default),
      GetIntensiveWakeUpThrottlingGracePeriod(true));
}

TEST_F(FrameSchedulerImplTestQuickIntensiveWakeUpThrottlingEnabled,
       LoadedPageGracePeriod) {
  EXPECT_EQ(base::Seconds(
                kIntensiveWakeUpThrottling_GracePeriodSecondsLoaded_Default),
            GetIntensiveWakeUpThrottlingGracePeriod(false));
}

// Verify that non-delayed kWebSchedulingPostedTask tasks are not throttled.
TEST_F(FrameSchedulerImplTest, ImmediateWebSchedulingTasksAreNotThrottled) {
  std::vector<base::TimeTicks> run_times;

  // Make sure we are *not* aligned to a 1 second boundary by aligning to a 1
  // second boundary and moving past it a bit. If we were throttled, even
  // non-delayed tasks will need to wait until the next aligned interval to run.
  FastForwardToAlignedTime(base::Seconds(1));
  task_environment_.FastForwardBy(base::Milliseconds(1));

  const base::TimeTicks start = base::TimeTicks::Now();

  // Hide the page to start throttling timers.
  page_scheduler_->SetPageVisible(false);

  std::unique_ptr<WebSchedulingTaskQueue> queue =
      frame_scheduler_->CreateWebSchedulingTaskQueue(
          WebSchedulingQueueType::kTaskQueue,
          WebSchedulingPriority::kUserVisiblePriority);
  // Post a non-delayed task to a web scheduling task queue.
  queue->GetTaskRunner()->PostTask(FROM_HERE,
                                   base::BindOnce(&RecordRunTime, &run_times));

  // Run any ready tasks, which includes our non-delayed non-throttled web
  // scheduling task. If we are throttled, our task will not run.
  base::RunLoop().RunUntilIdle();

  EXPECT_THAT(run_times, testing::ElementsAre(start));
}

TEST_F(FrameSchedulerImplTest, PostMessageForwardingHasVeryHighPriority) {
  auto task_queue = GetTaskQueue(TaskType::kInternalPostMessageForwarding);

  EXPECT_EQ(TaskPriority::kVeryHighPriority, task_queue->GetQueuePriority());
}

class FrameSchedulerImplThrottleUnimportantFrameTimersEnabledTest
    : public FrameSchedulerImplTest {
 public:
  FrameSchedulerImplThrottleUnimportantFrameTimersEnabledTest()
      : FrameSchedulerImplTest({features::kThrottleUnimportantFrameTimers},
                               {}) {}
};

TEST_F(FrameSchedulerImplThrottleUnimportantFrameTimersEnabledTest,
       VisibleSizeChange_CrossOrigin_ExplicitInit) {
  LazyInitThrottleableTaskQueue();
  EXPECT_FALSE(IsThrottled());
  frame_scheduler_->SetFrameVisible(true);
  frame_scheduler_->SetVisibleAreaLarge(true);
  frame_scheduler_->SetCrossOriginToNearestMainFrame(true);
  EXPECT_FALSE(IsThrottled());
  frame_scheduler_->SetVisibleAreaLarge(false);
  EXPECT_TRUE(IsThrottled());
  frame_scheduler_->SetVisibleAreaLarge(true);
  EXPECT_FALSE(IsThrottled());
}

TEST_F(FrameSchedulerImplThrottleUnimportantFrameTimersEnabledTest,
       UserActivationChange_CrossOrigin_ExplicitInit) {
  LazyInitThrottleableTaskQueue();
  EXPECT_FALSE(IsThrottled());
  frame_scheduler_->SetFrameVisible(true);
  frame_scheduler_->SetVisibleAreaLarge(false);
  frame_scheduler_->SetCrossOriginToNearestMainFrame(true);
  frame_scheduler_->SetHadUserActivation(false);
  EXPECT_TRUE(IsThrottled());
  frame_scheduler_->SetHadUserActivation(true);
  EXPECT_FALSE(IsThrottled());
  frame_scheduler_->SetHadUserActivation(false);
  EXPECT_TRUE(IsThrottled());
}

TEST_F(FrameSchedulerImplThrottleUnimportantFrameTimersEnabledTest,
       UnimportantFrameThrottling) {
  page_scheduler_->SetPageVisible(true);
  frame_scheduler_->SetCrossOriginToNearestMainFrame(true);
  const scoped_refptr<base::SingleThreadTaskRunner> task_runner =
      frame_scheduler_->GetTaskRunner(
          TaskType::kJavascriptTimerDelayedLowNesting);
  frame_scheduler_->SetFrameVisible(true);
  frame_scheduler_->SetVisibleAreaLarge(false);
  frame_scheduler_->SetHadUserActivation(false);

  PostTasks_Expect32msAlignment(task_runner);
}

TEST_F(FrameSchedulerImplThrottleUnimportantFrameTimersEnabledTest,
       HiddenCrossOriginFrameThrottling) {
  page_scheduler_->SetPageVisible(true);
  frame_scheduler_->SetCrossOriginToNearestMainFrame(true);
  const scoped_refptr<base::SingleThreadTaskRunner> task_runner =
      frame_scheduler_->GetTaskRunner(
          TaskType::kJavascriptTimerDelayedLowNesting);
  frame_scheduler_->SetFrameVisible(false);
  frame_scheduler_->SetVisibleAreaLarge(false);
  frame_scheduler_->SetHadUserActivation(false);

  PostTasks_Expect1sAlignment(task_runner);
}

TEST_F(FrameSchedulerImplThrottleUnimportantFrameTimersEnabledTest,
       BackgroundPageTimerThrottling) {
  page_scheduler_->SetPageVisible(false);

  frame_scheduler_->SetCrossOriginToNearestMainFrame(false);
  const scoped_refptr<base::SingleThreadTaskRunner> task_runner =
      frame_scheduler_->GetTaskRunner(
          TaskType::kJavascriptTimerDelayedLowNesting);
  frame_scheduler_->SetFrameVisible(true);
  frame_scheduler_->SetVisibleAreaLarge(true);
  frame_scheduler_->SetHadUserActivation(false);

  PostTasks_Expect1sAlignment(task_runner);
}

TEST_F(FrameSchedulerImplThrottleUnimportantFrameTimersEnabledTest,
       LargeCrossOriginFrameNoThrottling) {
  page_scheduler_->SetPageVisible(true);
  frame_scheduler_->SetCrossOriginToNearestMainFrame(true);
  const scoped_refptr<base::SingleThreadTaskRunner> task_runner =
      frame_scheduler_->GetTaskRunner(
          TaskType::kJavascriptTimerDelayedLowNesting);
  frame_scheduler_->SetFrameVisible(true);
  frame_scheduler_->SetVisibleAreaLarge(true);
  frame_scheduler_->SetHadUserActivation(false);

  PostTasks_ExpectNoAlignment(task_runner);
}

TEST_F(FrameSchedulerImplThrottleUnimportantFrameTimersEnabledTest,
       UserActivatedCrossOriginFrameNoThrottling) {
  page_scheduler_->SetPageVisible(true);
  frame_scheduler_->SetCrossOriginToNearestMainFrame(true);
  const scoped_refptr<base::SingleThreadTaskRunner> task_runner =
      frame_scheduler_->GetTaskRunner(
          TaskType::kJavascriptTimerDelayedLowNesting);
  frame_scheduler_->SetFrameVisible(true);
  frame_scheduler_->SetVisibleAreaLarge(false);
  frame_scheduler_->SetHadUserActivation(true);

  PostTasks_ExpectNoAlignment(task_runner);
}

class FrameSchedulerImplNoThrottlingVisibleAgentTest
    : public FrameSchedulerImplTest,
      // True iff the other frame belongs to a different page.
      public testing::WithParamInterface<bool> {
 public:
  FrameSchedulerImplNoThrottlingVisibleAgentTest()
      : FrameSchedulerImplTest({features::kNoThrottlingVisibleAgent}, {}) {}

  void SetUp() override {
    FrameSchedulerImplTest::SetUp();

    if (IsOtherFrameOnDifferentPage()) {
      other_page_scheduler_ = CreatePageScheduler(nullptr, scheduler_.get(),
                                                  *agent_group_scheduler_);
      EXPECT_TRUE(other_page_scheduler_->IsPageVisible());
    }

    task_runner_ = frame_scheduler_->GetTaskRunner(
        TaskType::kJavascriptTimerDelayedLowNesting);

    // Initial state: `frame_scheduler_` is a visible frame cross-origin to its
    // main frame. Its parent page scheduler is visible. It is not throttled.
    LazyInitThrottleableTaskQueue
"""


```