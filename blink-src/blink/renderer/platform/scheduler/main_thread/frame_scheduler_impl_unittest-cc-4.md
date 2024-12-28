Response:
My thinking process to analyze the provided code snippet and generate the summary involves several steps:

1. **Understand the Core Purpose:** The filename `frame_scheduler_impl_unittest.cc` immediately suggests this is a unit test file for `FrameSchedulerImpl`. Unit tests verify the functionality of individual components in isolation. Therefore, the primary function is to test different aspects of the `FrameSchedulerImpl` class.

2. **Identify Key Classes and Concepts:** I scanned the code for important class names and concepts. `FrameSchedulerImpl`, `PageSchedulerImpl`, `TaskRunner`, "throttling," "visibility," "agent," and "tasks" stood out. These terms are central to understanding what's being tested.

3. **Analyze Test Fixtures:** I paid close attention to the `TEST_F` and `TEST_P` macros and the classes they use (`FrameSchedulerImplTest`, `FrameSchedulerImplNoThrottlingVisibleAgentTest`, `FrameSchedulerImplNoThrottlingVisibleAgentAndThrottleUnimportantTest`). These fixtures set up the testing environment. The names themselves often provide clues about the specific scenarios being tested (e.g., "NoThrottlingVisibleAgent"). The `INSTANTIATE_TEST_SUITE_P` lines indicate parameterized tests, allowing the same test logic to be run with different configurations (in this case, whether the other frame is on the same page or a different page).

4. **Examine Individual Tests:** I went through each `TEST_P` and `TEST_F` block to understand the specific functionality being verified. I looked for:
    * **Setup:** How the test environment is initialized (e.g., setting frame visibility, agent IDs).
    * **Actions:** The specific methods of `FrameSchedulerImpl` being called (e.g., `SetFrameVisible`, `SetAgentClusterId`, `SetCrossOriginToNearestMainFrame`).
    * **Assertions:** The `EXPECT_TRUE`, `EXPECT_FALSE`, and `PostTasks_Expect...Alignment` calls, which check the expected behavior of the `FrameSchedulerImpl` under the given conditions. The alignment expectations are key for understanding throttling behavior.

5. **Infer Functionality from Tests:** Based on the individual tests, I started to infer the broader functionalities being tested:
    * **Throttling Logic:**  A significant portion of the tests focuses on how frame and page visibility, agent IDs, and cross-origin status affect the throttling of tasks.
    * **Visibility Handling:** Tests verify how `FrameSchedulerImpl` reacts to changes in frame and page visibility.
    * **Agent Affinity:** Tests explore how the `FrameSchedulerImpl` manages tasks and throttling based on which "agent cluster" a frame belongs to.
    * **Task Management:**  The `DeleteSoon` tests investigate how tasks are handled during and after the `FrameSchedulerImpl` is destroyed.

6. **Identify Relationships to Web Concepts:**  I connected the tested functionalities to web development concepts:
    * **JavaScript Timers:** Throttling directly impacts the execution of `setTimeout` and `setInterval` in JavaScript.
    * **HTML Structure (iframes):** The concept of embedded frames and cross-origin frames is evident in the tests.
    * **Page Visibility API:** The tests explicitly manipulate page visibility, a browser API.
    * **CSS and Rendering (Implicit):** Although not directly tested, the scheduling of tasks ultimately affects the rendering pipeline, which is influenced by CSS.

7. **Look for Logic and Assumptions:** I noted the "same-agent" concept and how it affects throttling. The tests implicitly assume a certain understanding of how Blink's scheduler works. The parameterized tests using `IsOtherFrameOnDifferentPage()` demonstrate an awareness of potential differences in behavior based on frame relationships.

8. **Identify Potential User/Programming Errors:**  I considered scenarios where incorrect usage could lead to unexpected behavior. For instance, relying on timers in hidden or backgrounded frames without understanding the throttling implications could lead to issues. Deleting objects managed by the scheduler incorrectly could also cause problems.

9. **Structure the Summary:** I organized the findings into logical sections: main function, relationship to web technologies, logical inferences (with examples), potential errors, and overall summary.

10. **Refine and Elaborate:** I reviewed the initial draft and added more detail and specific examples to make the explanation clearer and more comprehensive. For instance, I provided concrete examples of how throttling affects JavaScript timers.

By following these steps, I could systematically analyze the code snippet and produce a detailed and informative summary of its functionality. The key is to understand the *purpose* of unit tests and then deduce the functionality being tested by examining the setup, actions, and assertions within each test case.
这是目录为 `blink/renderer/platform/scheduler/main_thread/frame_scheduler_impl_unittest.cc` 的 Chromium Blink 引擎源代码文件的功能总结，这是第 5 部分，共 5 部分，意味着这是对该文件功能的最终总结。

**整体功能归纳：**

这个单元测试文件 (`frame_scheduler_impl_unittest.cc`) 的主要功能是 **全面测试 `FrameSchedulerImpl` 类的各种行为和逻辑**。 `FrameSchedulerImpl` 是 Blink 渲染引擎中负责管理单个渲染帧（Frame）任务调度的核心组件。  这个测试文件通过模拟各种场景，验证 `FrameSchedulerImpl` 是否按照预期的方式工作，特别是在任务优先级、节流 (throttling)、与页面可见性、跨域状态以及 Agent Cluster ID 相关的行为上。

**具体功能点总结（基于所有部分，包括当前部分）：**

1. **任务调度基础功能测试:**
   - 验证 `FrameSchedulerImpl` 能否正确地 Post 和执行不同类型的任务 (TaskType)。
   - 测试任务的执行顺序和优先级是否符合预期。
   - 验证内部测试任务 (kInternalTest) 的特殊处理。

2. **节流 (Throttling) 机制测试:**
   - **核心功能：**  深入测试 `FrameSchedulerImpl` 如何根据帧和页面的可见性、是否为跨域以及是否属于同一个 Agent Cluster 来决定是否以及如何节流任务。
   - **可见性影响：** 验证当帧或页面变为不可见时，任务是否会按照预期的延迟 (例如 1 秒) 进行节流。当帧或页面重新变为可见时，节流是否会被取消。
   - **相同 Agent Cluster 的影响：** 测试当存在相同 Agent Cluster 的可见帧时，即使当前帧不可见，任务是否不会被完全节流 (可能会被更小的延迟节流，例如 32ms，如果 `ThrottleUnimportantFrameTimers` 特性启用)。
   - **跨域影响：** 验证当帧与最近的主框架同源时，是否完全不会被节流。
   - **Agent Cluster ID 的影响：** 测试当帧的 Agent Cluster ID 发生变化时，节流状态的变化。
   - **重要性节流 (ThrottleUnimportantFrameTimers)：** 测试在启用 `ThrottleUnimportantFrameTimers` 特性时，对于非重要的定时器任务的节流行为，例如从 1 秒降低到 32 毫秒。

3. **页面可见性变化测试:**
   - 验证当包含该帧的页面可见性发生变化时，`FrameSchedulerImpl` 的节流状态是否正确更新。
   - 特别关注与其他相同 Agent Cluster 的可见帧在不同页面时的交互影响。

4. **Agent Cluster ID 管理测试:**
   - 测试 `SetAgentClusterId` 方法是否正确设置帧的 Agent Cluster ID。
   - 验证 Agent Cluster ID 的变化如何影响节流行为，尤其是在与其他帧共享相同 Agent Cluster 时。

5. **跨域状态管理测试:**
   - 测试 `SetCrossOriginToNearestMainFrame` 方法如何影响帧的跨域状态。
   - 验证跨域状态如何影响节流行为。

6. **对象生命周期管理测试 (`DeleteSoon`):**
   - 测试 `DeleteSoon` 方法，验证在 `FrameSchedulerImpl` 析构前后，通过 `DeleteSoon` 提交的对象是否会被正确删除。
   - 验证在 `FrameSchedulerImpl` 析构后，`DeleteSoon` 是否仍然能安全地执行清理操作。
   - 使用 `base::RunLoop().RunUntilIdle()` 来确保异步任务的执行。

**与 JavaScript, HTML, CSS 的关系举例说明:**

* **JavaScript (定时器):**  `FrameSchedulerImpl` 的节流机制直接影响 JavaScript 中 `setTimeout` 和 `setInterval` 的执行。
    * **例子：** 如果一个隐藏的 iframe 中设置了 `setTimeout(function() { console.log("hello"); }, 10);`，当没有同 Agent Cluster 的可见帧时，这个定时器很可能不会在 10ms 后执行，而是被节流到 1 秒后执行。如果存在同 Agent Cluster 的可见帧，并且启用了 `ThrottleUnimportantFrameTimers`，则可能会被节流到 32ms。
* **HTML (iframe):**  `FrameSchedulerImpl` 负责管理每个 iframe 对应的调度。
    * **例子：**  测试中会创建不同的 `FrameSchedulerImpl` 实例来模拟不同的 iframe，并设置它们的可见性、Agent Cluster ID 等属性，以测试它们之间的相互影响。
* **CSS (渲染触发):** 虽然测试文件本身不直接操作 CSS，但 `FrameSchedulerImpl` 调度的任务最终会影响渲染流水线，其中包括 CSS 样式的计算和应用。
    * **例子：**  一个 JavaScript 动画可能会通过 `requestAnimationFrame` 提交任务到 `FrameSchedulerImpl`。如果帧被节流，动画的更新频率就会降低，导致视觉上的卡顿。

**逻辑推理的假设输入与输出举例:**

**假设输入:**

1. 帧 A 可见，与主框架同源。
2. 帧 B 不可见，与主框架跨域，与帧 A 属于不同的 Agent Cluster。
3. JavaScript 在帧 B 中设置了一个 10ms 的 `setTimeout`。

**输出:**

1. 帧 A 的任务不会被节流，会尽快执行。
2. 帧 B 的任务会被 1 秒节流，`setTimeout` 的回调函数会在大约 1 秒后执行，而不是 10ms 后。

**用户或编程常见的使用错误举例:**

* **错误地假设隐藏的 iframe 中的定时器会立即执行：** 开发者可能会在隐藏的 iframe 中设置很短的定时器来执行某些操作，但由于节流机制，这些操作可能会延迟很久才执行，导致功能异常。
* **没有考虑到相同 Agent Cluster 的影响：** 开发者可能认为一个隐藏的 iframe 的定时器会被节流，但如果存在同一个 Agent Cluster 的可见帧，且启用了 `ThrottleUnimportantFrameTimers`，则定时器可能只会受到较小的延迟，这可能不是开发者期望的行为。
* **在 `FrameSchedulerImpl` 析构后尝试使用其任务队列：** 虽然 `DeleteSoon` 可以处理一些清理工作，但开发者不应该依赖在 `FrameSchedulerImpl` 完全销毁后还能正常提交和执行任务。

**总结:**

总而言之，`blink/renderer/platform/scheduler/main_thread/frame_scheduler_impl_unittest.cc` 是一个关键的测试文件，用于确保 `FrameSchedulerImpl` 的正确性和稳定性。它涵盖了帧调度器的核心功能，特别是围绕任务节流的各种复杂场景，并验证了其与页面可见性、跨域状态和 Agent Cluster ID 的交互。这些测试对于维护 Chromium 的性能和用户体验至关重要，因为 `FrameSchedulerImpl` 直接影响了网页中 JavaScript 定时器、动画以及其他需要调度的任务的执行。 通过 `DeleteSoon` 相关的测试，也保证了资源清理和对象生命周期管理的正确性。

Prompt: 
```
这是目录为blink/renderer/platform/scheduler/main_thread/frame_scheduler_impl_unittest.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第5部分，共5部分，请归纳一下它的功能

"""
();
    EXPECT_TRUE(page_scheduler_->IsPageVisible());
    EXPECT_TRUE(frame_scheduler_->IsFrameVisible());
    EXPECT_FALSE(IsThrottled());
    frame_scheduler_->SetCrossOriginToNearestMainFrame(true);
    EXPECT_FALSE(IsThrottled());
    frame_scheduler_->SetAgentClusterId(kAgent1);
    EXPECT_FALSE(IsThrottled());
  }

  void TearDown() override {
    other_page_scheduler_.reset();
    FrameSchedulerImplTest::TearDown();
  }

  static const char* GetSuffix(const testing::TestParamInfo<bool>& info) {
    if (info.param) {
      return "OtherPage";
    }
    return "SamePage";
  }

  bool IsOtherFrameOnDifferentPage() { return GetParam(); }

  PageSchedulerImpl* GetOtherFramePageScheduler() {
    if (IsOtherFrameOnDifferentPage()) {
      return other_page_scheduler_.get();
    }
    return page_scheduler_.get();
  }

  std::unique_ptr<FrameSchedulerImpl> CreateOtherFrameScheduler() {
    return CreateFrameScheduler(GetOtherFramePageScheduler(),
                                frame_scheduler_delegate_.get(),
                                /*is_in_embedded_frame_tree=*/false,
                                FrameScheduler::FrameType::kSubframe);
  }

  const base::UnguessableToken kAgent1 = base::UnguessableToken::Create();
  const base::UnguessableToken kAgent2 = base::UnguessableToken::Create();
  scoped_refptr<base::SingleThreadTaskRunner> task_runner_;
  std::unique_ptr<PageSchedulerImpl> other_page_scheduler_;
};

class FrameSchedulerImplNoThrottlingVisibleAgentAndThrottleUnimportantTest
    : public FrameSchedulerImplNoThrottlingVisibleAgentTest {
 public:
  FrameSchedulerImplNoThrottlingVisibleAgentAndThrottleUnimportantTest() {
    nested_scoped_feature_list_.InitAndEnableFeature(
        features::kThrottleUnimportantFrameTimers);
  }

 private:
  base::test::ScopedFeatureList nested_scoped_feature_list_;
};

// Verify the throttled state on frame visibility changes.
TEST_P(FrameSchedulerImplNoThrottlingVisibleAgentTest, FrameVisibilityChange) {
  // Hidden frame with a visible same-agent frame: expect no throttling.
  frame_scheduler_->SetFrameVisible(false);
  auto other_frame_scheduler = CreateOtherFrameScheduler();
  other_frame_scheduler->SetAgentClusterId(kAgent1);
  EXPECT_TRUE(other_frame_scheduler->IsFrameVisible());
  EXPECT_FALSE(IsThrottled());
  PostTasks_ExpectNoAlignment(task_runner_);

  // Same-agent frame hidden: expect 1s throttling because there is no visible
  // same-agent frame.
  other_frame_scheduler->SetFrameVisible(false);
  EXPECT_TRUE(IsThrottled());
  PostTasks_Expect1sAlignment(task_runner_);

  // Same-agent frame visible: expect no throttling because there is a visible
  // same-agent frame.
  other_frame_scheduler->SetFrameVisible(true);
  EXPECT_FALSE(IsThrottled());
  PostTasks_ExpectNoAlignment(task_runner_);

  // Same-agent frame hidden: expect 1s throttling because there is no visible
  // same-agent frame.
  other_frame_scheduler->SetFrameVisible(false);
  EXPECT_TRUE(IsThrottled());
  PostTasks_Expect1sAlignment(task_runner_);

  // Frame visible: expect no throttling for a visible frame.
  frame_scheduler_->SetFrameVisible(true);
  EXPECT_FALSE(IsThrottled());
  PostTasks_ExpectNoAlignment(task_runner_);
}

// Verify the throttled state when page visibility changes and there is a
// visible same-agent frame.
TEST_P(FrameSchedulerImplNoThrottlingVisibleAgentTest, PageVisibilityChange) {
  // This test is only relevant when the other frame is on a different page.
  if (!IsOtherFrameOnDifferentPage()) {
    return;
  }

  // Hidden frame with a visible same-agent frame: expect no throttling.
  frame_scheduler_->SetFrameVisible(false);
  auto other_frame_scheduler = CreateOtherFrameScheduler();
  other_frame_scheduler->SetAgentClusterId(kAgent1);
  EXPECT_TRUE(other_frame_scheduler->IsFrameVisible());
  EXPECT_FALSE(IsThrottled());
  PostTasks_ExpectNoAlignment(task_runner_);

  // Visible frame: expect no throttling.
  frame_scheduler_->SetFrameVisible(true);
  EXPECT_FALSE(IsThrottled());
  PostTasks_ExpectNoAlignment(task_runner_);

  // Hidden page: expect no throttling, because there is a visible same-agent
  // frame.
  page_scheduler_->SetPageVisible(false);
  EXPECT_FALSE(IsThrottled());
  PostTasks_ExpectNoAlignment(task_runner_);

  // Visible page: still no throttling.
  page_scheduler_->SetPageVisible(true);
  EXPECT_FALSE(IsThrottled());
  PostTasks_ExpectNoAlignment(task_runner_);
}

// Verify the throttled state when the page visibility of a same-agent frame
// changes.
TEST_P(FrameSchedulerImplNoThrottlingVisibleAgentTest,
       SameAgentFramePageVisibilityChange) {
  // Hidden frame with a visible same-agent frame: expect no throttling.
  frame_scheduler_->SetFrameVisible(false);
  auto other_frame_scheduler = CreateOtherFrameScheduler();
  other_frame_scheduler->SetAgentClusterId(kAgent1);
  EXPECT_TRUE(other_frame_scheduler->IsFrameVisible());
  EXPECT_FALSE(IsThrottled());
  PostTasks_ExpectNoAlignment(task_runner_);

  // Page of the same-agent frame hidden: expect 1s throttling because there is
  // no visible same-agent frame.
  GetOtherFramePageScheduler()->SetPageVisible(false);
  EXPECT_TRUE(IsThrottled());
  PostTasks_Expect1sAlignment(task_runner_);

  // Page of the same-agent frame visible: expect no throttling because there is
  // a visible same-agent frame.
  GetOtherFramePageScheduler()->SetPageVisible(true);
  EXPECT_FALSE(IsThrottled());
  PostTasks_ExpectNoAlignment(task_runner_);

  // Repeat the 2 steps above, but with the same-agent frame is hidden: expect
  // 1s throttling because there is no visible same-agent frame.
  other_frame_scheduler->SetFrameVisible(false);

  GetOtherFramePageScheduler()->SetPageVisible(false);
  EXPECT_TRUE(IsThrottled());
  PostTasks_Expect1sAlignment(task_runner_);

  GetOtherFramePageScheduler()->SetPageVisible(true);
  EXPECT_TRUE(IsThrottled());
  PostTasks_Expect1sAlignment(task_runner_);
}

// Verify the throttled state when a same-agent visible frame is deleted.
TEST_P(FrameSchedulerImplNoThrottlingVisibleAgentTest, VisibleFrameDeletion) {
  // Hidden frame with a visible same-agent frame: expect no throttling.
  frame_scheduler_->SetFrameVisible(false);
  auto other_frame_scheduler = CreateOtherFrameScheduler();
  other_frame_scheduler->SetAgentClusterId(kAgent1);
  EXPECT_TRUE(other_frame_scheduler->IsFrameVisible());
  EXPECT_FALSE(IsThrottled());
  PostTasks_ExpectNoAlignment(task_runner_);

  // Visible same-agent frame deleted: expect 1s throttling because there is no
  // visible same-agent frame.
  other_frame_scheduler.reset();
  EXPECT_TRUE(IsThrottled());
  PostTasks_Expect1sAlignment(task_runner_);
}

// Verify the throttled state when a same-agent visible frame on a hidden page
// is deleted. This test exists to confirm that ~FrameSchedulerImpl checks
// `AreFrameAndPageVisible()`, not just `frame_visible_`, before invoking
// `DecrementVisibleFramesForAgent()`.
TEST_P(FrameSchedulerImplNoThrottlingVisibleAgentTest,
       VisibleFrameOnHiddenPageDeletion) {
  // Hidden frame with a visible same-agent frame: expect no throttling.
  frame_scheduler_->SetFrameVisible(false);
  auto other_frame_scheduler = CreateOtherFrameScheduler();
  other_frame_scheduler->SetAgentClusterId(kAgent1);
  EXPECT_TRUE(other_frame_scheduler->IsFrameVisible());
  EXPECT_FALSE(IsThrottled());
  PostTasks_ExpectNoAlignment(task_runner_);

  // Hide the other frame's page: expect 1s throttling because there is no
  // visible same-agent frame.
  GetOtherFramePageScheduler()->SetPageVisible(false);
  EXPECT_TRUE(IsThrottled());
  PostTasks_Expect1sAlignment(task_runner_);

  // Visible same-agent frame on a hidden page deleted: no change.
  other_frame_scheduler.reset();
  EXPECT_TRUE(IsThrottled());
  PostTasks_Expect1sAlignment(task_runner_);
}

// Verify the throttled state when the page scheduler of a same-agent frame is
// deleted.
//
// Note: Ideally, we would enforce that a page scheduler is deleted after its
// frame schedulers. But until this enforcement is in place, it is important
// that throttling deletion of a page scheduler that still has frame schedulers
// correctly.
TEST_P(FrameSchedulerImplNoThrottlingVisibleAgentTest,
       PageSchedulerWithSameAgentFrameDeleted) {
  // This test is only relevant when the other frame is on a different page.
  if (!IsOtherFrameOnDifferentPage()) {
    return;
  }

  // Hidden frame with a visible same-agent frame: expect no throttling.
  frame_scheduler_->SetFrameVisible(false);
  auto other_frame_scheduler = CreateOtherFrameScheduler();
  other_frame_scheduler->SetAgentClusterId(kAgent1);
  EXPECT_TRUE(other_frame_scheduler->IsFrameVisible());
  EXPECT_FALSE(IsThrottled());
  PostTasks_ExpectNoAlignment(task_runner_);

  // Delete the `other_frame_scheduler_`'s page scheduler: expect 1s throttling
  // because there is no visible same-agent frame (a frame scheduler with no
  // parent page scheduler doesn't count).
  other_page_scheduler_.reset();
  EXPECT_TRUE(IsThrottled());
  PostTasks_Expect1sAlignment(task_runner_);
}

// Verify the throttled state when frame agent changes.
TEST_P(FrameSchedulerImplNoThrottlingVisibleAgentTest, AgentChange) {
  // Hidden frame with a visible same-agent frame: expect no throttling.
  frame_scheduler_->SetFrameVisible(false);
  auto other_frame_scheduler = CreateOtherFrameScheduler();
  other_frame_scheduler->SetAgentClusterId(kAgent1);
  EXPECT_TRUE(other_frame_scheduler->IsFrameVisible());
  EXPECT_FALSE(IsThrottled());
  PostTasks_ExpectNoAlignment(task_runner_);

  // Other frame associated with `kAgent2`: expect 1s throttling because there
  // is no visible same-agent frame (other-frame-switches-to-different-agent).
  other_frame_scheduler->SetAgentClusterId(kAgent2);
  EXPECT_TRUE(IsThrottled());
  PostTasks_Expect1sAlignment(task_runner_);

  // Frame associated with `kAgent2`: expect no throttling because there is a
  // visible same-agent frame (frame-switches-to-same-agent).
  frame_scheduler_->SetAgentClusterId(kAgent2);
  EXPECT_FALSE(IsThrottled());
  PostTasks_ExpectNoAlignment(task_runner_);

  // Frame associated with `kAgent1`:  expect 1s throttling because there
  // is no visible same-agent frame (frame-switches-to-different-agent).
  frame_scheduler_->SetAgentClusterId(kAgent1);
  EXPECT_TRUE(IsThrottled());
  PostTasks_Expect1sAlignment(task_runner_);

  // Other frame associated with `kAgent1`: expect no throttling because there
  // is a visible same-agent frame (other-frame-switches-to-same-agent).
  other_frame_scheduler->SetAgentClusterId(kAgent1);
  EXPECT_FALSE(IsThrottled());
  PostTasks_ExpectNoAlignment(task_runner_);

  // Hide the other frame's page scheduler: frame should remain throttled to 1s
  // on agent change.
  GetOtherFramePageScheduler()->SetPageVisible(false);
  EXPECT_TRUE(IsThrottled());
  PostTasks_Expect1sAlignment(task_runner_);

  other_frame_scheduler->SetAgentClusterId(kAgent2);
  EXPECT_TRUE(IsThrottled());
  PostTasks_Expect1sAlignment(task_runner_);

  frame_scheduler_->SetAgentClusterId(kAgent2);
  EXPECT_TRUE(IsThrottled());
  PostTasks_Expect1sAlignment(task_runner_);

  frame_scheduler_->SetAgentClusterId(kAgent1);
  EXPECT_TRUE(IsThrottled());
  PostTasks_Expect1sAlignment(task_runner_);

  other_frame_scheduler->SetAgentClusterId(kAgent1);
  EXPECT_TRUE(IsThrottled());
  PostTasks_Expect1sAlignment(task_runner_);
}

// Verify the throttled state for a frame that is same-origin with the nearest
// main frame.
TEST_P(FrameSchedulerImplNoThrottlingVisibleAgentTest,
       SameOriginWithNearestMainFrame) {
  // Hidden frame with a visible same-agent frame: expect no throttling.
  frame_scheduler_->SetFrameVisible(false);
  auto other_frame_scheduler = CreateOtherFrameScheduler();
  other_frame_scheduler->SetAgentClusterId(kAgent1);
  EXPECT_TRUE(other_frame_scheduler->IsFrameVisible());
  EXPECT_FALSE(IsThrottled());
  PostTasks_ExpectNoAlignment(task_runner_);

  // Same-agent frame hidden: expect 1s throttling because there
  // is no visible same-agent frame.
  other_frame_scheduler->SetFrameVisible(false);
  EXPECT_TRUE(IsThrottled());
  PostTasks_Expect1sAlignment(task_runner_);

  // Frame is same-origin with nearest main frame: never throttled.
  frame_scheduler_->SetCrossOriginToNearestMainFrame(false);
  EXPECT_FALSE(IsThrottled());
  PostTasks_ExpectNoAlignment(task_runner_);

  other_frame_scheduler->SetAgentClusterId(kAgent2);
  other_frame_scheduler->SetAgentClusterId(kAgent1);
  EXPECT_FALSE(IsThrottled());
  PostTasks_ExpectNoAlignment(task_runner_);

  other_frame_scheduler->SetFrameVisible(false);
  other_frame_scheduler->SetFrameVisible(true);
  EXPECT_FALSE(IsThrottled());
  PostTasks_ExpectNoAlignment(task_runner_);

  GetOtherFramePageScheduler()->SetPageVisible(false);
  GetOtherFramePageScheduler()->SetPageVisible(true);
  EXPECT_FALSE(IsThrottled());
  PostTasks_ExpectNoAlignment(task_runner_);
}

// Verify that tasks are throttled to 32ms (not 1 second) in a frame that is
// hidden but same-agent with a visible frame, when the
// "ThrottleUnimportantFrameTimers" feature is enabled.
TEST_P(FrameSchedulerImplNoThrottlingVisibleAgentAndThrottleUnimportantTest,
       SameAgentWithVisibleFrameIs32msThrottled) {
  // Hidden frame with a visible same-agent frame: expect 32ms throttling.
  frame_scheduler_->SetFrameVisible(false);
  auto other_frame_scheduler = CreateOtherFrameScheduler();
  other_frame_scheduler->SetAgentClusterId(kAgent1);
  EXPECT_TRUE(other_frame_scheduler->IsFrameVisible());
  EXPECT_TRUE(IsThrottled());
  PostTasks_Expect32msAlignment(task_runner_);

  // Frame visible: expect no throttling.
  frame_scheduler_->SetFrameVisible(true);
  EXPECT_FALSE(IsThrottled());
  PostTasks_ExpectNoAlignment(task_runner_);

  // Frame hidden again: expect 32ms throttling.
  frame_scheduler_->SetFrameVisible(false);
  EXPECT_TRUE(IsThrottled());
  PostTasks_Expect32msAlignment(task_runner_);

  // Same-agent frame hidden: expect 1s throttling.
  other_frame_scheduler->SetFrameVisible(false);
  EXPECT_TRUE(IsThrottled());
  PostTasks_Expect1sAlignment(task_runner_);
}

INSTANTIATE_TEST_SUITE_P(
    ,
    FrameSchedulerImplNoThrottlingVisibleAgentTest,
    ::testing::Bool(),
    &FrameSchedulerImplNoThrottlingVisibleAgentTest::GetSuffix);

INSTANTIATE_TEST_SUITE_P(
    ,
    FrameSchedulerImplNoThrottlingVisibleAgentAndThrottleUnimportantTest,
    ::testing::Bool(),
    &FrameSchedulerImplNoThrottlingVisibleAgentTest::GetSuffix);

TEST_F(FrameSchedulerImplTest, DeleteSoonUsesBackupTaskRunner) {
  scoped_refptr<base::SingleThreadTaskRunner> task_runner =
      frame_scheduler_->GetTaskRunner(TaskType::kInternalTest);
  int counter = 0;
  task_runner->PostTask(
      FROM_HERE, base::BindOnce(&IncrementCounter, base::Unretained(&counter)));
  frame_scheduler_.reset();

  EXPECT_EQ(0, counter);
  // Because of graceful shutdown, the increment task should run since it was
  // queued. Since it's empty after the task finishes, the queue should then be
  // shut down.
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(1, counter);

  std::unique_ptr<TestObject> test_object =
      std::make_unique<TestObject>(&counter);
  task_runner->DeleteSoon(FROM_HERE, std::move(test_object));
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(2, counter);
}

TEST_F(FrameSchedulerImplTest, DeleteSoonAfterShutdown) {
  scoped_refptr<base::SingleThreadTaskRunner> task_runner =
      frame_scheduler_->GetTaskRunner(TaskType::kInternalTest);
  int counter = 0;

  // Deleting before shutdown should always work.
  std::unique_ptr<TestObject> test_object1 =
      std::make_unique<TestObject>(&counter);
  task_runner->DeleteSoon(FROM_HERE, std::move(test_object1));
  EXPECT_EQ(counter, 0);
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(counter, 1);

  task_runner->PostTask(
      FROM_HERE, base::BindOnce(&IncrementCounter, base::Unretained(&counter)));
  frame_scheduler_.reset();

  EXPECT_EQ(counter, 1);
  // Because of graceful shutdown, the increment task should run since it was
  // queued. Since it's empty after the task finishes, the queue should then be
  // shut down.
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(counter, 2);

  std::unique_ptr<TestObject> test_object2 =
      std::make_unique<TestObject>(&counter);
  task_runner->DeleteSoon(FROM_HERE, std::move(test_object2));
  EXPECT_EQ(counter, 2);
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(counter, 3);
}

}  // namespace frame_scheduler_impl_unittest
}  // namespace scheduler
}  // namespace blink

"""


```