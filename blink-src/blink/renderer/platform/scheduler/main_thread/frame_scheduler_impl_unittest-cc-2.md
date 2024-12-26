Response: The user is asking for a summary of the functionality of the provided C++ code, which is a unit test file for `FrameSchedulerImpl` in the Chromium Blink engine. I need to identify the primary purpose of the tests and how they interact with different aspects of the frame scheduling mechanism.

Here's a breakdown of the thought process:

1. **Identify the Core Class Under Test:** The filename `frame_scheduler_impl_unittest.cc` clearly indicates that the tests are for the `FrameSchedulerImpl` class.

2. **Recognize the Test Structure:** The code uses the Google Test framework (`TEST_F`, `TEST_P`, `INSTANTIATE_TEST_SUITE_P`). This means the code defines various test cases within test fixtures (classes inheriting from `testing::Test`).

3. **Analyze Test Fixture Names:** Pay close attention to the names of the test fixtures. For example, `FrameSchedulerImplTest`, `FrameSchedulerImplNoThrottlingVisibleAgentTest`, and `FrameSchedulerImplNoThrottlingVisibleAgentAndThrottleUnimportantTest` provide hints about the specific aspects being tested.

4. **Examine Individual Test Cases:**  Read through the individual `TEST_P` and `TEST_F` blocks and understand what each test is verifying. Look for calls to methods of `frame_scheduler_` and other related objects (like `page_scheduler_`). Pay attention to `EXPECT_TRUE`, `EXPECT_FALSE`, and function names like `IsThrottled`, `SetFrameVisible`, `SetPageVisible`, `SetAgentClusterId`, `SetCrossOriginToNearestMainFrame`.

5. **Identify Key Concepts:**  Based on the test names and actions within the tests, identify the core concepts being tested. In this case, throttling is a major theme, particularly in relation to frame visibility, page visibility, agent clusters (related to cross-origin isolation), and the `ThrottleUnimportantFrameTimers` feature.

6. **Relate to Web Technologies:** Consider how the tested concepts relate to web development.
    * **Throttling:** Directly impacts the execution of JavaScript timers (like `setTimeout` and `setInterval`) and animation frames, affecting performance and battery life, especially for background tabs or hidden frames.
    * **Frame Visibility:**  Corresponds to whether a frame is currently displayed on the screen. Hidden frames are often throttled to conserve resources.
    * **Page Visibility:** Refers to whether the entire tab or window is visible to the user. Background tabs are typically heavily throttled.
    * **Agent Clusters:**  A security mechanism that isolates browsing contexts. Cross-origin frames might have different throttling behaviors.
    * **Same-Origin:** A fundamental security concept in web browsers. Frames from the same origin often have less restricted access and might be treated differently in terms of throttling.

7. **Infer Assumptions and Logic:** For tests involving conditional logic (like checking `IsOtherFrameOnDifferentPage`), deduce the assumptions being made and how the test verifies different scenarios. For example, tests with `TEST_P` are parameterized, testing the same logic under different conditions (in this case, whether the "other" frame is on the same or a different page).

8. **Identify Potential User Errors:** Think about common mistakes developers might make that these tests could help catch. For example, relying on high-frequency timers in hidden or backgrounded frames is a common issue that throttling addresses.

9. **Address the "Part 3" Constraint:**  Since this is the final part, the summary should encompass the overall functionality demonstrated in this specific code snippet.

10. **Structure the Summary:** Organize the findings into logical categories, addressing the user's specific requests (functionality, relationship to web technologies, logical inferences, user errors).

By following these steps, I can generate a comprehensive and accurate summary of the provided unit test code.
好的，这是针对 `blink/renderer/platform/scheduler/main_thread/frame_scheduler_impl_unittest.cc` 文件的第三部分分析和功能归纳。

**功能归纳 (基于第三部分代码):**

这部分代码主要关注 `FrameSchedulerImpl` 在以下场景下的**节流 (throttling)** 行为测试，特别是当存在**同源代理 (same-agent)** 的可见帧时的行为：

* **帧的显示与隐藏 (Frame Visibility Change):** 测试当被测帧和另一个同源代理帧的显示状态变化时，是否会发生预期的节流。
* **页面的显示与隐藏 (Page Visibility Change):** 测试当包含被测帧或同源代理帧的页面显示状态变化时，是否会发生预期的节流。
* **同源代理帧的页面显示与隐藏 (SameAgentFramePageVisibilityChange):**  测试当另一个同源代理帧所在的页面显示状态变化时，被测帧的节流行为。
* **同源代理可见帧的删除 (VisibleFrameDeletion):** 测试当一个可见的同源代理帧被删除后，被测帧的节流状态。
* **隐藏页面上的同源代理可见帧的删除 (VisibleFrameOnHiddenPageDeletion):**  更细致地测试当同源代理帧在隐藏页面上被删除时，节流机制是否正确工作。
* **包含同源代理帧的 PageScheduler 的删除 (PageSchedulerWithSameAgentFrameDeleted):** 测试在某些非理想情况下（PageScheduler 比 FrameScheduler 先被删除），节流机制是否仍然能正确工作。
* **帧的代理变更 (Agent Change):** 测试当帧的代理标识符 (AgentClusterId) 改变时，是否会触发或取消节流。
* **与最近主框架同源 (SameOriginWithNearestMainFrame):**  测试当帧与最近的主框架同源时，其节流行为是否会被豁免。
* **启用 "ThrottleUnimportantFrameTimers" 特性时的行为 (SameAgentWithVisibleFrameIs32msThrottled):** 测试当启用此特性时，隐藏但与可见帧同源的帧是否会应用 32ms 的节流而不是 1s。
* **DeleteSoon 方法的使用 (DeleteSoonUsesBackupTaskRunner, DeleteSoonAfterShutdown):** 测试 `DeleteSoon` 方法在 `FrameSchedulerImpl` 关闭前后的行为，包括是否使用了备份的任务队列来执行延迟删除。

**与 JavaScript, HTML, CSS 的关系举例说明:**

* **节流 (Throttling) 与 JavaScript:** 节流直接影响 JavaScript 定时器 (`setTimeout`, `setInterval`) 和 `requestAnimationFrame` 的执行。当一个帧被节流时，这些定时器的回调函数不会立即执行，而是会被延迟。这部分测试验证了在不同可见性状态和同源关系下，JavaScript 定时器是否会被正确地节流。
    * **假设输入:**  一个隐藏的 iframe 包含以下 JavaScript 代码：`setInterval(() => { console.log('tick'); }, 10);` 且该 iframe 与主页面属于不同的 agent cluster。
    * **预期输出:**  由于 iframe 被隐藏且不同源，它应该被节流到 1 秒，`console.log('tick')` 不会每 10 毫秒执行，而是大约每秒执行一次。
* **帧的显示与隐藏 (Frame Visibility) 与 HTML/CSS:**  HTML 结构定义了帧（例如 `<iframe>`），而 CSS 可以控制帧的可见性（例如 `display: none;` 或 `visibility: hidden;`）。`FrameSchedulerImpl` 监听这些变化来决定是否需要节流。
    * **假设输入:**  一个包含 `<iframe>` 的 HTML 页面，初始状态下 iframe 是隐藏的（例如通过 CSS 设置 `display: none;`）。
    * **预期输出:** `FrameSchedulerImpl` 会检测到 iframe 是不可见的，并应用相应的节流策略。
* **页面的显示与隐藏 (Page Visibility) 与浏览器 API:**  浏览器提供了 Page Visibility API，允许 JavaScript 代码检测页面是否可见。`FrameSchedulerImpl` 也依赖于这些信息来执行节流。
    * **假设输入:** 用户将一个包含动画的标签页切换到后台。
    * **预期输出:**  `FrameSchedulerImpl` 会检测到页面不可见，并大幅度节流该页面的帧，以节省资源。

**逻辑推理的假设输入与输出:**

* **测试场景: 同源代理可见帧的删除 (VisibleFrameDeletion)**
    * **假设输入:**
        1. 一个隐藏的被测帧 `frame_scheduler_`。
        2. 另一个可见的同源代理帧 `other_frame_scheduler` 存在。
        3. `other_frame_scheduler` 被销毁 (例如，对应的 iframe 从 DOM 中移除)。
    * **预期输出:** 在 `other_frame_scheduler` 被销毁后，由于不再存在可见的同源代理帧，`frame_scheduler_->IsThrottled()` 将返回 `true`，并且后续的任务会被 1 秒对齐（`PostTasks_Expect1sAlignment(task_runner_)`）。

* **测试场景: 与最近主框架同源 (SameOriginWithNearestMainFrame)**
    * **假设输入:**
        1. 一个隐藏的被测帧 `frame_scheduler_`。
        2. `frame_scheduler_->SetCrossOriginToNearestMainFrame(false);` 被调用，表示该帧与最近的主框架同源。
    * **预期输出:** 无论其他条件如何（例如，是否存在其他可见的同源代理帧，页面是否可见），`frame_scheduler_->IsThrottled()` 始终返回 `false`，并且任务不会被节流（`PostTasks_ExpectNoAlignment(task_runner_)`）。

**涉及用户或编程常见的使用错误举例说明:**

* **依赖隐藏帧或后台页面的高频定时器:**  开发者可能会错误地认为在隐藏的 iframe 或后台标签页中设置的 `setInterval` 或 `requestAnimationFrame` 会像在前台页面一样高频率地执行。`FrameSchedulerImpl` 的节流机制会阻止这种情况，这可能是开发者没有预期到的行为。
    * **错误示例:**  一个广告 iframe 即使在不可见时也尝试频繁更新广告内容，浪费用户资源。
* **没有考虑同源代理帧的影响:** 开发者可能只关注当前帧的可见性，而忽略了同源代理帧的存在会影响节流策略。例如，一个隐藏的 iframe 如果存在一个可见的同源代理帧，它的节流程度可能会降低（在启用 `ThrottleUnimportantFrameTimers` 时甚至会是 32ms 而不是 1s）。
    * **错误示例:**  一个隐藏的辅助 iframe 依赖于与主页面共享的某些定时器逻辑，开发者可能没有意识到主页面的可见性会影响辅助 iframe 的定时器执行频率。
* **错误地假设 `DeleteSoon` 会立即执行:**  `DeleteSoon` 并不保证立即删除对象，它会将删除操作放入任务队列中。开发者可能会错误地依赖于 `DeleteSoon` 后的立即清理行为。
    * **错误示例:**  在调用 `DeleteSoon` 后立即尝试访问被删除对象的资源，可能导致程序崩溃或未定义行为。

**总结 (基于第三部分):**

这部分单元测试主要集中验证 `FrameSchedulerImpl` 在各种与帧和页面可见性、同源性以及代理关系相关的场景下的节流行为是否符合预期。 特别强调了当存在可见的同源代理帧时，被测帧的节流策略会发生怎样的变化。此外，还测试了 `DeleteSoon` 方法在对象销毁过程中的行为。这些测试对于确保 Blink 引擎能够有效地管理资源，避免不必要的后台活动，并优化性能至关重要。

Prompt: 
```
这是目录为blink/renderer/platform/scheduler/main_thread/frame_scheduler_impl_unittest.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第3部分，共3部分，请归纳一下它的功能

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