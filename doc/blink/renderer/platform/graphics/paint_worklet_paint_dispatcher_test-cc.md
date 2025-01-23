Response:
Let's break down the thought process for analyzing this C++ test file.

1. **Understand the Goal:** The core objective is to understand the functionality of the `PaintWorkletPaintDispatcher` by examining its tests. Test files demonstrate how a class is intended to be used and what behaviors are considered correct.

2. **Identify Key Classes:** The filename itself, `paint_worklet_paint_dispatcher_test.cc`, immediately points to the central class being tested: `PaintWorkletPaintDispatcher`. The presence of "test" in the name reinforces this.

3. **Examine Includes:** The included headers provide crucial context:
    * `"third_party/blink/renderer/platform/graphics/paint_worklet_paint_dispatcher.h"`: This confirms the main class being tested and its location within the Blink rendering engine.
    * `"base/functional/bind.h"` and `"base/run_loop.h"`:  These suggest asynchronous operations and the need to wait for them to complete in the tests.
    * `"cc/paint/paint_worklet_job.h"`: This indicates interaction with the Chromium Compositor (cc) and the concept of `PaintWorkletJob`s, which are the units of work for paint worklets.
    * `"testing/gmock/include/gmock/gmock.h"` and `"testing/gtest/include/gtest/gtest.h"`: These are the standard Google testing frameworks used for mocking and assertions.
    * Blink-specific scheduler headers: These highlight that paint worklets involve threading and task scheduling.

4. **Analyze Test Structure:**  The code is organized into `TEST_F` blocks, which are the individual test cases. Each test case focuses on a specific aspect of the `PaintWorkletPaintDispatcher`'s behavior. The `PaintWorkletPaintDispatcherAsyncTest` class sets up the testing environment.

5. **Deconstruct Individual Tests:** For each test case, ask:
    * **What is being set up?** (e.g., creating a `PaintWorkletPaintDispatcher`, mock painters, worklet threads, job maps).
    * **What action is being performed?** (e.g., calling `DispatchWorklets`).
    * **What is being asserted?** (e.g., `EXPECT_CALL`s on mock objects, `EXPECT_TRUE`/`EXPECT_FALSE` on the dispatcher's state).

6. **Identify Mock Objects:**  The code uses `NiceMock` to create mock implementations of `PaintWorkletPainter` and `PaintWorkletInput`. This is a key indicator of how the tests isolate the `PaintWorkletPaintDispatcher`'s logic. Pay attention to the methods being mocked (`Paint`, `GetWorkletId`, etc.) as they reveal the interactions the dispatcher has with these objects.

7. **Focus on Asynchronous Behavior:** The `WaitForTestCompletion()` method and the use of `base::RunLoop` clearly show that the tests are dealing with asynchronous operations. This implies that the `PaintWorkletPaintDispatcher` offloads work to other threads.

8. **Relate to Web Technologies (if applicable):** Since the prompt asks about connections to JavaScript, HTML, and CSS, consider how the tested functionality fits into the browser's rendering pipeline. Paint worklets are a CSS feature, so the tests likely involve how the browser handles the execution of CSS paint functions.

9. **Infer Functionality:** Based on the test cases, deduce the core responsibilities of the `PaintWorkletPaintDispatcher`:
    * **Registration:**  It can register `PaintWorkletPainter` instances for specific worklet IDs.
    * **Dispatching:** It receives `PaintWorkletJobMap`s and routes the work to the correct registered painter based on the worklet ID.
    * **Asynchronous Execution:** The painting happens on separate threads.
    * **Handling Different Scenarios:** It correctly handles cases with no registered painters, empty input, and multiple painters.
    * **Tracking Dispatch State:** It keeps track of whether a dispatch operation is ongoing.

10. **Consider Potential Errors:** Think about how developers might misuse the `PaintWorkletPaintDispatcher` based on its behavior. For instance, not registering a painter, providing incorrect worklet IDs, or not waiting for asynchronous completion could lead to problems.

11. **Structure the Explanation:** Organize the findings into logical sections, covering functionality, relationships to web technologies, logical reasoning (input/output), and potential usage errors. Use clear and concise language. Provide specific examples from the code to support the explanations.

**(Self-Correction during the process):**

* **Initial thought:** Maybe the dispatcher directly calls the `Paint` method on the painters.
* **Correction:** The use of `NonMainThread` and `WaitForTestCompletion` indicates asynchronous behavior. The dispatcher *schedules* the painting to happen on another thread.
* **Initial thought:** The tests are solely focused on the positive cases.
* **Correction:** While primarily focused on correct behavior, the test `DispatchCompletesWithNoPainters` also checks a scenario where no matching painter exists, which touches upon error handling or graceful completion.

By following this systematic analysis, you can effectively understand the purpose and behavior of the `PaintWorkletPaintDispatcher` by studying its test file.
这个C++源代码文件 `paint_worklet_paint_dispatcher_test.cc` 是 Chromium Blink 引擎中 `PaintWorkletPaintDispatcher` 类的单元测试文件。它的主要功能是 **测试 `PaintWorkletPaintDispatcher` 类的各种功能和行为是否符合预期。**

下面详细列举其功能以及与 JavaScript, HTML, CSS 的关系：

**核心功能:**

1. **测试 Worklet Painter 的注册和选择:**
   - 验证 `PaintWorkletPaintDispatcher` 能否正确注册不同的 `PaintWorkletPainter` 对象，并根据 `PaintWorkletJob` 中指定的 worklet ID 选择正确的 painter 来执行绘制任务。
   - **例子:** 测试用例 `DispatchSelectsCorrectPainter` 注册了两个不同的 `MockPaintWorkletPainter`，并断言只有与 `PaintWorkletJob` 中 worklet ID 匹配的 painter 的 `Paint` 方法会被调用。

2. **测试 Worklet 绘制任务的调度和执行:**
   - 验证 `PaintWorkletPaintDispatcher` 能否接收包含多个 `PaintWorkletJob` 的 `PaintWorkletJobMap`，并将这些任务分发到相应的 worklet painter 进行处理。
   - **例子:** 测试用例 `DispatchedWorkletIsPainted` 创建了一个包含多个相同 worklet ID 的 jobs 的 `PaintWorkletJobMap`，并断言对应的 `MockPaintWorkletPainter` 的 `Paint` 方法被调用了相应的次数。

3. **测试异步执行:**
   - `PaintWorkletPaintDispatcher` 涉及到在非主线程上执行 worklet 代码。测试验证了任务被正确地调度到 worklet 线程执行，并且测试能够等待异步操作完成。
   - **例子:** `PaintWorkletPaintDispatcherAsyncTest` 类使用了 `base::RunLoop` 来等待 worklet 线程完成绘制任务并调用回调函数。

4. **测试处理各种输入情况:**
   - 包括没有注册 painter 的情况，输入 job map 为空的情况，以及输入 job map 中包含不匹配已注册 painter 的 worklet ID 的情况。
   - **例子:**
     - `DispatchCompletesWithNoPainters` 测试了当没有注册任何 painter 时，dispatch 操作是否能够正常完成，并调用完成回调。
     - `DispatchHandlesEmptyInput` 测试了当输入的 `PaintWorkletJobMap` 为空时，是否会调用完成回调，并且不会调用任何 painter 的 `Paint` 方法。
     - `DispatchIgnoresNonMatchingInput` 测试了当输入的 job 中包含未注册的 worklet ID 时，已注册的 painter 是否只处理匹配的 job。

5. **测试跟踪正在进行的 dispatch 操作:**
   - 验证 `PaintWorkletPaintDispatcher` 能否正确跟踪是否有正在进行的 worklet 绘制任务。
   - **例子:** `HasOngoingDispatchIsTrackedCorrectly` 测试了在 dispatch 操作开始和结束时 `HasOngoingDispatch()` 方法的返回值是否符合预期。

**与 JavaScript, HTML, CSS 的关系:**

`PaintWorkletPaintDispatcher` 是 Blink 渲染引擎中处理 CSS Paint Worklet 的关键组件。CSS Paint Worklet 允许开发者使用 JavaScript 定义自定义的图像绘制函数，这些函数可以在 CSS 样式中使用，用于绘制背景、边框等。

1. **JavaScript:** CSS Paint Worklet 的逻辑是用 JavaScript 编写的。当浏览器遇到使用了 `paint()` 函数的 CSS 样式时，会调用相应的 JavaScript 代码来生成图像。`PaintWorkletPaintDispatcher` 负责调度和执行这些 JavaScript 代码（通过对应的 `PaintWorkletPainter`）。

   **举例:** 假设有一个 CSS Paint Worklet 的 JavaScript 代码定义了一个名为 `my-fancy-background` 的 painter：

   ```javascript
   registerPaint('my-fancy-background', class {
     paint(ctx, geom, properties) {
       ctx.fillStyle = 'red';
       ctx.fillRect(0, 0, geom.width, geom.height);
     }
   });
   ```

   在 HTML 中使用这个 painter：

   ```html
   <div style="background-image: paint(my-fancy-background);"></div>
   ```

   当渲染引擎处理这个 HTML 和 CSS 时，`PaintWorkletPaintDispatcher` 会找到与 `my-fancy-background` 对应的 `PaintWorkletPainter`，并将绘制任务传递给它，最终调用上面定义的 JavaScript `paint` 函数来绘制红色的背景。

2. **HTML:** HTML 结构定义了需要进行绘制的元素。CSS Paint Worklet 生成的图像会被应用到 HTML 元素上。

3. **CSS:** CSS 是触发 Paint Worklet 执行的关键。`paint()` 函数是 CSS 中用于调用 Paint Worklet 的语法。

   **举例:**  `background-image: paint(my-fancy-background);` 这段 CSS 代码指示浏览器使用名为 `my-fancy-background` 的 Paint Worklet 来绘制元素的背景图像。`PaintWorkletPaintDispatcher` 的作用就是响应这种 CSS 指令，找到并执行相应的绘制逻辑。

**逻辑推理 (假设输入与输出):**

**假设输入:**

* 注册了一个 `MockPaintWorkletPainter`，其 `GetWorkletId()` 返回 `123`。
* 创建了一个 `PaintWorkletJobMap`，其中包含一个 `PaintWorkletJob`，该 job 的 worklet ID 为 `123`。

**预期输出:**

* 当调用 `DispatchWorklets` 方法时，`MockPaintWorkletPainter` 的 `Paint` 方法会被调用一次，传入的 `PaintWorkletInput` 的 `WorkletId()` 应该返回 `123`。

**涉及用户或者编程常见的使用错误 (举例说明):**

1. **忘记注册 Painter:** 如果在 CSS 中使用了 `paint()` 函数，但是对应的 Paint Worklet 没有被注册（即没有调用 `RegisterPaintWorkletPainter`），`PaintWorkletPaintDispatcher` 将无法找到对应的 painter，导致绘制失败。用户可能会看到一个空白的区域或者默认的背景色。

2. **Worklet ID 不匹配:**  在创建 `PaintWorkletJob` 时，指定的 worklet ID 与已注册的 painter 的 worklet ID 不匹配。这会导致 `PaintWorkletPaintDispatcher` 找不到合适的 painter 来处理任务，同样会造成绘制失败。

3. **在错误的线程调用:** 虽然测试中模拟了多线程环境，但在实际开发中，如果在不正确的线程上调用 `PaintWorkletPaintDispatcher` 的方法，可能会导致线程安全问题或程序崩溃。

4. **假设同步完成:** 开发者可能会错误地认为 `DispatchWorklets` 方法是同步执行的，并直接使用绘制结果。然而，Paint Worklet 的执行是异步的，需要通过回调函数来获取结果。如果未正确处理异步操作，可能会导致数据不一致或其他问题。

总而言之，`paint_worklet_paint_dispatcher_test.cc` 通过各种测试用例，细致地验证了 `PaintWorkletPaintDispatcher` 在处理 CSS Paint Worklet 时的核心功能，确保了该组件的稳定性和正确性，从而保证了浏览器能够正确渲染使用了 CSS Paint Worklet 的网页内容。

### 提示词
```
这是目录为blink/renderer/platform/graphics/paint_worklet_paint_dispatcher_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/graphics/paint_worklet_paint_dispatcher.h"

#include "base/functional/bind.h"
#include "base/run_loop.h"
#include "base/task/single_thread_task_runner.h"
#include "cc/paint/paint_worklet_job.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/platform/scheduler/test/renderer_scheduler_test_support.h"
#include "third_party/blink/renderer/platform/scheduler/public/non_main_thread.h"
#include "third_party/blink/renderer/platform/scheduler/public/thread_type.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"

using ::testing::_;
using ::testing::NiceMock;
using ::testing::Return;

namespace blink {
namespace {
// We need a thread (or multiple threads) for the (mock) worklets to run on.
std::unique_ptr<NonMainThread> CreateTestThread(const char* name) {
  return NonMainThread::CreateThread(
      ThreadCreationParams(ThreadType::kTestThread).SetThreadNameForTest(name));
}

class PaintWorkletPaintDispatcherAsyncTest : public ::testing::Test {
 public:
  PlatformPaintWorkletLayerPainter::DoneCallback CreateTestCompleteCallback() {
    return base::BindOnce(
        &PaintWorkletPaintDispatcherAsyncTest::VerifyResultAndFinish,
        base::Unretained(this));
  }

  // Allows a test to block on |VerifyResultAndFinish| being called. If a
  // PaintWorkletPaintDispatcherAsyncTest test times out, it likely means the
  // callback created by |CreateTestCompleteCallback| was never posted by the
  // worklet thread.
  void WaitForTestCompletion() { run_loop_.Run(); }

 private:
  void VerifyResultAndFinish(cc::PaintWorkletJobMap results) {
    run_loop_.Quit();
  }

  test::TaskEnvironment task_environment_;
  base::RunLoop run_loop_;
};

class MockPaintWorkletPainter
    : public GarbageCollected<MockPaintWorkletPainter>,
      public PaintWorkletPainter {
 public:
  MockPaintWorkletPainter(int worklet_id) {
    ON_CALL(*this, GetWorkletId).WillByDefault(Return(worklet_id));
  }
  ~MockPaintWorkletPainter() override = default;

  MOCK_CONST_METHOD0(GetWorkletId, int());
  MOCK_METHOD2(Paint,
               PaintRecord(const cc::PaintWorkletInput*,
                           const cc::PaintWorkletJob::AnimatedPropertyValues&));
};

class MockPaintWorkletInput : public cc::PaintWorkletInput {
 public:
  explicit MockPaintWorkletInput(int worklet_id) {
    ON_CALL(*this, WorkletId).WillByDefault(Return(worklet_id));
  }
  ~MockPaintWorkletInput() override = default;

  MOCK_CONST_METHOD0(GetSize, gfx::SizeF());
  MOCK_CONST_METHOD0(WorkletId, int());
  MOCK_CONST_METHOD0(GetPropertyKeys,
                     const std::vector<PaintWorkletInput::PropertyKey>&());
  MOCK_CONST_METHOD0(IsCSSPaintWorkletInput, bool());
};

cc::PaintWorkletInput* AddPaintWorkletInputToMap(cc::PaintWorkletJobMap& map,
                                                 int worklet_id) {
  if (!map.contains(worklet_id))
    map[worklet_id] = base::MakeRefCounted<cc::PaintWorkletJobVector>();
  auto input = base::MakeRefCounted<MockPaintWorkletInput>(worklet_id);
  MockPaintWorkletInput* input_ptr = input.get();
  cc::PaintWorkletJob::AnimatedPropertyValues animated_property_values;
  map[worklet_id]->data.emplace_back(/*layer_id=*/1, std::move(input),
                                     animated_property_values);
  return input_ptr;
}

class PaintWorkletPaintDispatcherMainThread
    : public PaintWorkletPaintDispatcher {
 protected:
  scoped_refptr<base::SingleThreadTaskRunner> GetCompositorTaskRunner()
      override {
    // There is no compositor thread in testing, so return the current thread.
    return scheduler::GetSingleThreadTaskRunnerForTesting();
  }
};

}  // namespace

TEST_F(PaintWorkletPaintDispatcherAsyncTest, DispatchedWorkletIsPainted) {
  auto dispatcher = std::make_unique<PaintWorkletPaintDispatcherMainThread>();

  const int worklet_id = 4;
  MockPaintWorkletPainter* mock_painter =
      MakeGarbageCollected<NiceMock<MockPaintWorkletPainter>>(worklet_id);
  std::unique_ptr<NonMainThread> worklet_thread =
      CreateTestThread("WorkletThread");
  dispatcher->RegisterPaintWorkletPainter(mock_painter,
                                          worklet_thread->GetTaskRunner());

  cc::PaintWorkletJobMap job_map;
  Vector<cc::PaintWorkletInput*> inputs = {
      AddPaintWorkletInputToMap(job_map, worklet_id),
      AddPaintWorkletInputToMap(job_map, worklet_id),
      AddPaintWorkletInputToMap(job_map, worklet_id),
  };

  // The input jobs match the registered painter, so we should see a series of
  // calls to Paint() with the appropriate PaintWorkletInputs.
  for (cc::PaintWorkletInput* input : inputs)
    EXPECT_CALL(*mock_painter, Paint(input, _)).Times(1);
  dispatcher->DispatchWorklets(job_map, CreateTestCompleteCallback());

  WaitForTestCompletion();
}

TEST_F(PaintWorkletPaintDispatcherAsyncTest, DispatchCompletesWithNoPainters) {
  auto dispatcher = std::make_unique<PaintWorkletPaintDispatcherMainThread>();

  cc::PaintWorkletJobMap job_map;
  AddPaintWorkletInputToMap(job_map, /*worklet_id=*/2);
  AddPaintWorkletInputToMap(job_map, /*worklet_id=*/2);
  AddPaintWorkletInputToMap(job_map, /*worklet_id=*/5);

  // There are no painters to dispatch to, matching or otherwise, but the
  // callback should still be called so this test passes if it doesn't hang on
  // WaitForTestCompletion.
  dispatcher->DispatchWorklets(job_map, CreateTestCompleteCallback());

  WaitForTestCompletion();
}

TEST_F(PaintWorkletPaintDispatcherAsyncTest, DispatchHandlesEmptyInput) {
  auto dispatcher = std::make_unique<PaintWorkletPaintDispatcherMainThread>();

  const int worklet_id = 4;
  auto* mock_painter =
      MakeGarbageCollected<NiceMock<MockPaintWorkletPainter>>(worklet_id);
  std::unique_ptr<NonMainThread> worklet_thread =
      CreateTestThread("WorkletThread");
  dispatcher->RegisterPaintWorkletPainter(mock_painter,
                                          worklet_thread->GetTaskRunner());

  cc::PaintWorkletJobMap job_map;

  // The input job map is empty, so we should see no calls to Paint but the
  // callback should still be called.
  EXPECT_CALL(*mock_painter, Paint(_, _)).Times(0);
  dispatcher->DispatchWorklets(job_map, CreateTestCompleteCallback());

  WaitForTestCompletion();
}

TEST_F(PaintWorkletPaintDispatcherAsyncTest, DispatchSelectsCorrectPainter) {
  auto dispatcher = std::make_unique<PaintWorkletPaintDispatcherMainThread>();

  const int first_worklet_id = 2;
  auto* first_mock_painter =
      MakeGarbageCollected<NiceMock<MockPaintWorkletPainter>>(first_worklet_id);
  std::unique_ptr<NonMainThread> first_thread =
      CreateTestThread("WorkletThread1");
  dispatcher->RegisterPaintWorkletPainter(first_mock_painter,
                                          first_thread->GetTaskRunner());

  const int second_worklet_id = 3;
  auto* second_mock_painter =
      MakeGarbageCollected<NiceMock<MockPaintWorkletPainter>>(
          second_worklet_id);
  std::unique_ptr<NonMainThread> second_thread =
      CreateTestThread("WorkletThread2");
  dispatcher->RegisterPaintWorkletPainter(second_mock_painter,
                                          second_thread->GetTaskRunner());

  cc::PaintWorkletJobMap job_map;
  Vector<cc::PaintWorkletInput*> inputs{
      AddPaintWorkletInputToMap(job_map, second_worklet_id),
      AddPaintWorkletInputToMap(job_map, second_worklet_id),
  };

  // Paint should only be called on the correct painter, with our input.
  EXPECT_CALL(*first_mock_painter, Paint(_, _)).Times(0);
  for (cc::PaintWorkletInput* input : inputs) {
    EXPECT_CALL(*second_mock_painter, Paint(input, _)).Times(1);
  }
  dispatcher->DispatchWorklets(job_map, CreateTestCompleteCallback());

  WaitForTestCompletion();
}

TEST_F(PaintWorkletPaintDispatcherAsyncTest, DispatchIgnoresNonMatchingInput) {
  auto dispatcher = std::make_unique<PaintWorkletPaintDispatcherMainThread>();

  const int worklet_id = 2;
  auto* mock_painter =
      MakeGarbageCollected<NiceMock<MockPaintWorkletPainter>>(worklet_id);
  std::unique_ptr<NonMainThread> worklet_thread =
      CreateTestThread("WorkletThread");
  dispatcher->RegisterPaintWorkletPainter(mock_painter,
                                          worklet_thread->GetTaskRunner());

  cc::PaintWorkletJobMap job_map;
  const int non_registered_worklet_id = 3;
  cc::PaintWorkletInput* matching_input =
      AddPaintWorkletInputToMap(job_map, worklet_id);
  AddPaintWorkletInputToMap(job_map, non_registered_worklet_id);

  // Only one job matches, so our painter should only be called once, and the
  // callback should still be called.
  EXPECT_CALL(*mock_painter, Paint(matching_input, _)).Times(1);
  dispatcher->DispatchWorklets(job_map, CreateTestCompleteCallback());

  WaitForTestCompletion();
}

TEST_F(PaintWorkletPaintDispatcherAsyncTest,
       DispatchCorrectlyAssignsInputsToMultiplePainters) {
  auto dispatcher = std::make_unique<PaintWorkletPaintDispatcherMainThread>();

  const int first_worklet_id = 5;
  auto* first_mock_painter =
      MakeGarbageCollected<NiceMock<MockPaintWorkletPainter>>(first_worklet_id);
  std::unique_ptr<NonMainThread> first_thread =
      CreateTestThread("WorkletThread1");
  dispatcher->RegisterPaintWorkletPainter(first_mock_painter,
                                          first_thread->GetTaskRunner());

  const int second_worklet_id = 1;
  auto* second_mock_painter =
      MakeGarbageCollected<NiceMock<MockPaintWorkletPainter>>(
          second_worklet_id);
  std::unique_ptr<NonMainThread> second_thread =
      CreateTestThread("WorkletThread2");
  dispatcher->RegisterPaintWorkletPainter(second_mock_painter,
                                          second_thread->GetTaskRunner());

  cc::PaintWorkletJobMap job_map;
  cc::PaintWorkletInput* first_input =
      AddPaintWorkletInputToMap(job_map, first_worklet_id);
  cc::PaintWorkletInput* second_input =
      AddPaintWorkletInputToMap(job_map, second_worklet_id);

  // Both painters should be called with the correct inputs.
  EXPECT_CALL(*first_mock_painter, Paint(first_input, _)).Times(1);
  EXPECT_CALL(*second_mock_painter, Paint(second_input, _)).Times(1);
  dispatcher->DispatchWorklets(job_map, CreateTestCompleteCallback());

  WaitForTestCompletion();
}

TEST_F(PaintWorkletPaintDispatcherAsyncTest,
       HasOngoingDispatchIsTrackedCorrectly) {
  auto dispatcher = std::make_unique<PaintWorkletPaintDispatcherMainThread>();

  const int first_worklet_id = 2;
  auto* first_mock_painter =
      MakeGarbageCollected<NiceMock<MockPaintWorkletPainter>>(first_worklet_id);
  std::unique_ptr<NonMainThread> first_thread =
      CreateTestThread("WorkletThread1");
  dispatcher->RegisterPaintWorkletPainter(first_mock_painter,
                                          first_thread->GetTaskRunner());

  // Nothing going on; no dispatch.
  EXPECT_FALSE(dispatcher->HasOngoingDispatch());

  cc::PaintWorkletJobMap job_map;
  AddPaintWorkletInputToMap(job_map, first_worklet_id);

  dispatcher->DispatchWorklets(job_map, CreateTestCompleteCallback());
  EXPECT_TRUE(dispatcher->HasOngoingDispatch());

  WaitForTestCompletion();
  EXPECT_FALSE(dispatcher->HasOngoingDispatch());
}

}  // namespace blink
```