Response:
The user wants me to summarize the functionality of the provided C++ code snippet from a Chromium Blink engine test file. I need to identify the main features being tested and highlight any connections to web technologies like JavaScript, HTML, and CSS. I should also look for examples of logical reasoning in the tests (with input/output examples), common user/programming errors being tested, and how a user's actions could lead to the tested code being executed.

Here's a plan:
1. **Identify Core Functionality:**  Look for keywords and patterns in the test names and code that indicate the primary features being tested. The prevalence of "Hibernation" suggests this is a key area.
2. **Relate to Web Technologies:** Consider how "hibernation" and related canvas behaviors manifest in a web browser and how they might be triggered by user interactions or JavaScript/HTML/CSS.
3. **Analyze Logical Reasoning:**  Examine the test structure for setup (e.g., `CreateContext`, `SetVisibilityState`) and assertions (e.g., `EXPECT_TRUE`, `EXPECT_FALSE`, `ExpectUniqueSample`). Infer the expected input and output based on these.
4. **Identify User/Programming Errors:**  Look for tests that simulate error conditions or test edge cases that developers might encounter.
5. **Trace User Actions:**  Imagine a user interacting with a web page containing a canvas element and how their actions might trigger the code being tested.
6. **Synthesize the Summary:** Combine the findings from the previous steps into a concise description of the code's functionality.
这是 `blink/renderer/modules/canvas/canvas2d/canvas_rendering_context_2d_test.cc` 文件的第 4 部分，主要关注 `CanvasRenderingContext2D` 的**加速模式**下的特定功能测试，特别是与**画布休眠 (Hibernation)** 相关的测试，以及资源管理和状态恢复等方面的测试。

**它的主要功能可以归纳为:**

* **画布休眠 (Hibernation) 机制的测试:**
    * **进入休眠状态:** 测试在页面进入后台 (`SetVisibilityState(kHidden)`) 时，画布是否正确地进入休眠状态，降低资源消耗 (切换到 CPU 栅格化 `RasterMode::kCPU`)。
    * **退出休眠状态:** 测试在页面回到前台 (`SetVisibilityState(kVisible)`) 时，画布是否能正常退出休眠状态 (切换回 GPU 栅格化 `RasterMode::kGPU`)。
    * **休眠过程中的取消:** 测试在休眠尚未完成时，如果页面重新回到前台或发生 `TearDownHost` (例如关闭标签页)，休眠是否会被正确取消。
    * **休眠状态下的操作限制:** 测试在休眠状态下，某些操作 (例如 `PrepareTransferableResource`) 是否会失败。
    * **休眠状态下的快照:** 测试在休眠状态下调用 `getImage()` 等方法获取画布快照，是否能正常工作，并且快照是非加速的。
    * **带未关闭图层的休眠:** 测试当画布存在未关闭的图层时进行休眠和恢复，是否能正确处理图层状态。
    * **没有资源提供者时不休眠:** 测试当画布没有关联的资源提供者时，是否不会触发休眠。
* **资源回收 (Resource Recycling) 的测试:**
    * 测试当画布资源不再被使用时，是否会被回收以供后续绘制使用，从而优化内存占用。
    * 测试在页面隐藏时，资源回收机制是否会受到影响。
* **属性同步 (Property Pushing) 的测试:**
    * 测试在页面可见性发生变化后，画布的属性 (例如是否需要重新设置资源) 是否能正确同步到合成层。
* **低延迟模式 (Low Latency) 的测试:**
    * 测试低延迟模式下的画布是否不是单缓冲的。
* **`drawImage` 方法与视频帧的交互:**
    * 测试使用 `drawImage` 绘制视频帧时是否会触发画布的刷新 (flush)。
* **`flush` 和 `putImageData` 操作对裁剪栈 (Clip Stack) 的影响:**
    * 测试在调用 `flush()` 和 `putImageData()` 方法后，画布的裁剪栈是否能正确恢复。
* **禁用加速 (Disable Acceleration) 的测试:**
    * 测试禁用画布硬件加速后，是否能正确切换到 CPU 栅格化。
    * 测试禁用加速时，是否能保留已有的栅格化内容和录制的操作。

**与 JavaScript, HTML, CSS 的功能关系及举例说明:**

* **HTML `<canvas>` 元素:** 这些测试直接关联到 HTML 中的 `<canvas>` 元素。通过 JavaScript 获取 `<canvas>` 元素的 2D 渲染上下文 (`getContext('2d')`) 后，就可以使用 `CanvasRenderingContext2D` 接口进行绘制操作。
    * **例子:**  在 HTML 中定义一个 `<canvas>` 元素 `<canvas id="myCanvas" width="200" height="100"></canvas>`，JavaScript 代码可以通过 `document.getElementById('myCanvas')` 获取该元素，并调用 `getContext('2d')` 获取测试中操作的 `Context2D()` 对象。
* **JavaScript `CanvasRenderingContext2D` API:**  测试中的 `fillRect()`, `drawImage()`, `beginLayer()`, `endLayer()`, `getImage()`, `putImageData()`, `translate()`, `save()`, `restore()` 等方法都是 `CanvasRenderingContext2D` 接口提供的 JavaScript API。
    * **例子:**  JavaScript 代码 `ctx.fillRect(10, 10, 50, 50);` 会在画布上绘制一个矩形，测试代码会模拟这些 JavaScript 调用来验证底层实现。
* **CSS 控制画布样式:** 虽然测试代码本身不直接涉及 CSS，但 CSS 可以控制 `<canvas>` 元素的大小、位置等样式，这些样式会影响画布的渲染和资源管理。
    * **例子:**  CSS 代码 `canvas { width: 300px; height: 200px; }` 可以设置画布的尺寸，这可能会影响画布的内存占用和休眠行为。
* **页面可见性 API:** 测试中使用的 `GetDocument().GetPage()->SetVisibilityState()` 模拟了页面可见性的变化，这与浏览器的 Page Visibility API 相关。JavaScript 可以监听 `visibilitychange` 事件来感知页面可见性的变化。
    * **例子:** JavaScript 可以使用 `document.addEventListener('visibilitychange', function() { ... });` 来监听页面可见性变化，这与测试中模拟的 `kHidden` 和 `kVisible` 状态对应。

**逻辑推理的假设输入与输出:**

**假设输入:** 页面从前台切换到后台 (`GetDocument().GetPage()->SetVisibilityState(mojom::blink::PageVisibilityState::kHidden, /*is_initial_state=*/false);`)。

**输出:**  期望 `CanvasElement().GetRasterMode()` 返回 `RasterMode::kCPU`，表明画布已进入休眠状态并切换到 CPU 栅格化。 相应的，相关的性能指标 `Blink.Canvas.HibernationEvents` 应该记录 `kHibernationScheduled` 事件。

**用户或编程常见的使用错误举例说明:**

* **未正确处理页面可见性变化导致的画布状态变化:**  开发者可能没有考虑到页面进入后台时画布会进入休眠状态，导致在后台进行绘制操作时出现意外行为或者性能问题。
    * **错误例子:**  开发者在 `visibilitychange` 事件触发且 `document.hidden` 为 `true` 时，仍然假设画布处于激活状态并进行高频绘制操作，可能会导致性能下降。
* **在休眠状态下调用 `PrepareTransferableResource`:** 开发者可能没有意识到在画布休眠期间某些操作是受限的。
    * **错误例子:**  在页面进入后台后，尝试调用 `canvas.getContext('2d').transferToImageBitmap()` 将画布内容转移到 `ImageBitmap` 对象，此时如果画布正在休眠，该操作可能会失败。
* **未正确管理画布资源，导致内存泄漏:** 开发者可能没有及时释放不再使用的画布资源，尤其是在加速模式下，GPU 资源的泄漏会更加严重。
    * **错误例子:**  频繁创建和销毁 `<canvas>` 元素，但没有显式释放相关的资源，可能导致内存占用持续增加。

**用户操作如何一步步的到达这里，作为调试线索:**

1. **用户打开一个包含 `<canvas>` 元素的网页。**
2. **JavaScript 代码获取了该 `<canvas>` 元素的 2D 渲染上下文。**
3. **用户与页面交互，可能触发了画布上的绘制操作 (例如，鼠标移动绘制线条)。**
4. **用户切换到另一个应用或标签页，导致当前页面进入后台 (对应测试中的 `SetVisibilityState(kHidden)`)。**  这时，浏览器可能会尝试将后台页面的画布置于休眠状态以节省资源。
5. **用户又切换回原来的页面 (对应测试中的 `SetVisibilityState(kVisible)`)。**  浏览器会尝试唤醒休眠的画布。
6. **在调试过程中，开发者可能会关注画布的栅格化模式 (`GetRasterMode()`)、资源使用情况以及休眠状态 (`IsHibernating()`)，以便了解画布的性能和资源管理情况。** 测试代码模拟了这些状态的检查，帮助开发者验证画布休眠机制的正确性。

总而言之，这部分测试代码主要验证了 Blink 引擎中 `CanvasRenderingContext2D` 在加速模式下，特别是在画布休眠机制方面的功能正确性、资源管理以及状态转换的可靠性。这些测试确保了在各种场景下，画布能够正确地进入和退出休眠状态，有效地管理 GPU 资源，并在页面可见性变化时保持状态的同步。

### 提示词
```
这是目录为blink/renderer/modules/canvas/canvas2d/canvas_rendering_context_2d_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第4部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
ibilityState(
      mojom::blink::PageVisibilityState::kVisible,
      /*is_initial_state=*/false);

  // Move the page to the background again and verify that hibernation is not
  // newly scheduled, as the hibernation scheduled on the first backgrounding is
  // still pending.
  {
    base::HistogramTester histogram_tester;
    GetDocument().GetPage()->SetVisibilityState(
        mojom::blink::PageVisibilityState::kHidden,
        /*is_initial_state=*/false);

    histogram_tester.ExpectUniqueSample(
        "Blink.Canvas.HibernationEvents",
        CanvasHibernationHandler::HibernationEvent::kHibernationScheduled, 0);
    EXPECT_FALSE(handler.IsHibernating());
  }

  // Run the task that initiates hibernation and verify that hibernation
  // triggers.
  ThreadScheduler::Current()
      ->ToMainThreadScheduler()
      ->StartIdlePeriodForTesting();
  blink::test::RunPendingTasks();

  EXPECT_EQ(CanvasElement().GetRasterMode(), RasterMode::kCPU);
  EXPECT_TRUE(handler.IsHibernating());
  EXPECT_TRUE(CanvasElement().IsResourceValid());

  // Verify that coming to the foreground ends hibernation synchronously.
  {
    base::HistogramTester histogram_tester;
    GetDocument().GetPage()->SetVisibilityState(
        mojom::blink::PageVisibilityState::kVisible,
        /*is_initial_state=*/false);

    histogram_tester.ExpectUniqueSample(
        "Blink.Canvas.HibernationEvents",
        CanvasHibernationHandler::HibernationEvent::kHibernationEndedNormally,
        1);
    EXPECT_EQ(CanvasElement().GetRasterMode(), RasterMode::kGPU);
    EXPECT_FALSE(handler.IsHibernating());
    EXPECT_TRUE(CanvasElement().IsResourceValid());
  }
}

TEST_P(CanvasRenderingContext2DTestAccelerated, TeardownEndsHibernation) {
  base::test::ScopedFeatureList scoped_feature_list;
  scoped_feature_list.InitWithFeatures({features::kCanvas2DHibernation}, {});

  CreateContext(kNonOpaque);
  CanvasElement().GetOrCreateCanvasResourceProvider(RasterModeHint::kPreferGPU);
  EXPECT_EQ(CanvasElement().GetRasterMode(), RasterMode::kGPU);

  auto& handler = CHECK_DEREF(CanvasElement().GetHibernationHandler());

  // Install a minimal delay for testing to ensure that the test remains fast
  // to execute.
  handler.SetBeforeCompressionDelayForTesting(base::Microseconds(10));

  EXPECT_FALSE(handler.IsHibernating());

  // Verify that going to the background triggers hibernation asynchronously.
  {
    base::HistogramTester histogram_tester;
    GetDocument().GetPage()->SetVisibilityState(
        mojom::blink::PageVisibilityState::kHidden,
        /*is_initial_state=*/false);

    histogram_tester.ExpectUniqueSample(
        "Blink.Canvas.HibernationEvents",
        CanvasHibernationHandler::HibernationEvent::kHibernationScheduled, 1);
    EXPECT_FALSE(handler.IsHibernating());
  }

  // Run the task that initiates hibernation, which has been posted as an idle
  // task.
  ThreadScheduler::Current()
      ->ToMainThreadScheduler()
      ->StartIdlePeriodForTesting();
  blink::test::RunPendingTasks();

  EXPECT_EQ(CanvasElement().GetRasterMode(), RasterMode::kCPU);
  EXPECT_TRUE(handler.IsHibernating());
  EXPECT_TRUE(CanvasElement().IsResourceValid());

  // Verify that tearing down the host ends hibernation synchronously.
  {
    base::HistogramTester histogram_tester;
    TearDownHost();
    histogram_tester.ExpectUniqueSample(
        "Blink.Canvas.HibernationEvents",
        CanvasHibernationHandler::HibernationEvent::
            kHibernationEndedWithTeardown,
        1);
  }
}

TEST_P(CanvasRenderingContext2DTestAccelerated,
       TeardownWhileHibernationIsPendingAbortsHibernation) {
  base::test::ScopedFeatureList scoped_feature_list;
  scoped_feature_list.InitWithFeatures({features::kCanvas2DHibernation}, {});

  CreateContext(kNonOpaque);
  CanvasElement().GetOrCreateCanvasResourceProvider(RasterModeHint::kPreferGPU);
  EXPECT_EQ(CanvasElement().GetRasterMode(), RasterMode::kGPU);

  auto& handler = CHECK_DEREF(CanvasElement().GetHibernationHandler());

  // Install a minimal delay for testing to ensure that the test remains fast
  // to execute.
  handler.SetBeforeCompressionDelayForTesting(base::Microseconds(10));

  EXPECT_FALSE(handler.IsHibernating());

  // Verify that going to the background triggers hibernation asynchronously.
  {
    base::HistogramTester histogram_tester;
    GetDocument().GetPage()->SetVisibilityState(
        mojom::blink::PageVisibilityState::kHidden,
        /*is_initial_state=*/false);

    histogram_tester.ExpectUniqueSample(
        "Blink.Canvas.HibernationEvents",
        CanvasHibernationHandler::HibernationEvent::kHibernationScheduled, 1);
    EXPECT_FALSE(handler.IsHibernating());
  }

  // Tear down the host while hibernation is pending.
  TearDownHost();

  // Verify that running the hibernation task aborts hibernation (and doesn't
  // crash by calling into the destroyed state).
  {
    base::HistogramTester histogram_tester;

    // Run the task that initiates hibernation, which has been posted as an idle
    // task.
    ThreadScheduler::Current()
        ->ToMainThreadScheduler()
        ->StartIdlePeriodForTesting();
    blink::test::RunPendingTasks();

    histogram_tester.ExpectUniqueSample(
        "Blink.Canvas.HibernationEvents",
        CanvasHibernationHandler::HibernationEvent::
            kHibernationAbortedDueToDestructionWhileHibernatePending,
        1);
  }
}

TEST_P(CanvasRenderingContext2DTestAccelerated,
       ForegroundingWhileHibernationIsPendingAbortsHibernation) {
  base::test::ScopedFeatureList scoped_feature_list;
  scoped_feature_list.InitWithFeatures({features::kCanvas2DHibernation}, {});

  CreateContext(kNonOpaque);
  CanvasElement().GetOrCreateCanvasResourceProvider(RasterModeHint::kPreferGPU);
  EXPECT_EQ(CanvasElement().GetRasterMode(), RasterMode::kGPU);

  auto& handler = CHECK_DEREF(CanvasElement().GetHibernationHandler());

  // Install a minimal delay for testing to ensure that the test remains fast
  // to execute.
  handler.SetBeforeCompressionDelayForTesting(base::Microseconds(10));

  EXPECT_FALSE(handler.IsHibernating());

  // Verify that going to the background triggers hibernation asynchronously.
  {
    base::HistogramTester histogram_tester;
    GetDocument().GetPage()->SetVisibilityState(
        mojom::blink::PageVisibilityState::kHidden,
        /*is_initial_state=*/false);

    histogram_tester.ExpectUniqueSample(
        "Blink.Canvas.HibernationEvents",
        CanvasHibernationHandler::HibernationEvent::kHibernationScheduled, 1);
    EXPECT_FALSE(handler.IsHibernating());
  }

  // Foreground the page while hibernation is pending.
  GetDocument().GetPage()->SetVisibilityState(
      mojom::blink::PageVisibilityState::kVisible,
      /*is_initial_state=*/false);

  // Verify that running the hibernation task aborts hibernation due to the
  // page having been foregrounded.
  {
    base::HistogramTester histogram_tester;

    // Run the task that initiates hibernation, which has been posted as an idle
    // task.
    ThreadScheduler::Current()
        ->ToMainThreadScheduler()
        ->StartIdlePeriodForTesting();
    blink::test::RunPendingTasks();

    histogram_tester.ExpectUniqueSample(
        "Blink.Canvas.HibernationEvents",
        CanvasHibernationHandler::HibernationEvent::
            kHibernationAbortedDueToVisibilityChange,
        1);
    EXPECT_EQ(CanvasElement().GetRasterMode(), RasterMode::kGPU);
    EXPECT_FALSE(handler.IsHibernating());
    EXPECT_TRUE(CanvasElement().IsResourceValid());
  }
}

TEST_P(CanvasRenderingContext2DTestAccelerated, ContextLossAbortsHibernation) {
  base::test::ScopedFeatureList scoped_feature_list;
  scoped_feature_list.InitWithFeatures({features::kCanvas2DHibernation}, {});

  CreateContext(kNonOpaque);

  // For CanvasResourceHost to check for the GPU context being lost as part of
  // checking resource validity, it is necessary to have both accelerated
  // raster/compositing and a CC layer.
  ASSERT_TRUE(SetUpFullAccelerationAndCcLayer(CanvasElement()));

  EXPECT_TRUE(CanvasElement().IsResourceValid());

  auto& handler = CHECK_DEREF(CanvasElement().GetHibernationHandler());

  // Install a minimal delay for testing to ensure that the test remains fast
  // to execute.
  handler.SetBeforeCompressionDelayForTesting(base::Microseconds(10));

  EXPECT_FALSE(handler.IsHibernating());

  // Simulate GPU context loss.
  test_context_provider_->TestContextGL()->set_context_lost(true);

  // Verify that going to the background triggers hibernation asynchronously.
  {
    base::HistogramTester histogram_tester;
    GetDocument().GetPage()->SetVisibilityState(
        mojom::blink::PageVisibilityState::kHidden,
        /*is_initial_state=*/false);

    histogram_tester.ExpectUniqueSample(
        "Blink.Canvas.HibernationEvents",
        CanvasHibernationHandler::HibernationEvent::kHibernationScheduled, 1);
    EXPECT_FALSE(handler.IsHibernating());
  }

  // Verify that running the hibernation task aborts hibernation due to the
  // GPU context having been lost.
  {
    base::HistogramTester histogram_tester;

    // Run the task that initiates hibernation, which has been posted as an idle
    // task.
    ThreadScheduler::Current()
        ->ToMainThreadScheduler()
        ->StartIdlePeriodForTesting();
    blink::test::RunPendingTasks();

    histogram_tester.ExpectUniqueSample(
        "Blink.Canvas.HibernationEvents",
        CanvasHibernationHandler::HibernationEvent::
            kHibernationAbortedDueGpuContextLoss,
        1);
    EXPECT_EQ(CanvasElement().GetRasterMode(), RasterMode::kCPU);
    EXPECT_FALSE(handler.IsHibernating());
    EXPECT_FALSE(CanvasElement().IsResourceValid());
  }
}

TEST_P(CanvasRenderingContext2DTestAccelerated, ResourceRecycling) {
  CreateContext(kNonOpaque);

  viz::TransferableResource resources[3];
  viz::ReleaseCallback callbacks[3];
  cc::PaintFlags flags;

  Context2D()->fillRect(3, 3, 1, 1);

  // Invoking PrepareTransferableResource() has a precondition that a CC layer
  // be present.
  CanvasElement().GetOrCreateCcLayerIfNeeded();

  ASSERT_TRUE(CanvasElement().PrepareTransferableResource(&resources[0],
                                                          &callbacks[0]));

  Context2D()->fillRect(3, 3, 1, 1);

  ASSERT_TRUE(CanvasElement().PrepareTransferableResource(&resources[1],
                                                          &callbacks[1]));
  EXPECT_NE(resources[0].mailbox(), resources[1].mailbox());

  // Now release the first resource and draw again. It should be reused due to
  // recycling.
  std::move(callbacks[0]).Run(gpu::SyncToken(), false);

  Context2D()->fillRect(3, 3, 1, 1);

  ASSERT_TRUE(CanvasElement().PrepareTransferableResource(&resources[2],
                                                          &callbacks[2]));
  EXPECT_EQ(resources[0].mailbox(), resources[2].mailbox());
}

TEST_P(CanvasRenderingContext2DTestAccelerated,
       NoResourceRecyclingWhenPageHidden) {
  CreateContext(kNonOpaque);

  EXPECT_EQ(test_context_provider_->TestContextGL()->NumTextures(), 0u);

  Context2D()->fillRect(3, 3, 1, 1);

  EXPECT_EQ(test_context_provider_->TestContextGL()->NumTextures(), 1u);

  // Invoking PrepareTransferableResource() has a precondition that a CC layer
  // be present.
  CanvasElement().GetOrCreateCcLayerIfNeeded();

  viz::TransferableResource resources[2];
  viz::ReleaseCallback callbacks[2];

  // Emulate sending the canvas' resource to the display compositor.
  ASSERT_TRUE(CanvasElement().PrepareTransferableResource(&resources[0],
                                                          &callbacks[0]));

  // Write to the canvas.
  Context2D()->fillRect(3, 3, 1, 1);

  // Note that the write did not in of itself trigger copy-on-write since
  // rasterization has not occurred yet.
  EXPECT_EQ(test_context_provider_->TestContextGL()->NumTextures(), 1u);

  // Emulate sending the canvas' resource to the display compositor, which
  // forces copy-on-write before rasterization as the display compositor has a
  // read ref on the first resource.
  ASSERT_TRUE(CanvasElement().PrepareTransferableResource(&resources[1],
                                                          &callbacks[1]));
  EXPECT_NE(resources[0].mailbox(), resources[1].mailbox());
  EXPECT_EQ(test_context_provider_->TestContextGL()->NumTextures(), 2u);

  // Emulate the display compositor releasing the first resource. The released
  // resource should be saved for recycling (i.e., it should not be dropped).
  std::move(callbacks[0]).Run(gpu::SyncToken(), false);
  EXPECT_EQ(test_context_provider_->TestContextGL()->NumTextures(), 2u);

  // Move the page to the background. This should cause resource recycling to be
  // disabled and the previously-released resource to now be dropped.
  GetDocument().GetPage()->SetVisibilityState(
      mojom::blink::PageVisibilityState::kHidden,
      /*is_initial_state=*/false);
  EXPECT_EQ(test_context_provider_->TestContextGL()->NumTextures(), 1u);

  // Emulate the display compositor releasing the second resource. The resource
  // should not be dropped because it's the current render target for the canvas
  // and so the canvas itself still has a reference on this resource. This
  // resource should be dropped only if the canvas is hibernated.
  std::move(callbacks[1]).Run(gpu::SyncToken(), false);
  EXPECT_EQ(test_context_provider_->TestContextGL()->NumTextures(), 1u);
}

TEST_P(CanvasRenderingContext2DTestAccelerated,
       PushPropertiesAfterVisibilityChange) {
  base::test::ScopedFeatureList feature_list;
  feature_list.InitWithFeatures({::features::kClearCanvasResourcesInBackground},
                                {features::kCanvas2DHibernation});

  CreateContext(kNonOpaque);

  ASSERT_TRUE(SetUpFullAccelerationAndCcLayer(CanvasElement()));

  GetDocument().GetPage()->SetVisibilityState(
      mojom::blink::PageVisibilityState::kHidden,
      /*is_initial_state=*/false);
  EXPECT_FALSE(CanvasElement().CcLayer()->needs_set_resource_for_testing());

  GetDocument().GetPage()->SetVisibilityState(
      mojom::blink::PageVisibilityState::kVisible,
      /*is_initial_state=*/false);
  EXPECT_TRUE(CanvasElement().CcLayer()->needs_set_resource_for_testing());
}

TEST_P(CanvasRenderingContext2DTestAccelerated,
       PrepareTransferableResourceFailsWhileHibernating) {
  base::test::ScopedFeatureList scoped_feature_list;
  scoped_feature_list.InitWithFeatures({features::kCanvas2DHibernation}, {});

  CreateContext(kNonOpaque);

  // Invoking PrepareTransferableResource() has a precondition that a CC layer
  // is present, while GPU compositing is necessary for hibernation to succeed.
  ASSERT_TRUE(SetUpFullAccelerationAndCcLayer(CanvasElement()));

  auto& handler = CHECK_DEREF(CanvasElement().GetHibernationHandler());

  // Install a minimal delay for testing to ensure that the test remains fast
  // to execute.
  handler.SetBeforeCompressionDelayForTesting(base::Microseconds(10));

  EXPECT_FALSE(handler.IsHibernating());

  // Verify that going to the background triggers hibernation asynchronously.
  {
    base::HistogramTester histogram_tester;
    GetDocument().GetPage()->SetVisibilityState(
        mojom::blink::PageVisibilityState::kHidden,
        /*is_initial_state=*/false);

    histogram_tester.ExpectUniqueSample(
        "Blink.Canvas.HibernationEvents",
        CanvasHibernationHandler::HibernationEvent::kHibernationScheduled, 1);
    EXPECT_FALSE(handler.IsHibernating());
  }

  // Run the task that initiates hibernation, which has been posted as an idle
  // task.
  ThreadScheduler::Current()
      ->ToMainThreadScheduler()
      ->StartIdlePeriodForTesting();
  blink::test::RunPendingTasks();
  EXPECT_TRUE(handler.IsHibernating());

  // Verify that PrepareTransferableResource() fails while hibernating.
  viz::TransferableResource resource;
  viz::ReleaseCallback release_callback;
  EXPECT_FALSE(CanvasElement().PrepareTransferableResource(&resource,
                                                           &release_callback));
  EXPECT_TRUE(handler.IsHibernating());
  EXPECT_TRUE(CanvasElement().IsResourceValid());
}

TEST_P(CanvasRenderingContext2DTestAccelerated,
       CanvasDrawInBackgroundEndsHibernation) {
  base::test::ScopedFeatureList scoped_feature_list;
  scoped_feature_list.InitWithFeatures({features::kCanvas2DHibernation}, {});

  CreateContext(kNonOpaque);
  CanvasElement().GetOrCreateCanvasResourceProvider(RasterModeHint::kPreferGPU);

  auto& handler = CHECK_DEREF(CanvasElement().GetHibernationHandler());
  base::RunLoop run_loop;

  // Install a minimal delay for testing to ensure that the test remains fast
  // to execute.
  handler.SetBeforeCompressionDelayForTesting(base::Microseconds(10));

  // NOTE: It is necessary to install the quit closure before running tasks
  // below in order to avoid test flake, as it is possible that encoding occurs
  // on a background thread *before* we run the run loop to wait for encoding.
  // As long as the quit closure has been invoked as part of encoding in that
  // case, the run loop will immediately exit out when Run() is invoked
  // (otherwise it would spin until timing out).
  handler.SetOnEncodedCallbackForTesting(run_loop.QuitClosure());

  EXPECT_FALSE(handler.is_encoded());
  EXPECT_FALSE(handler.IsHibernating());

  // Hide the page to trigger the hibernation task.
  GetDocument().GetPage()->SetVisibilityState(
      mojom::blink::PageVisibilityState::kHidden,
      /*is_initial_state=*/false);

  // Hibernation is triggered asynchronously.
  EXPECT_FALSE(handler.is_encoded());
  EXPECT_FALSE(handler.IsHibernating());

  // Run the task that initiates hibernation, which has been posted as an idle
  // task.
  ThreadScheduler::Current()
      ->ToMainThreadScheduler()
      ->StartIdlePeriodForTesting();
  blink::test::RunPendingTasks();
  EXPECT_FALSE(CanvasElement().ResourceProvider());
  EXPECT_TRUE(handler.IsHibernating());

  // Wait for encoding to complete on a background thread.
  run_loop.Run();
  EXPECT_TRUE(handler.is_encoded());

  // Draw into the canvas while the page is backgrounded.
  Context2D()->fillRect(0, 0, 1, 1);

  // That draw should have caused hibernation to end and the encoded canvas to
  // be dropped.
  EXPECT_FALSE(handler.IsHibernating());
  EXPECT_FALSE(handler.is_encoded());
}

TEST_P(CanvasRenderingContext2DTestAccelerated,
       CanvasSnapshotWhileHibernating) {
  base::test::ScopedFeatureList scoped_feature_list;
  scoped_feature_list.InitWithFeatures({features::kCanvas2DHibernation}, {});

  CreateContext(kNonOpaque);
  ASSERT_TRUE(CanvasElement().GetOrCreateCanvasResourceProvider(
      RasterModeHint::kPreferGPU));
  ASSERT_EQ(CanvasElement().GetRasterMode(), RasterMode::kGPU);

  auto& handler = CHECK_DEREF(CanvasElement().GetHibernationHandler());
  base::RunLoop run_loop;

  // Install a minimal delay for testing to ensure that the test remains fast
  // to execute.
  handler.SetBeforeCompressionDelayForTesting(base::Microseconds(10));

  // NOTE: It is necessary to install the quit closure before running tasks
  // below in order to avoid test flake, as it is possible that encoding occurs
  // on a background thread *before* we run the run loop to wait for encoding.
  // As long as the quit closure has been invoked as part of encoding in that
  // case, the run loop will immediately exit out when Run() is invoked
  // (otherwise it would spin until timing out).
  handler.SetOnEncodedCallbackForTesting(run_loop.QuitClosure());

  ASSERT_FALSE(handler.is_encoded());
  ASSERT_FALSE(handler.IsHibernating());

  // Hide the page to trigger the hibernation task.
  GetDocument().GetPage()->SetVisibilityState(
      mojom::blink::PageVisibilityState::kHidden,
      /*is_initial_state=*/false);

  // Hibernation is triggered asynchronously.
  ASSERT_FALSE(handler.is_encoded());
  ASSERT_FALSE(handler.IsHibernating());

  // Run the task that initiates hibernation, which has been posted as an idle
  // task.
  ThreadScheduler::Current()
      ->ToMainThreadScheduler()
      ->StartIdlePeriodForTesting();
  blink::test::RunPendingTasks();

  ASSERT_FALSE(CanvasElement().ResourceProvider());
  ASSERT_TRUE(handler.IsHibernating());
  ASSERT_EQ(CanvasElement().GetRasterMode(), RasterMode::kCPU);

  // Wait for encoding to complete on a background thread.
  run_loop.Run();
  ASSERT_TRUE(handler.is_encoded());

  // Taking a snapshot of the canvas while hibernating should produce an
  // unaccelerated image.
  EXPECT_FALSE(Context2D()->GetImage(FlushReason::kTesting)->IsTextureBacked());

  // The action of taking the snapshot should not have impacted the state of
  // hibernation.
  EXPECT_EQ(CanvasElement().GetRasterMode(), RasterMode::kCPU);
  EXPECT_TRUE(handler.IsHibernating());
  EXPECT_TRUE(handler.is_encoded());
}

sk_sp<SkImage> CreateSkImage(int width, int height, SkColor color) {
  sk_sp<SkSurface> surface =
      SkSurfaces::Raster(SkImageInfo::MakeN32Premul(width, height));
  surface->getCanvas()->clear(color);
  return surface->makeImageSnapshot();
}

ImageBitmap* CreateImageBitmap(int width, int height, SkColor color) {
  return MakeGarbageCollected<ImageBitmap>(
      UnacceleratedStaticBitmapImage::Create(
          CreateSkImage(width, height, color)));
}

MATCHER_P(DrawImageRectOpIs, sk_image, "") {
  if (!ExplainMatchResult(PaintOpIs<DrawImageRectOp>(), arg, result_listener)) {
    return false;
  }
  const auto& draw_op = static_cast<const DrawImageRectOp&>(arg);
  SkBitmap lhs, rhs;
  draw_op.image.GetSwSkImage()->asLegacyBitmap(&lhs);
  sk_image->asLegacyBitmap(&rhs);
  if (!gfx::BitmapsAreEqual(lhs, rhs)) {
    *result_listener << "DrawImageRectOp has an unexpected image content";
    return false;
  }
  return true;
}

TEST_P(CanvasRenderingContext2DTestAccelerated, HibernationWithUnclosedLayer) {
  ScopedCanvas2dLayersForTest layer_feature{/*enabled=*/true};
  ScopedFeatureList scoped_feature_list(features::kCanvas2DHibernation);
  CreateContext(kNonOpaque);
  CanvasElement().SetPreferred2DRasterMode(RasterModeHint::kPreferGPU);

  gfx::Size size(100, 100);
  auto provider = std::make_unique<FakeCanvasResourceProvider>(
      SkImageInfo::MakeN32Premul(size.width(), size.height()),
      RasterModeHint::kPreferGPU, &CanvasElement(),
      CompositingMode::kSupportsDirectCompositing);

  // Recorded draw ops are resterized on hibernation. The provider gets replaced
  // when getting out of hibernation, so this mock will not see the later calls
  // to `RasterRecord`.
  cc::PaintRecord hibernation_raster;
  EXPECT_CALL(*provider, Snapshot(FlushReason::kHibernating, _)).Times(1);
  EXPECT_CALL(*provider, RasterRecord)
      .Times(1)
      .WillOnce(SaveArg<0>(&hibernation_raster));

  CanvasElement().SetResourceProviderForTesting(std::move(provider), size);

  ThreadScheduler::Current()->PostIdleTask(
      FROM_HERE, WTF::BindOnce(
                     [](CanvasRenderingContext2DTestAccelerated* fixture,
                        base::TimeTicks /*idleDeadline*/) {
                       NonThrowableExceptionState exception_state;

                       // Will be rasterized on hibernation.
                       fixture->Context2D()->fillRect(0, 0, 1, 1);

                       fixture->Context2D()->beginLayer(
                           fixture->GetScriptState(),
                           BeginLayerOptions::Create(), exception_state);

                       // Will be preserved as a paint op in hibernation.
                       fixture->Context2D()->fillRect(1, 1, 1, 1);

                       // Referred image should survive hibernation.
                       fixture->Context2D()->drawImage(
                           CreateImageBitmap(/*width=*/1, /*height=*/1,
                                             SK_ColorRED),          //
                           /*sx=*/0, /*sy=*/0, /*sw=*/1, /*sh*/ 1,  //
                           /*dx=*/0, /*dy=*/0, /*dw=*/1, /*dh=*/1,  //
                           exception_state);
                     },
                     WTF::Unretained(this)));
  blink::test::RunPendingTasks();

  // Hibernate the canvas. Hibernation is handled in a idle task.
  GetDocument().GetPage()->SetVisibilityState(
      mojom::blink::PageVisibilityState::kHidden, /*is_initial_state=*/false);
  ThreadScheduler::Current()
      ->ToMainThreadScheduler()
      ->StartIdlePeriodForTesting();
  blink::test::RunPendingTasks();

  // Hibernating should have rastered paint ops preceding `beginLayer`.
  EXPECT_THAT(hibernation_raster,
              RecordedOpsAre(PaintOpEq<DrawRectOp>(SkRect::MakeXYWH(0, 0, 1, 1),
                                                   FillFlags())));

  // Wake up from hibernation.
  GetDocument().GetPage()->SetVisibilityState(
      mojom::blink::PageVisibilityState::kVisible, /*is_initial_state=*/false);

  NonThrowableExceptionState exception_state;
  Context2D()->endLayer(exception_state);

  // Post hibernation recording now holds the layer content.
  EXPECT_THAT(
      Context2D()->FlushCanvas(FlushReason::kTesting),
      Optional(RecordedOpsAre(DrawRecordOpEq(
          PaintOpEq<SaveLayerAlphaOp>(1.0f),
          PaintOpEq<DrawRectOp>(SkRect::MakeXYWH(1, 1, 1, 1), FillFlags()),
          DrawImageRectOpIs(
              CreateSkImage(/*width=*/1, /*height=*/1, SK_ColorRED)),
          PaintOpEq<RestoreOp>()))));
}

TEST_P(CanvasRenderingContext2DTestAccelerated,
       NoHibernationIfNoResourceProvider) {
  CreateContext(kNonOpaque);
  gfx::Size size(300, 300);
  CanvasElement().SetPreferred2DRasterMode(RasterModeHint::kPreferGPU);
  CanvasElement().SetResourceProviderForTesting(
      /*provider=*/nullptr, size);
  EXPECT_EQ(CanvasElement().GetRasterMode(), RasterMode::kGPU);

  EXPECT_TRUE(CanvasElement().GetLayoutBoxModelObject());
  auto* box = CanvasElement().GetLayoutBoxModelObject();
  EXPECT_TRUE(box);
  PaintLayer* painting_layer = box->PaintingLayer();
  EXPECT_TRUE(painting_layer);
  UpdateAllLifecyclePhasesForTest();

  // The resource provider gets lazily created. Force it to be dropped.
  canvas_element_->ReplaceResourceProvider(nullptr);

  // Hide element to trigger hibernation (if enabled).
  GetDocument().GetPage()->SetVisibilityState(
      mojom::blink::PageVisibilityState::kHidden,
      /*is_initial_state=*/false);
  // Run hibernation task.
  ThreadScheduler::Current()
      ->ToMainThreadScheduler()
      ->StartIdlePeriodForTesting();
  blink::test::RunPendingTasks();

  // Never hibernate a canvas with no resource provider.
  EXPECT_FALSE(box->NeedsPaintPropertyUpdate());
  EXPECT_FALSE(painting_layer->SelfNeedsRepaint());
}

TEST_P(CanvasRenderingContext2DTestAccelerated, LowLatencyIsNotSingleBuffered) {
  CreateContext(kNonOpaque, kLowLatency);
  // No need to set-up the layer bridge when testing low latency mode.
  DrawSomething();
  EXPECT_TRUE(Context2D()->getContextAttributes()->desynchronized());
  EXPECT_EQ(Context2D()->getContextAttributes()->willReadFrequently(),
            V8CanvasWillReadFrequently::Enum::kUndefined);
  EXPECT_TRUE(CanvasElement().LowLatencyEnabled());
  EXPECT_FALSE(
      CanvasElement()
          .GetOrCreateCanvasResourceProvider(RasterModeHint::kPreferGPU)
          ->SupportsSingleBuffering());
  EXPECT_EQ(CanvasElement().GetRasterMode(), RasterMode::kGPU);
}

TEST_P(CanvasRenderingContext2DTestAccelerated, DrawImage_Video_Flush) {
  V8TestingScope scope;

  CreateContext(kNonOpaque);
  // No need to set-up the layer bridge when testing low latency mode.
  CanvasElement().GetOrCreateCanvasResourceProvider(RasterModeHint::kPreferGPU);
  EXPECT_EQ(CanvasElement().GetRasterMode(), RasterMode::kGPU);

  gfx::Size visible_size(10, 10);
  scoped_refptr<media::VideoFrame> media_frame =
      media::VideoFrame::WrapVideoFrame(
          media::VideoFrame::CreateBlackFrame(/*size=*/gfx::Size(16, 16)),
          media::PIXEL_FORMAT_I420,
          /*visible_rect=*/gfx::Rect(visible_size),
          /*natural_size=*/visible_size);
  media_frame->set_timestamp(base::Microseconds(1000));
  VideoFrame* frame = MakeGarbageCollected<VideoFrame>(std::move(media_frame),
                                                       GetExecutionContext());
  NonThrowableExceptionState exception_state;

  Context2D()->fillRect(0, 0, 5, 5);
  EXPECT_TRUE(
      CanvasElement().ResourceProvider()->Recorder().HasRecordedDrawOps());

  Context2D()->drawImage(frame, 0, 0, 10, 10, 0, 0, 10, 10, exception_state);
  EXPECT_FALSE(exception_state.HadException());
  // The drawImage Operation is supposed to trigger a flush, which means that
  // There should not be any Recorded ops at this point.
  EXPECT_FALSE(
      CanvasElement().ResourceProvider()->Recorder().HasRecordedDrawOps());
}

TEST_P(CanvasRenderingContext2DTest, FlushRestoresClipStack) {
  CreateContext(kNonOpaque);

  // Ensure that the ResourceProvider and canvas are created.
  CanvasElement().GetOrCreateCanvasResourceProvider(RasterModeHint::kPreferCPU);

  // Set a transform.
  Context2D()->translate(5, 0);
  EXPECT_EQ(Canvas().getLocalToDevice().rc(0, 3), 5);

  // Draw something so that there is something to flush.
  cc::PaintFlags flags;
  Canvas().drawLine(0, 0, 2, 2, flags);

  // Flush the canvas and verify that a new drawing canvas is created that has
  // the transform restored.
  EXPECT_TRUE(Context2D()->FlushCanvas(FlushReason::kTesting));
  EXPECT_EQ(Canvas().getLocalToDevice().rc(0, 3), 5);
}

TEST_P(CanvasRenderingContext2DTest, PutImageDataRestoresClipStack) {
  CreateContext(kNonOpaque);

  // Ensure that the ResourceProvider and canvas are created.
  CanvasElement().GetOrCreateCanvasResourceProvider(RasterModeHint::kPreferCPU);

  // Set a transform.
  Context2D()->translate(5, 0);
  EXPECT_EQ(Canvas().getLocalToDevice().rc(0, 3), 5);

  // Invoke putImageData(). This forces a flush, after which the transform
  // should be restored.
  NonThrowableExceptionState exception_state;
  Context2D()->fillRect(3, 3, 1, 1);
  Context2D()->putImageData(full_image_data_.Get(), 0, 0, exception_state);

  EXPECT_EQ(Canvas().getLocalToDevice().rc(0, 3), 5);
}

TEST_P(CanvasRenderingContext2DTestAccelerated,
       DISABLED_DisableAcceleration_UpdateGPUMemoryUsage) {
  CreateContext(kNonOpaque);

  gfx::Size size(10, 10);
  CanvasElement().SetPreferred2DRasterMode(RasterModeHint::kPreferGPU);
  CanvasElement().SetResourceProviderForTesting(
      /*provider=*/nullptr, size);
  CanvasRenderingContext2D* context = Context2D();

  // 800 = 10 * 10 * 4 * 2 where 10*10 is canvas size, 4 is num of bytes per
  // pixel per buffer, and 2 is an estimate of num of gpu buffers required

  context->fillRect(10, 10, 100, 100);
  EXPECT_EQ(CanvasElement().GetRasterMode(), RasterMode::kGPU);

  CanvasElement().DisableAcceleration();
  EXPECT_EQ(CanvasElement().GetRasterMode(), RasterMode::kCPU);

  context->fillRect(10, 10, 100, 100);
}

TEST_P(CanvasRenderingContext2DTestAccelerated,
       DisableAccelerationPreservesRasterAndRecording) {
  ScopedCanvas2dLayersForTest layer_feature{/*enabled=*/true};
  CreateContext(kNonOpaque);

  gfx::Size size(100, 100);
  auto gpu_provider = std::make_unique<FakeCanvasResourceProvider>(
      SkImageInfo::MakeN32Premul(size.width(), size.height()),
      RasterModeHint::kPreferGPU, &CanvasElement(),
      CompositingMode::kSupportsDirectCompositing);
  auto cpu_provider = std::make_unique<FakeCanvasResourceProvider>(
      SkImageInfo::MakeN32Premul(size.width(), size.height()),
      RasterModeHint::kPreferCPU, &CanvasElement(),
      CompositingMode::kSupportsDirectCompositing);

  // When disabling acceleration, the raster content is read from the
  // accelerated provider and written to the unaccelerated provider.
  InSequence s;
  EXPECT_CALL(*gpu_provider, Snapshot(FlushReason::kReplaceLayerBridge, _))
      .Times(1);
  EXPECT_CALL(*cpu_provider, WritePixels).Times(1);

  CanvasElement().SetPreferred2DRasterMode(RasterModeHint::kPreferGPU);
  CanvasElement().SetResourceProviderForTesting(std::move(gpu_provider), size);

  NonThrowableExceptionState exception_state;
  Context2D()->fillRect(10, 10, 20, 20);
  Context2D()->save();
  Context2D()->beginLayer(GetScriptState(), BeginLayerOptions::Create(),
                          exception_state);
  Context2D()->fillRect(10, 20, 30, 40);

  EXPECT_EQ(CanvasElement().GetRasterMode(), RasterMode::kGPU);
  CanvasElement().DisableAcceleration(std::move(cpu_provider));
  EXPECT_EQ(CanvasElement().GetRasterMode(), RasterMode::kCPU);

  Context2D()->endLayer(exception_state);
  Context2D()->restore(exception_state);

  EXPECT_THAT(
      Context2D()->FlushCanvas(FlushReason::kTesting),
      Optional(RecordedOpsAre(
          PaintOpEq<SaveOp>(),
          DrawRecordOpEq(Paint
```