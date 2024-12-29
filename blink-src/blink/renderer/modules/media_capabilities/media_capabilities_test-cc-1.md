Response:
The user wants a summary of the functionality of the provided C++ code snippet. This is the second part of a three-part series. The code is a test file for the `MediaCapabilities` feature in the Chromium Blink engine. It uses Google Test framework.

Here's a breakdown of the code's functionality:

1. **Testing Decoding Capabilities:**  It tests the logic for determining if a given media decoding configuration is supported, smooth, and power-efficient.
2. **Interaction with GPU Factories:** It simulates and tests how the `MediaCapabilities` feature interacts with the `GpuVideoAcceleratorFactories` to determine hardware decoding support and power efficiency.
3. **Interaction with Performance History Service (DB):** It tests how `MediaCapabilities` uses the `PerfHistoryService` to fetch historical data for predicting smoothness and power efficiency.
4. **Interaction with Machine Learning Services (Bad Window and NNR):** It tests how `MediaCapabilities` integrates with machine learning services to predict smoothness based on the "bad window" and "NNR" (likely Network Nack Ratio) metrics. It tests scenarios where only one service is enabled, or both are enabled.
5. **Testing Asynchronous Behavior:** It verifies that the `decodingInfo` promise resolves correctly even when responses from different sources (DB, ML services, GPU factories) arrive in different orders.
6. **Testing WebRTC Capabilities:** It specifically tests the `MediaCapabilities` logic for WebRTC audio and video decoding and encoding.
7. **Testing WebRTC Interaction with GPU Factories:** Similar to regular decoding, it tests how WebRTC decoding and encoding interact with `GpuVideoAcceleratorFactories`.
8. **Testing WebRTC Interaction with WebRTC Performance History Service:** It tests how `MediaCapabilities` uses the `WebrtcPerfHistoryService` for WebRTC-specific smoothness predictions.
9. **Testing Overrides for WebRTC Behavior:** It tests the functionality that allows overriding the default behavior of considering something smooth if it's power-efficient in WebRTC.

**Relationship to JavaScript, HTML, CSS:**

The `MediaCapabilities` API is exposed to JavaScript, allowing web developers to query the browser's media capabilities. This C++ test file directly validates the underlying logic that supports this JavaScript API.

*   **JavaScript:** The test uses `ScriptPromiseTester` which indicates interaction with JavaScript promises. The tests call `decodingInfo` which corresponds to a JavaScript API method.
*   **HTML:**  The media capabilities are relevant to HTML `<video>` and `<audio>` elements. The browser uses these capabilities to decide how to play media embedded in HTML.
*   **CSS:** While not directly related, CSS can affect how media elements are displayed. However, the `MediaCapabilities` API focuses on the underlying decoding and encoding capabilities, not the visual presentation.

**Logical Reasoning (with assumptions):**

The code uses mocks to simulate different scenarios. For example:

*   **Assumption:**  The `GpuVideoAcceleratorFactories` correctly reports whether a decoder is supported and if it's power-efficient.
*   **Input:** A `MediaDecodingConfiguration` object specifying codec, profile, etc.
*   **Output:** A `MediaCapabilitiesInfo` object indicating `supported`, `smooth`, and `powerEfficient`.
*   **Reasoning:** The test verifies that if the `GpuVideoAcceleratorFactories` reports support and power efficiency, the `MediaCapabilitiesInfo` reflects this. It also tests the priority order of different sources of information (GPU Factories > DB > ML).

**User/Programming Errors:**

While this is a test file, it implicitly reveals potential misuse of the `MediaCapabilities` API:

*   **Assuming immediate results:** The `decodingInfo` method returns a Promise, indicating asynchronous behavior. A common error would be to try to access the results synchronously before the promise resolves.
*   **Incorrectly interpreting the `MediaCapabilitiesInfo`:**  Developers might misinterpret the meaning of `smooth` or `powerEfficient`. The tests clarify how these properties are determined based on various factors.

**User Operation to Reach This Code:**

1. A web developer wants to use the `navigator.mediaCapabilities` API in their JavaScript code.
2. The browser internally calls the C++ implementation of this API.
3. To ensure the correctness of this implementation, Chromium developers write tests like the one provided. They would run these tests during development and before shipping new versions of the browser.

**Summary of Functionality (Part 2):**

This part of the `media_capabilities_test.cc` file primarily focuses on:

*   **Testing the integration of machine learning-based smoothness prediction into the media capabilities determination process.** It specifically tests scenarios involving the "bad window" and "NNR" ML services, including cases where one or both services are enabled and how their predictions influence the final smoothness result.
*   **Testing the asynchronous nature of fetching media capabilities information.** It ensures that the promises returned by `decodingInfo` resolve correctly regardless of the order in which responses are received from the underlying data sources (GPU, database, ML services).
*   **Continuing the testing of WebRTC specific media capabilities, focusing on both decoding and encoding scenarios.** This includes verifying the interaction with the `WebrtcPerfHistoryService` for smoothness predictions and the impact of GPU acceleration.

这是 `blink/renderer/modules/media_capabilities/media_capabilities_test.cc` 文件的第二部分，主要功能是测试 Blink 引擎中 `MediaCapabilities` 接口的正确性，特别是关于解码（decoding）能力判断的逻辑，并涵盖了与机器学习（ML）服务集成的测试。

**核心功能归纳：**

1. **测试解码能力判断与 GPU 加速器的交互：**
    *   模拟 GPU 硬件加速器工厂 (`MockGpuVideoAcceleratorFactories`) 的行为，测试当 GPU 支持解码配置时，`MediaCapabilities` 如何判断 `powerEfficient` 属性。
    *   验证 GPU 工厂的响应优先于性能历史数据库（DB）的响应。
    *   测试当 GPU 加速器支持状态未知时，`MediaCapabilities` 的行为。

2. **测试基于机器学习的平滑度（smooth）预测：**
    *   测试 `MediaCapabilities` 如何与 "bad window" 机器学习服务集成，根据预测结果判断平滑度。
    *   测试 `MediaCapabilities` 如何与 "NNR" (可能是 Network Nack Ratio) 机器学习服务集成，根据预测结果判断平滑度。
    *   测试同时启用 "bad window" 和 "NNR" 两个机器学习服务时，`MediaCapabilities` 如何综合两者的预测结果来判断平滑度（使用逻辑 OR）。
    *   验证当启用 ML 预测时，ML 预测结果优先于性能历史数据库的平滑度数据。

3. **测试异步回调的正确处理：**
    *   模拟解码信息查询过程中，性能历史数据库、机器学习服务和 GPU 工厂回调的不同到达顺序。
    *   验证 `decodingInfo` 方法返回的 Promise 在所有必要的回调完成后才正确解析（resolve）。

4. **测试 WebRTC 相关的解码和编码能力：**
    *   测试 WebRTC 音频和视频的基本解码能力判断，包括支持和不支持的编解码器。
    *   测试 WebRTC 视频解码中空间可伸缩性（spatial scalability）对平滑度的影响。
    *   测试 WebRTC 音频和视频的基本编码能力判断，包括支持和不支持的编解码器。
    *   测试 WebRTC 视频编码中可伸缩模式（scalability mode）对能力判断的影响。
    *   测试 WebRTC 解码和编码能力判断中与 GPU 加速器的交互。
    *   测试 WebRTC 场景下，性能历史数据库 (`WebrtcPerfHistoryService`) 如何用于平滑度预测。
    *   测试在 WebRTC 解码和编码中，当 `powerEfficient` 为 true 时，默认情况下 `smooth` 也为 true 的行为。
    *   测试可以通过 Field Trial 配置覆盖 WebRTC 解码中 `powerEfficient` 为 true 时 `smooth` 也为 true 的默认行为，强制从性能历史查询平滑度。

**与 JavaScript, HTML, CSS 的关系：**

*   **JavaScript:**  `MediaCapabilities` 是一个暴露给 JavaScript 的 API，允许网页开发者查询浏览器对特定媒体格式的支持情况。这个测试文件验证了该 API 后端 C++ 实现的正确性。例如，JavaScript 代码可能会调用 `navigator.mediaCapabilities.decodingInfo()` 来获取解码信息，而这个测试文件中的 `DecodingInfo()` 函数模拟了对该 JavaScript API 的调用。
*   **HTML:** `MediaCapabilities` 的目的是为了帮助开发者根据浏览器的能力选择合适的媒体资源，从而优化 HTML `<video>` 或 `<audio>` 元素的播放体验。测试用例中创建的 `MediaDecodingConfiguration` 和 `MediaEncodingConfiguration` 对象就模拟了 HTML 中可能遇到的各种媒体配置。
*   **CSS:**  CSS 主要负责媒体元素的外观和布局，与 `MediaCapabilities` 的功能没有直接关系。`MediaCapabilities` 关注的是底层的解码和编码能力。

**逻辑推理的假设输入与输出：**

*   **假设输入（以 `PredictWithBadWindowMLService` 测试为例）：**
    *   启用了基于 "bad window" ML 服务的平滑度预测。
    *   禁用了从 GPU 工厂查询电源效率。
    *   `MediaDecodingConfiguration` 描述了一个特定的视频解码配置。
    *   性能历史数据库报告 `smooth=true` 和 `efficient=false`。
    *   "bad window" 机器学习服务预测的 "bad windows" 数量等于设定的阈值 `kBadWindowThreshold`。
*   **输出：**
    *   `MediaCapabilitiesInfo` 对象的 `smooth` 属性为 `false`，因为 ML 预测的 "bad windows" 数量达到了阈值。
    *   `MediaCapabilitiesInfo` 对象的 `powerEfficient` 属性为 `false`，因为禁用了从 GPU 工厂查询，且数据库报告为 false。

**用户或编程常见的使用错误举例：**

*   **假设 ML 预测总是准确的：** 开发者可能会错误地认为 ML 预测的结果总是可靠的，而忽略了性能历史数据库或其他信息来源。测试用例通过模拟不同的预测结果和数据库返回值，强调了 `MediaCapabilities` 需要综合考虑多种信息来源。
*   **在异步操作完成前访问结果：** `decodingInfo` 方法返回的是一个 Promise，开发者如果直接访问结果而没有等待 Promise 解析，会导致错误。测试用例中的 `ScriptPromiseTester` 就用于验证异步操作的正确性。

**用户操作如何一步步到达这里作为调试线索：**

1. **用户遇到媒体播放问题：** 用户可能在访问某个网页时遇到视频播放卡顿或者耗电量过高的问题。
2. **开发者使用 `MediaCapabilities` API 进行调试：**  为了诊断问题，开发者可能会使用 `navigator.mediaCapabilities` API 来检查浏览器是否支持当前网页所使用的媒体格式，以及是否是平滑和节能的。
3. **浏览器内部调用 `MediaCapabilities` 的 C++ 实现：**  当 JavaScript 代码调用 `navigator.mediaCapabilities.decodingInfo()` 时，浏览器内部会调用 `blink/renderer/modules/media_capabilities/media_capabilities.cc` 中的相应代码。
4. **调试可能涉及到查看测试用例：** 如果开发者或者 Chromium 工程师需要深入了解 `MediaCapabilities` 的工作原理，或者发现了潜在的 bug，他们可能会查看像 `media_capabilities_test.cc` 这样的测试文件，来理解各种场景下的预期行为，以及如何模拟和复现问题。测试用例中的断言失败可以帮助定位 bug 的根源。

**总而言之，这部分测试代码专注于验证 `MediaCapabilities` 接口在处理解码能力判断时的核心逻辑，特别是与 GPU 加速、性能历史数据库以及机器学习服务的集成，并确保异步操作的正确性，同时也涵盖了 WebRTC 相关的能力判断。**

Prompt: 
```
这是目录为blink/renderer/modules/media_capabilities/media_capabilities_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能

"""
pportKnown())
        .Times(2)
        .WillRepeatedly(Return(true));
    EXPECT_CALL(*mock_gpu_factories, IsDecoderConfigSupported(_))
        .WillOnce(
            Return(media::GpuVideoAcceleratorFactories::Supported::kTrue));
  }

  // Info should be powerEfficient, preferring response of GpuFactories over
  // the DB.
  MediaCapabilitiesInfo* info = DecodingInfo(kDecodingConfig, &context);
  EXPECT_TRUE(info->powerEfficient());
  EXPECT_FALSE(info->smooth());
  context.VerifyAndClearMockExpectations();
  testing::Mock::VerifyAndClearExpectations(mock_gpu_factories.get());

  // Now expect a second query with support is already known to be false. Set
  // DB to respond with the opposite answer.
  EXPECT_CALL(*context.GetPerfHistoryService(), GetPerfInfo(_, _))
      .WillOnce(DbCallback(kFeatures, /*smooth*/ false, /*power_eff*/ true));
  EXPECT_CALL(context.GetMockPlatform(), GetGpuFactories());
  EXPECT_CALL(*mock_gpu_factories, IsDecoderSupportKnown())
      .Times(2)
      .WillRepeatedly(Return(true));
  EXPECT_CALL(*mock_gpu_factories, IsDecoderConfigSupported(_))
      .WillRepeatedly(
          Return(media::GpuVideoAcceleratorFactories::Supported::kFalse));

  // Info should be NOT powerEfficient, preferring response of GpuFactories over
  // the DB.
  info = DecodingInfo(kDecodingConfig, &context);
  EXPECT_FALSE(info->powerEfficient());
  EXPECT_FALSE(info->smooth());
  context.VerifyAndClearMockExpectations();
  testing::Mock::VerifyAndClearExpectations(mock_gpu_factories.get());
}

// Test with smoothness predictions coming solely from "bad window" ML service.
TEST(MediaCapabilitiesTests, PredictWithBadWindowMLService) {
  test::TaskEnvironment task_environment;
  // Enable ML predictions with thresholds. -1 disables the NNR predictor.
  const double kBadWindowThreshold = 2;
  const double kNnrThreshold = -1;
  base::test::ScopedFeatureList scoped_feature_list;
  scoped_feature_list.InitWithFeaturesAndParameters(
      // Enabled features w/ parameters
      {{media::kMediaLearningSmoothnessExperiment,
        MakeMlParams(kBadWindowThreshold, kNnrThreshold)}},
      // Disabled GpuFactories (use DB for power).
      {media::kMediaCapabilitiesQueryGpuFactories});

  MediaCapabilitiesTestContext context;
  const auto* kDecodingConfig = CreateDecodingConfig();
  const media::mojom::blink::PredictionFeatures kFeatures = CreateFeatures();
  const Vector<media::learning::FeatureValue> kFeaturesML = CreateFeaturesML();

  // ML is enabled, but DB should still be called for power efficiency (false).
  // Its smoothness value (true) should be ignored in favor of ML prediction.
  // Only bad window service should be asked for a prediction. Expect
  // smooth=false because bad window prediction is equal to its threshold.
  EXPECT_CALL(*context.GetPerfHistoryService(), GetPerfInfo(_, _))
      .WillOnce(DbCallback(kFeatures, /*smooth*/ true, /*efficient*/ false));
  EXPECT_CALL(*context.GetBadWindowService(), PredictDistribution(_, _))
      .WillOnce(MlCallback(kFeaturesML, kBadWindowThreshold));
  EXPECT_CALL(*context.GetNnrService(), PredictDistribution(_, _)).Times(0);
  MediaCapabilitiesInfo* info = DecodingInfo(kDecodingConfig, &context);
  EXPECT_FALSE(info->smooth());
  EXPECT_FALSE(info->powerEfficient());
  // NNR service should not be bound when NNR predictions disabled.
  EXPECT_FALSE(context.GetNnrService()->is_bound());
  context.VerifyAndClearMockExpectations();

  // Same as above, but invert all signals. Expect smooth=true because bad
  // window prediction is now less than its threshold.
  EXPECT_CALL(*context.GetPerfHistoryService(), GetPerfInfo(_, _))
      .WillOnce(DbCallback(kFeatures, /*smooth*/ false, /*efficient*/ true));
  EXPECT_CALL(*context.GetBadWindowService(), PredictDistribution(_, _))
      .WillOnce(MlCallback(kFeaturesML, kBadWindowThreshold - 0.25));
  EXPECT_CALL(*context.GetNnrService(), PredictDistribution(_, _)).Times(0);
  info = DecodingInfo(kDecodingConfig, &context);
  EXPECT_TRUE(info->smooth());
  EXPECT_TRUE(info->powerEfficient());
  EXPECT_FALSE(context.GetNnrService()->is_bound());
  context.VerifyAndClearMockExpectations();

  // Same as above, but predict zero bad windows. Expect smooth=true because
  // zero is below the threshold.
  EXPECT_CALL(*context.GetPerfHistoryService(), GetPerfInfo(_, _))
      .WillOnce(DbCallback(kFeatures, /*smooth*/ false, /*efficient*/ true));
  EXPECT_CALL(*context.GetBadWindowService(), PredictDistribution(_, _))
      .WillOnce(MlCallback(kFeaturesML, /* bad windows */ 0));
  EXPECT_CALL(*context.GetNnrService(), PredictDistribution(_, _)).Times(0);
  info = DecodingInfo(kDecodingConfig, &context);
  EXPECT_TRUE(info->smooth());
  EXPECT_TRUE(info->powerEfficient());
  EXPECT_FALSE(context.GetNnrService()->is_bound());
  context.VerifyAndClearMockExpectations();
}

// Test with smoothness predictions coming solely from "NNR" ML service.
TEST(MediaCapabilitiesTests, PredictWithNnrMLService) {
  test::TaskEnvironment task_environment;
  // Enable ML predictions with thresholds. -1 disables the bad window
  // predictor.
  const double kBadWindowThreshold = -1;
  const double kNnrThreshold = 5;
  base::test::ScopedFeatureList scoped_feature_list;
  scoped_feature_list.InitWithFeaturesAndParameters(
      // Enabled both ML services.
      {{media::kMediaLearningSmoothnessExperiment,
        MakeMlParams(kBadWindowThreshold, kNnrThreshold)}},
      // Disabled features (use DB for power efficiency)
      {media::kMediaCapabilitiesQueryGpuFactories});

  MediaCapabilitiesTestContext context;
  const auto* kDecodingConfig = CreateDecodingConfig();
  const media::mojom::blink::PredictionFeatures kFeatures = CreateFeatures();
  const Vector<media::learning::FeatureValue> kFeaturesML = CreateFeaturesML();

  // ML is enabled, but DB should still be called for power efficiency (false).
  // Its smoothness value (true) should be ignored in favor of ML prediction.
  // Only NNR service should be asked for a prediction. Expect smooth=false
  // because NNR prediction is equal to its threshold.
  EXPECT_CALL(*context.GetPerfHistoryService(), GetPerfInfo(_, _))
      .WillOnce(DbCallback(kFeatures, /*smooth*/ true, /*efficient*/ false));
  EXPECT_CALL(*context.GetBadWindowService(), PredictDistribution(_, _))
      .Times(0);
  EXPECT_CALL(*context.GetNnrService(), PredictDistribution(_, _))
      .WillOnce(MlCallback(kFeaturesML, kNnrThreshold));
  MediaCapabilitiesInfo* info = DecodingInfo(kDecodingConfig, &context);
  EXPECT_FALSE(info->smooth());
  EXPECT_FALSE(info->powerEfficient());
  // Bad window service should not be bound when NNR predictions disabled.
  EXPECT_FALSE(context.GetBadWindowService()->is_bound());
  context.VerifyAndClearMockExpectations();

  // Same as above, but invert all signals. Expect smooth=true because NNR
  // prediction is now less than its threshold.
  EXPECT_CALL(*context.GetPerfHistoryService(), GetPerfInfo(_, _))
      .WillOnce(DbCallback(kFeatures, /*smooth*/ false, /*efficient*/ true));
  EXPECT_CALL(*context.GetBadWindowService(), PredictDistribution(_, _))
      .Times(0);
  EXPECT_CALL(*context.GetNnrService(), PredictDistribution(_, _))
      .WillOnce(MlCallback(kFeaturesML, kNnrThreshold - 0.01));
  info = DecodingInfo(kDecodingConfig, &context);
  EXPECT_TRUE(info->smooth());
  EXPECT_TRUE(info->powerEfficient());
  EXPECT_FALSE(context.GetBadWindowService()->is_bound());
  context.VerifyAndClearMockExpectations();

  // Same as above, but predict zero NNRs. Expect smooth=true because zero is
  // below the threshold.
  EXPECT_CALL(*context.GetPerfHistoryService(), GetPerfInfo(_, _))
      .WillOnce(DbCallback(kFeatures, /*smooth*/ false, /*efficient*/ true));
  EXPECT_CALL(*context.GetBadWindowService(), PredictDistribution(_, _))
      .Times(0);
  EXPECT_CALL(*context.GetNnrService(), PredictDistribution(_, _))
      .WillOnce(MlCallback(kFeaturesML, /* NNRs */ 0));
  info = DecodingInfo(kDecodingConfig, &context);
  EXPECT_TRUE(info->smooth());
  EXPECT_TRUE(info->powerEfficient());
  EXPECT_FALSE(context.GetBadWindowService()->is_bound());
  context.VerifyAndClearMockExpectations();
}

// Test with combined smoothness predictions from both ML services.
TEST(MediaCapabilitiesTests, PredictWithBothMLServices) {
  test::TaskEnvironment task_environment;
  // Enable ML predictions with thresholds.
  const double kBadWindowThreshold = 2;
  const double kNnrThreshold = 1;
  base::test::ScopedFeatureList scoped_feature_list;
  scoped_feature_list.InitWithFeaturesAndParameters(
      // Enabled both ML services.
      {{media::kMediaLearningSmoothnessExperiment,
        MakeMlParams(kBadWindowThreshold, kNnrThreshold)}},
      // Disabled features (use DB for power efficiency)
      {media::kMediaCapabilitiesQueryGpuFactories});

  MediaCapabilitiesTestContext context;
  const auto* kDecodingConfig = CreateDecodingConfig();
  const media::mojom::blink::PredictionFeatures kFeatures = CreateFeatures();
  const Vector<media::learning::FeatureValue> kFeaturesML = CreateFeaturesML();

  // ML is enabled, but DB should still be called for power efficiency (false).
  // Its smoothness value (true) should be ignored in favor of ML predictions.
  // Both ML services should be called for prediction. In both cases we exceed
  // the threshold, such that smooth=false.
  EXPECT_CALL(*context.GetPerfHistoryService(), GetPerfInfo(_, _))
      .WillOnce(DbCallback(kFeatures, /*smooth*/ true, /*efficient*/ false));
  EXPECT_CALL(*context.GetBadWindowService(), PredictDistribution(_, _))
      .WillOnce(MlCallback(kFeaturesML, kBadWindowThreshold + 0.5));
  EXPECT_CALL(*context.GetNnrService(), PredictDistribution(_, _))
      .WillOnce(MlCallback(kFeaturesML, kNnrThreshold + 0.5));
  MediaCapabilitiesInfo* info = DecodingInfo(kDecodingConfig, &context);
  EXPECT_FALSE(info->smooth());
  EXPECT_FALSE(info->powerEfficient());
  context.VerifyAndClearMockExpectations();

  // Make another call to DecodingInfo with one "bad window" prediction
  // indicating smooth=false, while nnr prediction indicates smooth=true. Verify
  // resulting info predicts false, as the logic should OR the false signals.
  EXPECT_CALL(*context.GetPerfHistoryService(), GetPerfInfo(_, _))
      .WillOnce(DbCallback(kFeatures, /*smooth*/ true, /*efficient*/ false));
  EXPECT_CALL(*context.GetBadWindowService(), PredictDistribution(_, _))
      .WillOnce(MlCallback(kFeaturesML, kBadWindowThreshold + 0.5));
  EXPECT_CALL(*context.GetNnrService(), PredictDistribution(_, _))
      .WillOnce(MlCallback(kFeaturesML, kNnrThreshold / 2));
  info = DecodingInfo(kDecodingConfig, &context);
  EXPECT_FALSE(info->smooth());
  EXPECT_FALSE(info->powerEfficient());
  context.VerifyAndClearMockExpectations();

  // Same as above, but invert predictions from ML services. Outcome should
  // still be smooth=false (logic is ORed).
  EXPECT_CALL(*context.GetPerfHistoryService(), GetPerfInfo(_, _))
      .WillOnce(DbCallback(kFeatures, /*smooth*/ true, /*efficient*/ false));
  EXPECT_CALL(*context.GetBadWindowService(), PredictDistribution(_, _))
      .WillOnce(MlCallback(kFeaturesML, kBadWindowThreshold / 2));
  EXPECT_CALL(*context.GetNnrService(), PredictDistribution(_, _))
      .WillOnce(MlCallback(kFeaturesML, kNnrThreshold + 0.5));
  info = DecodingInfo(kDecodingConfig, &context);
  EXPECT_FALSE(info->smooth());
  EXPECT_FALSE(info->powerEfficient());
  context.VerifyAndClearMockExpectations();

  // This time both ML services agree smooth=true while DB predicts
  // smooth=false. Expect info->smooth() = true, as only ML predictions matter
  // when ML experiment enabled.
  EXPECT_CALL(*context.GetPerfHistoryService(), GetPerfInfo(_, _))
      .WillOnce(DbCallback(kFeatures, /*smooth*/ false, /*efficient*/ true));
  EXPECT_CALL(*context.GetBadWindowService(), PredictDistribution(_, _))
      .WillOnce(MlCallback(kFeaturesML, kBadWindowThreshold / 2));
  EXPECT_CALL(*context.GetNnrService(), PredictDistribution(_, _))
      .WillOnce(MlCallback(kFeaturesML, kNnrThreshold / 2));
  info = DecodingInfo(kDecodingConfig, &context);
  EXPECT_TRUE(info->smooth());
  EXPECT_TRUE(info->powerEfficient());
  context.VerifyAndClearMockExpectations();

  // Same as above, but with ML services predicting exactly their respective
  // thresholds. Now expect info->smooth() = false - reaching the threshold is
  // considered not smooth.
  EXPECT_CALL(*context.GetPerfHistoryService(), GetPerfInfo(_, _))
      .WillOnce(DbCallback(kFeatures, /*smooth*/ false, /*efficient*/ true));
  EXPECT_CALL(*context.GetBadWindowService(), PredictDistribution(_, _))
      .WillOnce(MlCallback(kFeaturesML, kBadWindowThreshold));
  EXPECT_CALL(*context.GetNnrService(), PredictDistribution(_, _))
      .WillOnce(MlCallback(kFeaturesML, kNnrThreshold));
  info = DecodingInfo(kDecodingConfig, &context);
  EXPECT_FALSE(info->smooth());
  EXPECT_TRUE(info->powerEfficient());
  context.VerifyAndClearMockExpectations();
}

// Simulate a call to DecodingInfo with smoothness predictions arriving in the
// specified |callback_order|. Ensure that promise resolves correctly only after
// all callbacks have arrived.
void RunCallbackPermutationTest(std::vector<PredictionType> callback_order) {
  // Enable ML predictions with thresholds.
  const double kBadWindowThreshold = 2;
  const double kNnrThreshold = 3;
  base::test::ScopedFeatureList scoped_feature_list;
  scoped_feature_list.InitWithFeaturesAndParameters(
      // Enabled features w/ parameters
      {{media::kMediaLearningSmoothnessExperiment,
        MakeMlParams(kBadWindowThreshold, kNnrThreshold)},
       {media::kMediaCapabilitiesQueryGpuFactories, {}}},
      // Disabled features.
      {});

  MediaCapabilitiesTestContext context;
  const auto* kDecodingConfig = CreateDecodingConfig();
  auto mock_gpu_factories =
      std::make_unique<media::MockGpuVideoAcceleratorFactories>(nullptr);

  // DB and both ML services should be called. Save their callbacks.
  CallbackSaver cb_saver;
  EXPECT_CALL(*context.GetPerfHistoryService(), GetPerfInfo(_, _))
      .WillOnce(Invoke(&cb_saver, &CallbackSaver::SavePerfHistoryCallback));
  EXPECT_CALL(*context.GetBadWindowService(), PredictDistribution(_, _))
      .WillOnce(Invoke(&cb_saver, &CallbackSaver::SaveBadWindowCallback));
  EXPECT_CALL(*context.GetNnrService(), PredictDistribution(_, _))
      .WillOnce(Invoke(&cb_saver, &CallbackSaver::SaveNnrCallback));

  // GpuFactories should also be called. Set it up to be async with arrival of
  // support info. Save the "notify" callback.
  EXPECT_CALL(context.GetMockPlatform(), GetGpuFactories())
      .WillRepeatedly(Return(mock_gpu_factories.get()));
  {
    // InSequence because we EXPECT two calls to IsDecoderSupportKnown with
    // different return values.
    InSequence s;
    EXPECT_CALL(*mock_gpu_factories, IsDecoderSupportKnown())
        .WillOnce(Return(false));
    EXPECT_CALL(*mock_gpu_factories, NotifyDecoderSupportKnown(_))
        .WillOnce(
            Invoke(&cb_saver, &CallbackSaver::SaveGpuFactoriesNotifyCallback));
    // MediaCapabilities calls IsDecoderSupportKnown() once, and
    // GpuVideoAcceleratorFactories::IsDecoderConfigSupported() also calls it
    // once internally.
    EXPECT_CALL(*mock_gpu_factories, IsDecoderSupportKnown())
        .Times(2)
        .WillRepeatedly(Return(true));
    EXPECT_CALL(*mock_gpu_factories, IsDecoderConfigSupported(_))
        .WillRepeatedly(
            Return(media::GpuVideoAcceleratorFactories::Supported::kFalse));
  }

  // Call decodingInfo() to kick off the calls to prediction services.
  auto promise = context.GetMediaCapabilities()->decodingInfo(
      context.GetScriptState(), kDecodingConfig, context.GetExceptionState());
  ScriptPromiseTester tester(context.GetScriptState(), promise);

  // Callbacks should all be saved after mojo's pending tasks have run.
  test::RunPendingTasks();
  ASSERT_TRUE(cb_saver.perf_history_cb() && cb_saver.bad_window_cb() &&
              cb_saver.nnr_cb() && cb_saver.gpu_factories_notify_cb());

  // Complete callbacks in whatever order.
  for (size_t i = 0; i < callback_order.size(); ++i) {
    switch (callback_order[i]) {
      case PredictionType::kDB:
        std::move(cb_saver.perf_history_cb()).Run(true, true);
        break;
      case PredictionType::kBadWindow:
        std::move(cb_saver.bad_window_cb())
            .Run(MakeHistogram(kBadWindowThreshold - 0.25));
        break;
      case PredictionType::kNnr:
        std::move(cb_saver.nnr_cb()).Run(MakeHistogram(kNnrThreshold + 0.5));
        break;
      case PredictionType::kGpuFactories:
        std::move(cb_saver.gpu_factories_notify_cb()).Run();
        break;
    }

    // Give callbacks/tasks a chance to run.
    test::RunPendingTasks();

    // Promise should only be resolved once the final callback has run.
    if (i < callback_order.size() - 1) {
      ASSERT_FALSE(tester.IsFulfilled());
    } else {
      ASSERT_TRUE(tester.IsFulfilled());
    }
  }

  ASSERT_FALSE(tester.IsRejected()) << " Cant get info from rejected promise.";
  MediaCapabilitiesInfo* info =
      NativeValueTraits<MediaCapabilitiesInfo>::NativeValue(
          context.GetIsolate(), tester.Value().V8Value(),
          context.GetExceptionState());

  // Smooth=false because NNR prediction exceeds threshold.
  EXPECT_FALSE(info->smooth());
  // DB predicted power_efficient = true, but GpuFactories overrides w/ false.
  EXPECT_FALSE(info->powerEfficient());
}

// Test that decodingInfo() behaves correctly for all orderings/timings of the
// underlying prediction services.
TEST(MediaCapabilitiesTests, PredictionCallbackPermutations) {
  test::TaskEnvironment task_environment;
  std::vector<PredictionType> callback_order(
      {PredictionType::kDB, PredictionType::kBadWindow, PredictionType::kNnr,
       PredictionType::kGpuFactories});
  do {
    RunCallbackPermutationTest(callback_order);
  } while (std::next_permutation(callback_order.begin(), callback_order.end()));
}

// WebRTC decodingInfo tests.
TEST(MediaCapabilitiesTests, WebrtcDecodingBasicAudio) {
  test::TaskEnvironment task_environment;
  MediaCapabilitiesTestContext context;
  EXPECT_CALL(context.GetMockPlatform(), GetGpuFactories())
      .Times(testing::AtMost(1));

  const MediaDecodingConfiguration* kDecodingConfig =
      CreateWebrtcAudioDecodingConfig();
  MediaCapabilitiesInfo* info = DecodingInfo(kDecodingConfig, &context);
  EXPECT_TRUE(info->supported());
  EXPECT_TRUE(info->smooth());
  EXPECT_TRUE(info->powerEfficient());
}

TEST(MediaCapabilitiesTests, WebrtcDecodingUnsupportedAudio) {
  test::TaskEnvironment task_environment;
  MediaCapabilitiesTestContext context;
  EXPECT_CALL(context.GetMockPlatform(), GetGpuFactories())
      .Times(testing::AtMost(1));

  const MediaDecodingConfiguration* kDecodingConfig =
      CreateAudioConfig<MediaDecodingConfiguration>("audio/FooCodec", "webrtc");
  MediaCapabilitiesInfo* info = DecodingInfo(kDecodingConfig, &context);
  EXPECT_FALSE(info->supported());
  EXPECT_FALSE(info->smooth());
  EXPECT_FALSE(info->powerEfficient());
}

// Other tests will assume these match. Test to be sure they stay in sync.
TEST(MediaCapabilitiesTests, WebrtcConfigMatchesFeatures) {
  test::TaskEnvironment task_environment;
  const MediaDecodingConfiguration* kDecodingConfig =
      CreateWebrtcDecodingConfig();
  const MediaEncodingConfiguration* kEncodingConfig =
      CreateWebrtcEncodingConfig();
  const media::mojom::blink::WebrtcPredictionFeatures kDecodeFeatures =
      CreateWebrtcFeatures(/*is_decode=*/true);
  const media::mojom::blink::WebrtcPredictionFeatures kEncodeFeatures =
      CreateWebrtcFeatures(/*is_decode=*/false);

  EXPECT_TRUE(kDecodeFeatures.is_decode_stats);
  EXPECT_FALSE(kEncodeFeatures.is_decode_stats);

  EXPECT_TRUE(kDecodingConfig->video()->contentType().Contains("video/VP9"));
  EXPECT_TRUE(kEncodingConfig->video()->contentType().Contains("video/VP9"));
  EXPECT_EQ(static_cast<media::VideoCodecProfile>(kDecodeFeatures.profile),
            media::VP9PROFILE_PROFILE0);
  EXPECT_EQ(static_cast<media::VideoCodecProfile>(kEncodeFeatures.profile),
            media::VP9PROFILE_PROFILE0);
  EXPECT_EQ(kCodecProfile, media::VP9PROFILE_PROFILE0);

  EXPECT_EQ(
      kDecodingConfig->video()->width() * kDecodingConfig->video()->height(),
      static_cast<uint32_t>(kDecodeFeatures.video_pixels));
  EXPECT_EQ(
      kEncodingConfig->video()->width() * kEncodingConfig->video()->height(),
      static_cast<uint32_t>(kEncodeFeatures.video_pixels));
}

// Test smoothness predictions from DB (WebrtcPerfHistoryService).
TEST(MediaCapabilitiesTests, WebrtcDecodingBasicVideo) {
  test::TaskEnvironment task_environment;
  MediaCapabilitiesTestContext context;
  EXPECT_CALL(context.GetMockPlatform(), GetGpuFactories())
      .Times(testing::AtMost(1));
  const auto* kDecodingConfig = CreateWebrtcDecodingConfig();
  const media::mojom::blink::WebrtcPredictionFeatures kFeatures =
      CreateWebrtcFeatures(/*is_decode=*/true);

  // WebrtcPerfHistoryService should be queried for smoothness. Signal
  // smooth=true.
  EXPECT_CALL(*context.GetWebrtcPerfHistoryService(), GetPerfInfo(_, _, _))
      .WillOnce(WebrtcDbCallback(kFeatures, kFramerate, /*is_smooth=*/true));
  MediaCapabilitiesInfo* info = DecodingInfo(kDecodingConfig, &context);
  EXPECT_TRUE(info->supported());
  EXPECT_TRUE(info->smooth());
  EXPECT_FALSE(info->powerEfficient());

  // Verify DB call was made.
  testing::Mock::VerifyAndClearExpectations(
      context.GetWebrtcPerfHistoryService());

  // Repeat test with smooth=false.
  EXPECT_CALL(*context.GetWebrtcPerfHistoryService(), GetPerfInfo(_, _, _))
      .WillOnce(WebrtcDbCallback(kFeatures, kFramerate, /*is_smooth=*/false));
  info = DecodingInfo(kDecodingConfig, &context);
  EXPECT_TRUE(info->supported());
  EXPECT_FALSE(info->smooth());
  EXPECT_FALSE(info->powerEfficient());
}

TEST(MediaCapabilitiesTests, WebrtcDecodingUnsupportedVideo) {
  test::TaskEnvironment task_environment;
  MediaCapabilitiesTestContext context;
  EXPECT_CALL(context.GetMockPlatform(), GetGpuFactories())
      .Times(testing::AtMost(1));

  const MediaDecodingConfiguration* kDecodingConfig =
      CreateVideoConfig<MediaDecodingConfiguration>("video/FooCodec", "webrtc");

  MediaCapabilitiesInfo* info = DecodingInfo(kDecodingConfig, &context);
  EXPECT_FALSE(info->supported());
  EXPECT_FALSE(info->smooth());
  EXPECT_FALSE(info->powerEfficient());
}

TEST(MediaCapabilitiesTests, WebrtcDecodingSpatialScalability) {
  test::TaskEnvironment task_environment;
  MediaCapabilitiesTestContext context;
  EXPECT_CALL(context.GetMockPlatform(), GetGpuFactories())
      .Times(testing::AtMost(1));

  auto* decoding_config = CreateWebrtcDecodingConfig();
  auto* video_config = decoding_config->getVideoOr(nullptr);
  video_config->setSpatialScalability(false);
  const media::mojom::blink::WebrtcPredictionFeatures kFeatures =
      CreateWebrtcFeatures(/*is_decode=*/true);

  // WebrtcPerfHistoryService should be queried for smoothness. Signal
  // smooth=true.
  EXPECT_CALL(*context.GetWebrtcPerfHistoryService(), GetPerfInfo(_, _, _))
      .WillOnce(WebrtcDbCallback(kFeatures, kFramerate, /*is_smooth=*/true));
  MediaCapabilitiesInfo* info = DecodingInfo(decoding_config, &context);
  EXPECT_TRUE(info->supported());
  EXPECT_TRUE(info->smooth());
  EXPECT_FALSE(info->powerEfficient());

  // Verify DB call was made.
  testing::Mock::VerifyAndClearExpectations(
      context.GetWebrtcPerfHistoryService());

  // Repeat test with spatialScalability=true.
  video_config->setSpatialScalability(true);
  EXPECT_CALL(*context.GetWebrtcPerfHistoryService(), GetPerfInfo(_, _, _))
      .WillOnce(WebrtcDbCallback(kFeatures, kFramerate, /*is_smooth=*/false));
  info = DecodingInfo(decoding_config, &context);
  EXPECT_TRUE(info->supported());
  EXPECT_FALSE(info->smooth());
  EXPECT_FALSE(info->powerEfficient());
}

// WebRTC encodingInfo tests.
TEST(MediaCapabilitiesTests, WebrtcEncodingBasicAudio) {
  test::TaskEnvironment task_environment;
  MediaCapabilitiesTestContext context;
  EXPECT_CALL(context.GetMockPlatform(), GetGpuFactories())
      .Times(testing::AtMost(1));

  const MediaEncodingConfiguration* kEncodingConfig =
      CreateWebrtcAudioEncodingConfig();
  MediaCapabilitiesInfo* info = EncodingInfo(kEncodingConfig, &context);
  EXPECT_TRUE(info->supported());
  EXPECT_TRUE(info->smooth());
  EXPECT_TRUE(info->powerEfficient());
}

TEST(MediaCapabilitiesTests, WebrtcEncodingUnsupportedAudio) {
  test::TaskEnvironment task_environment;
  MediaCapabilitiesTestContext context;
  EXPECT_CALL(context.GetMockPlatform(), GetGpuFactories())
      .Times(testing::AtMost(1));
  const MediaEncodingConfiguration* kEncodingConfig =
      CreateAudioConfig<MediaEncodingConfiguration>("audio/FooCodec", "webrtc");
  MediaCapabilitiesInfo* info = EncodingInfo(kEncodingConfig, &context);
  EXPECT_FALSE(info->supported());
  EXPECT_FALSE(info->smooth());
  EXPECT_FALSE(info->powerEfficient());
}

// Test smoothness predictions from DB (WebrtcPerfHistoryService).
TEST(MediaCapabilitiesTests, WebrtcEncodingBasicVideo) {
  test::TaskEnvironment task_environment;
  MediaCapabilitiesTestContext context;
  EXPECT_CALL(context.GetMockPlatform(), GetGpuFactories())
      .Times(testing::AtMost(1));
  const auto* kEncodingConfig = CreateWebrtcEncodingConfig();
  const media::mojom::blink::WebrtcPredictionFeatures kFeatures =
      CreateWebrtcFeatures(/*is_decode=*/false);

  // WebrtcPerfHistoryService should be queried for smoothness. Signal
  // smooth=true.
  EXPECT_CALL(*context.GetWebrtcPerfHistoryService(), GetPerfInfo(_, _, _))
      .WillOnce(WebrtcDbCallback(kFeatures, kFramerate, /*is_smooth=*/true));
  MediaCapabilitiesInfo* info = EncodingInfo(kEncodingConfig, &context);
  EXPECT_TRUE(info->supported());
  EXPECT_TRUE(info->smooth());
  EXPECT_FALSE(info->powerEfficient());

  // Verify DB call was made.
  testing::Mock::VerifyAndClearExpectations(
      context.GetWebrtcPerfHistoryService());

  // Repeat test with smooth=false.
  EXPECT_CALL(*context.GetWebrtcPerfHistoryService(), GetPerfInfo(_, _, _))
      .WillOnce(WebrtcDbCallback(kFeatures, kFramerate, /*is_smooth=*/false));
  info = EncodingInfo(kEncodingConfig, &context);
  EXPECT_TRUE(info->supported());
  EXPECT_FALSE(info->smooth());
  EXPECT_FALSE(info->powerEfficient());
}

TEST(MediaCapabilitiesTests, WebrtcEncodingUnsupportedVideo) {
  test::TaskEnvironment task_environment;
  MediaCapabilitiesTestContext context;
  EXPECT_CALL(context.GetMockPlatform(), GetGpuFactories())
      .Times(testing::AtMost(1));

  const MediaEncodingConfiguration* kEncodingConfig =
      CreateVideoConfig<MediaEncodingConfiguration>("video/FooCodec", "webrtc");

  MediaCapabilitiesInfo* info = EncodingInfo(kEncodingConfig, &context);
  EXPECT_FALSE(info->supported());
  EXPECT_FALSE(info->smooth());
  EXPECT_FALSE(info->powerEfficient());
}

TEST(MediaCapabilitiesTests, WebrtcEncodingScalabilityMode) {
  test::TaskEnvironment task_environment;
  MediaCapabilitiesTestContext context;
  EXPECT_CALL(context.GetMockPlatform(), GetGpuFactories())
      .Times(testing::AtMost(1));
  auto* encoding_config = CreateWebrtcEncodingConfig();
  auto* video_config = encoding_config->getVideoOr(nullptr);
  video_config->setScalabilityMode("L3T3_KEY");
  const media::mojom::blink::WebrtcPredictionFeatures kFeatures =
      CreateWebrtcFeatures(/*is_decode=*/false);

  // WebrtcPerfHistoryService should be queried for smoothness. Signal
  // smooth=true.
  EXPECT_CALL(*context.GetWebrtcPerfHistoryService(), GetPerfInfo(_, _, _))
      .WillOnce(WebrtcDbCallback(kFeatures, kFramerate, /*is_smooth=*/true));
  MediaCapabilitiesInfo* info = EncodingInfo(encoding_config, &context);
  EXPECT_TRUE(info->supported());
  EXPECT_TRUE(info->smooth());
  EXPECT_FALSE(info->powerEfficient());

  // Verify DB call was made.
  testing::Mock::VerifyAndClearExpectations(
      context.GetWebrtcPerfHistoryService());

  // Repeat with unsupported mode.
  video_config->setScalabilityMode("L3T2_Foo");
  info = EncodingInfo(encoding_config, &context);
  EXPECT_FALSE(info->supported());
  EXPECT_FALSE(info->smooth());
  EXPECT_FALSE(info->powerEfficient());
}

TEST(MediaCapabilitiesTests, WebrtcDecodePowerEfficientIsSmooth) {
  test::TaskEnvironment task_environment;
  // Set up a custom decoding info handler with a GPU factory that returns
  // supported and powerEfficient.
  MediaCapabilitiesTestContext context;
  auto mock_gpu_factories =
      std::make_unique<media::MockGpuVideoAcceleratorFactories>(nullptr);
  WebrtcDecodingInfoHandler decoding_info_handler(
      blink::CreateWebrtcVideoDecoderFactory(
          mock_gpu_factories.get(),
          Platform::Current()->GetRenderingColorSpace(), base::DoNothing()),
      blink::CreateWebrtcAudioDecoderFactory());

  context.GetMediaCapabilities()->set_webrtc_decoding_info_handler_for_test(
      &decoding_info_handler);

  EXPECT_CALL(*mock_gpu_factories, IsDecoderSupportKnown())
      .WillOnce(Return(true));
  EXPECT_CALL(*mock_gpu_factories, IsDecoderConfigSupported(_))
      .WillOnce(Return(media::GpuVideoAcceleratorFactories::Supported::kTrue));

  const auto* kDecodingConfig = CreateWebrtcDecodingConfig();
  MediaCapabilitiesInfo* info = DecodingInfo(kDecodingConfig, &context);
  // Expect that powerEfficient==true implies that smooth==true without querying
  // perf history.
  EXPECT_TRUE(info->supported());
  EXPECT_TRUE(info->smooth());
  EXPECT_TRUE(info->powerEfficient());
}

TEST(MediaCapabilitiesTests, WebrtcDecodeOverridePowerEfficientIsSmooth) {
  test::TaskEnvironment task_environment;
  // Override the default behavior using a field trial. Query smooth from perf
  // history regardless the value of powerEfficient.
  base::test::ScopedFeatureList scoped_feature_list;
  scoped_feature_list.InitWithFeaturesAndParameters(
      // Enabled features w/ parameters
      {{media::kWebrtcMediaCapabilitiesParameters,
        {{MediaCapabilities::kWebrtcDecodeSmoothIfPowerEfficientParamName,
          "false"}}}},
      // Disabled features.
      {});

  // Set up a custom decoding info handler with a GPU factory that returns
  // supported and powerEfficient.
  MediaCapabilitiesTestContext context;
  media::MockGpuVideoAcceleratorFactories mock_gpu_factories(nullptr);
  WebrtcDecodingInfoHandler decoding_info_handler(
      blink::CreateWebrtcVideoDecoderFactory(
          &mock_gpu_factories, Platform::Current()->GetRenderingColorSpace(),
          base::DoNothing()),
      blink::CreateWebrtcAudioDecoderFactory());
  context.GetMediaCapabilities()->set_webrtc_decoding_info_handler_for_test(
      &decoding_info_handler);

  EXPECT_CALL(mock_gpu_factories, IsDecoderSupportKnown())
      .WillOnce(Return(true));
  EXPECT_CALL(mock_gpu_factories, IsDecoderConfigSupported(_))
      .WillOnce(Return(media::GpuVideoAcceleratorFactories::Supported::kTrue));

  const auto* kDecodingConfig = CreateWebrtcDecodingConfig();
  media::mojom::blink::WebrtcPredictionFeatures expected_features =
      CreateWebrtcFeatures(/*is_decode=*/true);
  expected_features.hardware_accelerated = true;

  EXPECT_CALL(*context.GetWebrtcPerfHistoryService(), GetPerfInfo(_, _, _))
      .WillOnce(
          WebrtcDbCallback(expected_features, kFramerate, /*is_smooth=*/false));
  MediaCapabilitiesInfo* info = DecodingInfo(kDecodingConfig, &context);
  // Expect powerEfficient is true but smooth returned from perf history is
  // false.
  EXPECT_TRUE(info->supported());
  EXPECT_FALSE(info->smooth());
  EXPECT_TRUE(info->powerEfficient());
}

TEST(MediaCapabilitiesTests, WebrtcEncodePowerEfficientIsSmooth) {
  test::TaskEnvironment task_environment;
  // Set up a custom decoding info handler with a GPU factory that returns
  // supported and powerEfficient.
  MediaCapabilitiesTestContext context;
  media::MockGpuVideoAcceleratorFactories mock_gpu_factories(nullptr);

  auto video_encoder_factory =
      std::make_unique<RTCVideoEncoderFactory>(&mock_gpu_factories, nullptr);
  // Ensure all the profiles in our mock GPU factory are allowed.
  video_encoder_factory->clear_disabled_profiles_for_testing();

  WebrtcEncodingInfoHandler encoding_info_handler(
      std::move(video_encoder_factory),
      blink::CreateWebrtcAudioEncoderFactory());
  context.GetMediaCapabilities()->set_webrtc_encoding_info_handler_for_test(
      &encoding_info_handler);

  EXPECT_CALL(mock_gpu_factories, IsEncoderSupportKnown())
      .WillOnce(Return(true));
  EXPECT_CALL(mock_gpu_factories, GetVideoEncodeAcceleratorSupportedProfiles())
      .WillOnce(Return(media::VideoEncodeAccelerator::SupportedProfiles{
          {m
"""


```