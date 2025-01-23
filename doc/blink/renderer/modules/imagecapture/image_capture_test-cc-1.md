Response:
The user wants a summary of the functionality of the provided C++ code snippet. This snippet is part of a test file for the `ImageCapture` module in the Chromium Blink engine. The focus is on how constraints are applied to photo settings.

Here's a breakdown of the thought process to arrive at the summary:

1. **Identify the Core Class Under Test:** The file name `image_capture_test.cc` and the use of `image_capture_` member variable in the tests clearly indicate that the `ImageCapture` class is being tested.

2. **Recognize the Test Fixture:** The code defines a test fixture `ImageCaptureConstraintTest` which inherits from `ImageCaptureTest`. This suggests that the tests are specifically focused on constraint handling.

3. **Analyze the `SetUp` Method:** The `SetUp` method initializes `image_capture_` by setting its capabilities (`all_capabilities_`) and default settings (`default_settings_`). This is crucial for understanding the test environment.

4. **Examine the Initialization of Capabilities and Default Settings:** The code block before the `protected:` section meticulously sets various properties of `all_capabilities_` and `default_settings_`, such as `exposureTime`, `colorTemperature`, `iso`, etc. These represent the camera's potential features and their default values. The use of `CreateMediaSettingsRange` and `RangeMean` suggests the testing of range-based constraints. The `DCHECK_LT` and `DCHECK_GT` lines highlight specific conditions set up to ensure the tests for `CheckMaxValues` and `CheckMinValues` are effective.

5. **Understand the Test Structure:** The `TEST_F` macro indicates individual test cases. The names of the test cases (`ApplyBasicBareValueConstraints`, `ApplyBasicExactConstraints`, etc.) provide hints about the types of constraints being tested.

6. **Infer Functionality from Test Names and Logic:**
    * Tests like `ApplyBasicBareValueConstraints`, `ApplyBasicExactConstraints`, `ApplyBasicIdealConstraints`, `ApplyBasicMaxConstraints`, and `ApplyBasicMinConstraints` are clearly testing the application of different types of basic constraints (bare values, exact matches, ideal values, maximum values, and minimum values).
    * `ApplyBasicOverconstrainedConstraints` tests how the system handles constraints that cannot be satisfied by the available capabilities.
    * Tests with "Advanced" in their names (`ApplyFirstAdvancedBareValueConstraints`, `ApplyAdvancedBareValueConstraints`, etc.) likely deal with the "advanced" constraints mechanism defined in the Media Capture and Streams specification.

7. **Identify Interactions with Web Technologies:** The use of `MediaTrackConstraints`, `MediaTrackCapabilities`, and `MediaTrackSettings` are strong indicators of a connection to the WebRTC API, which is exposed to JavaScript. These interfaces allow web developers to specify desired camera settings. The mention of `ScriptPromiseResolver` and `V8TestingScope` signifies the interaction with the V8 JavaScript engine.

8. **Formulate Hypotheses about Inputs and Outputs:** For example, in `ApplyBasicBareValueConstraints`, the input is a set of bare-value constraints, and the expected output is that the `PhotoSettings` are updated to match these values if they are within the capabilities. For `ApplyBasicOverconstrainedConstraints`, the expected output is a rejection of the promise with an `OverconstrainedError`.

9. **Consider User/Developer Errors:**  The "Overconstrained" tests directly address a common error: specifying constraints that the hardware cannot fulfill.

10. **Trace User Operations (Debugging Clues):** To reach this code, a user would typically interact with a web page that uses the `getUserMedia` API to access the camera and the `ImageCapture` API to take photos. The browser's internal logic would then map the JavaScript constraints to the underlying C++ implementation.

11. **Synthesize the Summary:** Combine the insights from the above steps to create a concise summary of the code's function. Focus on the core purpose: testing the application of different constraint types within the `ImageCapture` module.

12. **Address the "Part 2" Instruction:** Since the prompt explicitly states "This is part 2," emphasize that the code continues to test constraint application, building upon the setup from the previous part (even though the previous part wasn't provided).
这是chromium blink引擎源代码文件`blink/renderer/modules/imagecapture/image_capture_test.cc`的第2部分，延续了第1部分的功能，主要集中在测试 `ImageCapture` 接口在应用各种媒体轨道约束（MediaTrackConstraints）时的行为。

**功能归纳：**

这部分代码的主要功能是**测试 `ImageCapture` 对象如何处理和应用不同类型的媒体轨道约束，以配置照片拍摄设置 (PhotoSettings)**。 它测试了各种约束形式，包括：

* **基本约束 (Basic Constraints):**
    * **裸值约束 (Bare Value Constraints):**  直接指定属性的值。
    * **精确约束 (Exact Constraints):**  要求属性的值必须与指定值完全匹配。
    * **理想约束 (Ideal Constraints):**  指定属性的理想值，系统会尝试找到最接近的值。
    * **最大值约束 (Max Constraints):**  限制属性的最大值。
    * **最小值约束 (Min Constraints):**  限制属性的最小值。
    * **无约束 (No Constraints):**  测试当提供空约束时的行为。
    * **过度约束 (Overconstrained Constraints):**  测试当提供的约束无法满足设备能力时的错误处理。

* **高级约束 (Advanced Constraints):**  使用 `advanced` 属性提供一组约束集合，系统会尝试满足其中一个集合。它测试了：
    * **第一个高级约束集合 (First Advanced Constraint Set):**  测试第一个高级约束集合的优先级和应用方式。
    * **多个高级约束集合 (Multiple Advanced Constraint Sets):** 测试在多个高级约束集合存在时，系统如何选择合适的设置。

**与 JavaScript, HTML, CSS 的关系：**

这个 C++ 代码文件是 Blink 渲染引擎的一部分，它处理 Web API 的底层实现。 `ImageCapture` API 是一个 JavaScript API，允许网页访问摄像头并控制照片拍摄设置。

* **JavaScript:**  网页开发者使用 JavaScript 的 `navigator.mediaDevices.getUserMedia()` 获取媒体流，然后使用 `ImageCapture` 接口来访问和控制摄像头的高级功能，包括应用各种约束。例如：

```javascript
navigator.mediaDevices.getUserMedia({ video: true })
  .then(mediaStream => {
    const track = mediaStream.getVideoTracks()[0];
    const imageCapture = new ImageCapture(track);

    // 设置基本约束
    imageCapture.getPhotoCapabilities()
      .then(capabilities => {
        const constraints = {};
        if (capabilities.whiteBalanceMode.includes('manual')) {
          constraints.whiteBalanceMode = 'manual';
        }
        return imageCapture.getPhotoSettings(constraints);
      });

    // 设置更复杂的约束
    const advancedConstraints = {
      advanced: [
        { exposureCompensation: { min: -2 } },
        { iso: { max: 800 } }
      ]
    };
    imageCapture.getPhotoSettings(advancedConstraints);
  });
```

* **HTML:** HTML 提供了网页结构，通过 JavaScript 调用 `ImageCapture` API。例如，一个按钮可以触发拍摄照片的功能。

```html
<button id="captureBtn">拍摄照片</button>
<script>
  document.getElementById('captureBtn').addEventListener('click', () => {
    // ... (获取 ImageCapture 对象并应用约束)
  });
</script>
```

* **CSS:** CSS 负责网页的样式，与 `ImageCapture` 的核心功能没有直接关系，但可以用于布局和美化与摄像头相关的界面元素。

**逻辑推理 (假设输入与输出):**

假设 `all_capabilities_` 定义了摄像头支持的白平衡模式为 `["auto", "manual"]`，曝光补偿范围为 `-3` 到 `3`。

* **假设输入（基本约束 - 精确约束）:**
  ```javascript
  const constraints = { whiteBalanceMode: { exact: "manual" } };
  ```
* **预期输出:** `image_capture_->CheckAndApplyMediaTrackConstraintsToSettings` 应该返回 `true`，并且生成的 `settings` 对象中的 `whiteBalanceMode` 应该设置为 "manual"。

* **假设输入（基本约束 - 过度约束）:**
  ```javascript
  const constraints = { whiteBalanceMode: { exact: "night" } };
  ```
* **预期输出:** `image_capture_->CheckAndApplyMediaTrackConstraintsToSettings` 应该返回 `false`，并且会触发一个 "OverconstrainedError" 错误，因为摄像头不支持 "night" 白平衡模式。

* **假设输入（高级约束）:**
  ```javascript
  const constraints = { advanced: [{ exposureCompensation: { min: 1 } }, { iso: { max: 400 } }] };
  ```
* **预期输出:** `image_capture_->CheckAndApplyMediaTrackConstraintsToSettings` 应该返回 `true`，并且生成的 `settings` 对象中的 `exposureCompensation` 至少为 `1`，或者 `iso` 最大为 `400`，取决于哪个约束集合更容易满足设备的当前状态和能力。

**用户或编程常见的使用错误：**

* **指定不支持的约束值:** 用户或开发者可能会尝试设置超出摄像头能力范围的约束值，例如，将曝光补偿设置为超出 `all_capabilities_->exposureCompensation()` 定义的范围。 这会导致 "OverconstrainedError"。
* **错误地使用约束类型:** 例如，将一个应该使用数组表示的枚举值用字符串表示，或者在需要数字范围的地方使用了布尔值。 虽然类型检查会在一定程度上防止这种情况，但逻辑上的错误仍然可能发生。
* **不理解理想约束的行为:** 开发者可能期望理想约束能够精确地设置到指定值，但实际上系统会选择最接近的可用值。
* **在高级约束中设置相互冲突的约束:**  在一个高级约束集合中设置相互冲突的约束可能会导致意外的结果或错误。

**用户操作到达这里的步骤（调试线索）：**

1. **用户打开一个使用摄像头的网页。**
2. **网页的 JavaScript 代码调用 `navigator.mediaDevices.getUserMedia({ video: true })` 请求访问摄像头。**
3. **用户授权访问摄像头。**
4. **网页的 JavaScript 代码创建 `ImageCapture` 对象，并尝试使用 `getPhotoCapabilities()` 获取摄像头的能力信息。**
5. **网页的 JavaScript 代码构建 `MediaTrackConstraints` 对象，指定期望的照片拍摄设置，例如白平衡模式、曝光补偿等。**
6. **网页的 JavaScript 代码调用 `imageCapture.getPhotoSettings(constraints)` 或 `imageCapture.takePhoto(constraints)` 方法。**
7. **浏览器内部，JavaScript 的调用会传递到 Blink 渲染引擎的 C++ 代码中。**
8. **`blink/renderer/modules/imagecapture/image_capture.cc` 文件中的代码会接收到这些约束。**
9. **`image_capture_test.cc` 文件中的测试用例模拟了上述步骤，并调用 `ImageCapture` 对象的方法，例如 `CheckAndApplyMediaTrackConstraintsToSettings`，来测试约束应用的逻辑。**
10. **当测试失败或需要调试约束应用逻辑时，开发者可能会查看 `image_capture_test.cc` 文件，分析测试用例的设置和预期结果，以找出问题所在。**

总而言之，这部分测试代码专注于验证 `ImageCapture` 模块的核心功能，即如何根据不同的约束条件，正确地配置和应用摄像头的照片拍摄设置，确保 Web API 的行为符合规范预期。

### 提示词
```
这是目录为blink/renderer/modules/imagecapture/image_capture_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
all_capabilities_->setExposureTime(CreateMediaSettingsRange("et"));
    all_capabilities_->setColorTemperature(CreateMediaSettingsRange("ct"));
    all_capabilities_->setIso(CreateMediaSettingsRange("is"));
    all_capabilities_->setBrightness(CreateMediaSettingsRange("br"));
    all_capabilities_->setContrast(CreateMediaSettingsRange("co"));
    all_capabilities_->setSaturation(CreateMediaSettingsRange("sa"));
    all_capabilities_->setSharpness(CreateMediaSettingsRange("sh"));
    all_capabilities_->setFocusDistance(CreateMediaSettingsRange("fd"));
    all_capabilities_->setPan(CreateMediaSettingsRange("pa"));
    all_capabilities_->setTilt(CreateMediaSettingsRange("ti"));
    all_capabilities_->setZoom(CreateMediaSettingsRange("zo"));
    all_capabilities_->setTorch(true);
    all_capabilities_->setBackgroundBlur({true});
    all_capabilities_->setEyeGazeCorrection({false});
    all_capabilities_->setFaceFraming({true, false});
    all_capabilities_->setBackgroundSegmentationMask({false, true});
    all_non_capabilities_->setBackgroundBlur({false});
    all_non_capabilities_->setEyeGazeCorrection({true});
    default_settings_ = MediaTrackSettings::Create();
    default_settings_->setWhiteBalanceMode(
        all_capabilities_->whiteBalanceMode()[0]);
    default_settings_->setExposureMode(all_capabilities_->exposureMode()[0]);
    default_settings_->setFocusMode(all_capabilities_->focusMode()[0]);
    default_settings_->setExposureCompensation(
        RangeMean(all_capabilities_->exposureCompensation()));
    default_settings_->setExposureTime(
        RangeMean(all_capabilities_->exposureTime()));
    default_settings_->setColorTemperature(
        RangeMean(all_capabilities_->colorTemperature()));
    default_settings_->setIso(RangeMean(all_capabilities_->iso()));
    default_settings_->setBrightness(
        RangeMean(all_capabilities_->brightness()));
    default_settings_->setContrast(RangeMean(all_capabilities_->contrast()));
    default_settings_->setSaturation(
        RangeMean(all_capabilities_->saturation()));
    default_settings_->setSharpness(RangeMean(all_capabilities_->sharpness()));
    default_settings_->setFocusDistance(
        RangeMean(all_capabilities_->focusDistance()));
    default_settings_->setPan(RangeMean(all_capabilities_->pan()));
    default_settings_->setTilt(RangeMean(all_capabilities_->tilt()));
    default_settings_->setZoom(RangeMean(all_capabilities_->zoom()));
    default_settings_->setTorch(false);
    default_settings_->setBackgroundBlur(true);
    default_settings_->setEyeGazeCorrection(false);
    default_settings_->setFaceFraming(false);
    default_settings_->setBackgroundSegmentationMask(false);
    // Capabilities and default settings must be chosen so that at least
    // the constraint set {exposureCompensation: {max: ...}} with
    // `all_capabilities_->exposureCompensation()->min() +
    //  kExposureCompensationDelta` is not satisfied by the default settings.
    // Otherwise `CheckMaxValues` does not really check anything.
    DCHECK_LT(all_capabilities_->exposureCompensation()->min() +
                  kExposureCompensationDelta,
              default_settings_->exposureCompensation());
    // Capabilities and default settings must be chosen so that at least
    // the constraint set {focusDistance: {min: ...}} with
    // `all_capabilities_->focusDistance()->min() +
    //  kFocusDistanceDelta` is not satisfied by the default settings.
    // Otherwise `CheckMinValues` does not really check anything.
    DCHECK_GT(all_capabilities_->focusDistance()->min() + kFocusDistanceDelta,
              default_settings_->focusDistance());
  }

 protected:
  void SetUp() override {
    image_capture_->SetCapabilitiesForTesting(all_capabilities_);
    image_capture_->SetSettingsForTesting(default_settings_);
  }

  void TearDown() override {
    image_capture_->SetExecutionContext(nullptr);
    ImageCaptureTest::TearDown();
  }

  Persistent<MediaTrackCapabilities> all_capabilities_;
  Persistent<MediaTrackCapabilities> all_non_capabilities_;
  Persistent<MediaTrackSettings> default_settings_;
};

TEST_F(ImageCaptureConstraintTest, ApplyBasicBareValueConstraints) {
  V8TestingScope scope;
  image_capture_->SetExecutionContext(scope.GetExecutionContext());
  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(
      scope.GetScriptState());

  // Create constraints:
  //   {
  //     whiteBalanceMode: "...",
  //     exposureMode: ["...", ...],
  //     focusMode: ["...", ...],
  //     exposureCompensation: ...,
  //     ...
  //   }
  auto* constraints = MediaTrackConstraints::Create();
  PopulateConstraintSet<ConstrainWithBareValueCreator>(constraints,
                                                       all_capabilities_);
  auto settings = media::mojom::blink::PhotoSettings::New();
  // Should apply the constraints to the settings as is and succeed.
  EXPECT_TRUE(image_capture_->CheckAndApplyMediaTrackConstraintsToSettings(
      &*settings, constraints, resolver));
  CheckExactValues(settings, all_capabilities_);

  // Create constraints: {exposureCompensation: ...}
  constraints = MediaTrackConstraints::Create();
  constraints->setExposureCompensation(
      MakeGarbageCollected<V8UnionConstrainDoubleRangeOrDouble>(
          all_capabilities_->exposureCompensation()->max() + 1));
  settings = media::mojom::blink::PhotoSettings::New();
  // Should apply the closest setting within the capability range and succeed.
  EXPECT_TRUE(image_capture_->CheckAndApplyMediaTrackConstraintsToSettings(
      &*settings, constraints, resolver));
  EXPECT_TRUE(settings->has_exposure_compensation);
  EXPECT_EQ(settings->exposure_compensation,
            all_capabilities_->exposureCompensation()->max());
}

TEST_F(ImageCaptureConstraintTest, ApplyBasicExactConstraints) {
  V8TestingScope scope;
  image_capture_->SetExecutionContext(scope.GetExecutionContext());
  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(
      scope.GetScriptState());

  // Create constraints:
  //   {
  //     whiteBalanceMode: {exact: "..."},
  //     exposureMode: {exact: ["...", ...]},
  //     focusMode: {exact: ["...", ...]},
  //     exposureCompensation: {exact: ...},
  //     ...
  //   }
  auto* constraints = MediaTrackConstraints::Create();
  PopulateConstraintSet<ConstrainWithExactDictionaryCreator>(constraints,
                                                             all_capabilities_);
  auto settings = media::mojom::blink::PhotoSettings::New();
  // Should apply the constraints to the settings as is and succeed.
  EXPECT_TRUE(image_capture_->CheckAndApplyMediaTrackConstraintsToSettings(
      &*settings, constraints, resolver));
  CheckExactValues(settings, all_capabilities_);
}

TEST_F(ImageCaptureConstraintTest, ApplyBasicIdealConstraints) {
  V8TestingScope scope;
  image_capture_->SetExecutionContext(scope.GetExecutionContext());
  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(
      scope.GetScriptState());

  // Create constraints:
  //   {
  //     whiteBalanceMode: {ideal: "..."},
  //     exposureMode: {ideal: ["...", ...]},
  //     focusMode: {ideal: ["...", ...]},
  //     exposureCompensation: {ideal: ...},
  //     ...
  //   }
  auto* full_constraints = MediaTrackConstraints::Create();
  PopulateConstraintSet<ConstrainWithIdealDictionaryCreator>(full_constraints,
                                                             all_capabilities_);
  auto settings = media::mojom::blink::PhotoSettings::New();
  // Should apply the constraints to the settings as is and succeed.
  EXPECT_TRUE(image_capture_->CheckAndApplyMediaTrackConstraintsToSettings(
      &*settings, full_constraints, resolver));
  CheckExactValues(settings, all_capabilities_);

  // Create constraints: {exposureCompensation: {ideal: ...}}
  auto* constraints = MediaTrackConstraints::Create();
  constraints->setExposureCompensation(
      MakeGarbageCollected<V8UnionConstrainDoubleRangeOrDouble>(
          ConstrainWithIdealDictionaryCreator::Create(
              all_capabilities_->exposureCompensation()->max() + 1)));
  settings = media::mojom::blink::PhotoSettings::New();
  // Should apply the closest setting within the capability range and succeed.
  EXPECT_TRUE(image_capture_->CheckAndApplyMediaTrackConstraintsToSettings(
      &*settings, constraints, resolver));
  EXPECT_TRUE(settings->has_exposure_compensation);
  EXPECT_EQ(settings->exposure_compensation,
            all_capabilities_->exposureCompensation()->max());

  // Reuse `full_constraints` but remove capabilities.
  image_capture_->SetCapabilitiesForTesting(
      MakeGarbageCollected<MediaTrackCapabilities>());
  settings = media::mojom::blink::PhotoSettings::New();
  // Shuold ignore ideal constraints without capabilities and succeed.
  EXPECT_TRUE(image_capture_->CheckAndApplyMediaTrackConstraintsToSettings(
      &*settings, full_constraints, resolver));
  CheckNoValues(settings, full_constraints->pointsOfInterest()
                              ->GetAsConstrainPoint2DParameters()
                              ->ideal()
                              .size());
}

TEST_F(ImageCaptureConstraintTest, ApplyBasicMaxConstraints) {
  V8TestingScope scope;
  image_capture_->SetExecutionContext(scope.GetExecutionContext());
  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(
      scope.GetScriptState());

  // Create constraints:
  //   {
  //     whiteBalanceMode: {},
  //     exposureMode: {},
  //     focusMode: {},
  //     exposureCompensation: {max: ...},
  //     ...
  //   }
  auto* constraints = MediaTrackConstraints::Create();
  PopulateConstraintSet<ConstrainWithMaxOrEmptyDictionaryCreator>(
      constraints, all_capabilities_);
  auto settings = media::mojom::blink::PhotoSettings::New();
  // Should apply the max constraints to the current settings and succeed.
  EXPECT_TRUE(image_capture_->CheckAndApplyMediaTrackConstraintsToSettings(
      &*settings, constraints, resolver));
  CheckMaxValues(settings, all_capabilities_, default_settings_);
}

TEST_F(ImageCaptureConstraintTest, ApplyBasicMinConstraints) {
  V8TestingScope scope;
  image_capture_->SetExecutionContext(scope.GetExecutionContext());
  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(
      scope.GetScriptState());

  // Create constraints:
  //   {
  //     whiteBalanceMode: {},
  //     exposureMode: {},
  //     focusMode: {},
  //     exposureCompensation: {min: ...},
  //     ...
  //   }
  auto* constraints = MediaTrackConstraints::Create();
  PopulateConstraintSet<ConstrainWithMinOrEmptyDictionaryCreator>(
      constraints, all_capabilities_);
  auto settings = media::mojom::blink::PhotoSettings::New();
  // Should apply the min constraints to the current settings and succeed.
  EXPECT_TRUE(image_capture_->CheckAndApplyMediaTrackConstraintsToSettings(
      &*settings, constraints, resolver));
  CheckMinValues(settings, all_capabilities_, default_settings_);
}

// If an empty list has been given as the value for a constraint, it MUST be
// interpreted as if the constraint were not specified (in other words,
// an empty constraint == no constraint).
// https://w3c.github.io/mediacapture-main/#dfn-selectsettings
TEST_F(ImageCaptureConstraintTest, ApplyBasicNoConstraints) {
  V8TestingScope scope;
  image_capture_->SetExecutionContext(scope.GetExecutionContext());
  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(
      scope.GetScriptState());

  // Create constraints:
  //   {
  //     whiteBalanceMode: [],
  //     exposureMode: {exact: []},
  //     focusMode: {ideal: []},
  //     pointsOfInterest: {exact: []}
  //   }
  auto* constraints = MediaTrackConstraints::Create();
  constraints->setWhiteBalanceMode(
      MakeGarbageCollected<
          V8UnionConstrainDOMStringParametersOrStringOrStringSequence>(
          Vector<String>()));
  constraints->setExposureMode(
      MakeGarbageCollected<
          V8UnionConstrainDOMStringParametersOrStringOrStringSequence>(
          ConstrainWithExactDictionaryCreator::Create(Vector<String>())));
  constraints->setFocusMode(
      MakeGarbageCollected<
          V8UnionConstrainDOMStringParametersOrStringOrStringSequence>(
          ConstrainWithIdealDictionaryCreator::Create(Vector<String>())));
  constraints->setPointsOfInterest(
      MakeGarbageCollected<V8UnionConstrainPoint2DParametersOrPoint2DSequence>(
          ConstrainWithExactDictionaryCreator::Create(
              HeapVector<Member<Point2D>>())));
  auto settings = media::mojom::blink::PhotoSettings::New();
  // Should ignore empty sequences and succeed.
  EXPECT_TRUE(image_capture_->CheckAndApplyMediaTrackConstraintsToSettings(
      &*settings, constraints, resolver));
  CheckNoValues(settings);
}

TEST_F(ImageCaptureConstraintTest, ApplyBasicOverconstrainedConstraints) {
  V8TestingScope scope;
  image_capture_->SetExecutionContext(scope.GetExecutionContext());
  auto settings = media::mojom::blink::PhotoSettings::New();

  // Create constraints: {whiteBalanceMode: {exact: "..."}}
  auto* constraints = MediaTrackConstraints::Create();
  constraints->setWhiteBalanceMode(
      MakeGarbageCollected<
          V8UnionConstrainDOMStringParametersOrStringOrStringSequence>(
          ConstrainWithExactDictionaryCreator::Create(
              all_non_capabilities_->whiteBalanceMode()[0])));
  auto* capture_error = MakeGarbageCollected<CaptureErrorFunction>();
  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(
      scope.GetScriptState());
  resolver->Promise().Catch(scope.GetScriptState(), capture_error);
  EXPECT_FALSE(image_capture_->CheckAndApplyMediaTrackConstraintsToSettings(
      &*settings, constraints, resolver));
  scope.PerformMicrotaskCheckpoint();  // Resolve/reject promises.
  EXPECT_TRUE(capture_error->WasCalled());
  EXPECT_EQ(capture_error->Name(), "OverconstrainedError");
  EXPECT_EQ(capture_error->Constraint(), "whiteBalanceMode");

  // Create constraints: {whiteBalanceMode: {exact: ["..."]}}
  constraints = MediaTrackConstraints::Create();
  constraints->setWhiteBalanceMode(
      MakeGarbageCollected<
          V8UnionConstrainDOMStringParametersOrStringOrStringSequence>(
          ConstrainWithExactDictionaryCreator::Create(
              all_non_capabilities_->whiteBalanceMode())));
  capture_error = MakeGarbageCollected<CaptureErrorFunction>();
  resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(
      scope.GetScriptState());
  resolver->Promise().Catch(scope.GetScriptState(), capture_error);
  EXPECT_FALSE(image_capture_->CheckAndApplyMediaTrackConstraintsToSettings(
      &*settings, constraints, resolver));
  scope.PerformMicrotaskCheckpoint();  // Resolve/reject promises.
  EXPECT_TRUE(capture_error->WasCalled());
  EXPECT_EQ(capture_error->Name(), "OverconstrainedError");
  EXPECT_EQ(capture_error->Constraint(), "whiteBalanceMode");

  // Create constraints: {exposureCompensation: {exact: ...}}
  constraints = MediaTrackConstraints::Create();
  constraints->setExposureCompensation(
      MakeGarbageCollected<V8UnionConstrainDoubleRangeOrDouble>(
          ConstrainWithExactDictionaryCreator::Create(
              all_capabilities_->exposureCompensation()->min() - 1)));
  capture_error = MakeGarbageCollected<CaptureErrorFunction>();
  resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(
      scope.GetScriptState());
  resolver->Promise().Catch(scope.GetScriptState(), capture_error);
  EXPECT_FALSE(image_capture_->CheckAndApplyMediaTrackConstraintsToSettings(
      &*settings, constraints, resolver));
  scope.PerformMicrotaskCheckpoint();  // Resolve/reject promises.
  EXPECT_TRUE(capture_error->WasCalled());
  EXPECT_EQ(capture_error->Name(), "OverconstrainedError");
  EXPECT_EQ(capture_error->Constraint(), "exposureCompensation");

  // Create constraints: {exposureCompensation: {max: ...}}
  constraints = MediaTrackConstraints::Create();
  constraints->setExposureCompensation(
      MakeGarbageCollected<V8UnionConstrainDoubleRangeOrDouble>(
          ConstrainWithMaxDictionaryCreator::Create(
              all_capabilities_->exposureCompensation()->min() - 1)));
  capture_error = MakeGarbageCollected<CaptureErrorFunction>();
  resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(
      scope.GetScriptState());
  resolver->Promise().Catch(scope.GetScriptState(), capture_error);
  EXPECT_FALSE(image_capture_->CheckAndApplyMediaTrackConstraintsToSettings(
      &*settings, constraints, resolver));
  scope.PerformMicrotaskCheckpoint();  // Resolve/reject promises.
  EXPECT_TRUE(capture_error->WasCalled());
  EXPECT_EQ(capture_error->Name(), "OverconstrainedError");
  EXPECT_EQ(capture_error->Constraint(), "exposureCompensation");

  // Create constraints: {exposureCompensation: {min: ...}}
  constraints = MediaTrackConstraints::Create();
  constraints->setExposureCompensation(
      MakeGarbageCollected<V8UnionConstrainDoubleRangeOrDouble>(
          ConstrainWithMinDictionaryCreator::Create(
              all_capabilities_->exposureCompensation()->max() + 1)));
  capture_error = MakeGarbageCollected<CaptureErrorFunction>();
  resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(
      scope.GetScriptState());
  resolver->Promise().Catch(scope.GetScriptState(), capture_error);
  EXPECT_FALSE(image_capture_->CheckAndApplyMediaTrackConstraintsToSettings(
      &*settings, constraints, resolver));
  scope.PerformMicrotaskCheckpoint();  // Resolve/reject promises.
  EXPECT_TRUE(capture_error->WasCalled());
  EXPECT_EQ(capture_error->Name(), "OverconstrainedError");
  EXPECT_EQ(capture_error->Constraint(), "exposureCompensation");

  // Create constraints: {backgroundBlur: {exact: ...}}
  constraints = MediaTrackConstraints::Create();
  constraints->setBackgroundBlur(
      MakeGarbageCollected<V8UnionBooleanOrConstrainBooleanParameters>(
          ConstrainWithExactDictionaryCreator::Create(
              all_non_capabilities_->backgroundBlur()[0])));
  capture_error = MakeGarbageCollected<CaptureErrorFunction>();
  resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(
      scope.GetScriptState());
  resolver->Promise().Catch(scope.GetScriptState(), capture_error);
  EXPECT_FALSE(image_capture_->CheckAndApplyMediaTrackConstraintsToSettings(
      &*settings, constraints, resolver));
  scope.PerformMicrotaskCheckpoint();  // Resolve/reject promises.
  EXPECT_TRUE(capture_error->WasCalled());
  EXPECT_EQ(capture_error->Name(), "OverconstrainedError");
  EXPECT_EQ(capture_error->Constraint(), "backgroundBlur");

  // Reuse previous constraints but remove capabilities.
  image_capture_->SetCapabilitiesForTesting(
      MakeGarbageCollected<MediaTrackCapabilities>());
  capture_error = MakeGarbageCollected<CaptureErrorFunction>();
  resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(
      scope.GetScriptState());
  resolver->Promise().Catch(scope.GetScriptState(), capture_error);
  EXPECT_FALSE(image_capture_->CheckAndApplyMediaTrackConstraintsToSettings(
      &*settings, constraints, resolver));
  scope.PerformMicrotaskCheckpoint();  // Resolve/reject promises.
  EXPECT_TRUE(capture_error->WasCalled());
  EXPECT_EQ(capture_error->Name(), "OverconstrainedError");
  EXPECT_EQ(capture_error->Message(), "Unsupported constraint");
}

TEST_F(ImageCaptureConstraintTest, ApplyFirstAdvancedBareValueConstraints) {
  V8TestingScope scope;
  image_capture_->SetExecutionContext(scope.GetExecutionContext());
  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(
      scope.GetScriptState());

  // Create constraints:
  //   {advanced: [
  //     {
  //       whiteBalanceMode: "...",
  //       exposureMode: ["...", ...],
  //       focusMode: ["...", ...],
  //       exposureCompensation: ...,
  //       ...
  //     }
  //   ]}
  auto* constraint_set = MediaTrackConstraintSet::Create();
  PopulateConstraintSet<ConstrainWithBareValueCreator>(constraint_set,
                                                       all_capabilities_);
  auto* constraints = MediaTrackConstraints::Create();
  constraints->setAdvanced({constraint_set});
  auto settings = media::mojom::blink::PhotoSettings::New();
  // Should apply the constraints to the settings as is and succeed.
  EXPECT_TRUE(image_capture_->CheckAndApplyMediaTrackConstraintsToSettings(
      &*settings, constraints, resolver));
  // TODO(crbug.com/1408091): This is not spec compliant.
  // ImageCapture should support DOMString sequence constraints (used above for
  // exposureMode and focusMode) in the first advanced constraint set.
  CheckExactValues(settings, all_capabilities_, ExpectHasPanTiltZoom(true),
                   ExpectHasExposureModeAndFocusMode(false));
}

TEST_F(ImageCaptureConstraintTest, ApplyFirstAdvancedExactConstraints) {
  V8TestingScope scope;
  image_capture_->SetExecutionContext(scope.GetExecutionContext());
  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(
      scope.GetScriptState());

  // Create constraints:
  //   {advanced: [
  //     {
  //       whiteBalanceMode: {exact: "..."},
  //       exposureMode: {exact: ["...", ...]},
  //       focusMode: {exact: ["...", ...]},
  //       exposureCompensation: {exact: ...},
  //       ...
  //     }
  //   ]}
  auto* constraint_set = MediaTrackConstraintSet::Create();
  PopulateConstraintSet<ConstrainWithExactDictionaryCreator>(constraint_set,
                                                             all_capabilities_);
  auto* constraints = MediaTrackConstraints::Create();
  constraints->setAdvanced({constraint_set});
  auto settings = media::mojom::blink::PhotoSettings::New();
  // Should apply the constraints to the settings as is and succeed.
  EXPECT_TRUE(image_capture_->CheckAndApplyMediaTrackConstraintsToSettings(
      &*settings, constraints, resolver));
  // TODO(crbug.com/1408091): This is not spec compliant.
  // ImageCapture should support non-bare value constraints in the first
  // advanced constraint set.
  CheckNoValues(settings);
}

TEST_F(ImageCaptureConstraintTest, ApplyFirstAdvancedIdealConstraints) {
  V8TestingScope scope;
  image_capture_->SetExecutionContext(scope.GetExecutionContext());
  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(
      scope.GetScriptState());

  // Create constraints:
  //   {advanced: [
  //     {
  //       whiteBalanceMode: {ideal: "..."},
  //       exposureMode: {ideal: ["...", ...]},
  //       focusMode: {ideal: ["...", ...]},
  //       exposureCompensation: {ideal: ...},
  //       ...
  //     }
  //   ]}
  auto* constraint_set = MediaTrackConstraintSet::Create();
  PopulateConstraintSet<ConstrainWithIdealDictionaryCreator>(constraint_set,
                                                             all_capabilities_);
  auto* constraints = MediaTrackConstraints::Create();
  constraints->setAdvanced({constraint_set});
  auto settings = media::mojom::blink::PhotoSettings::New();
  // Shuold ignore ideal constraints in advanced constraint sets and succeed.
  EXPECT_TRUE(image_capture_->CheckAndApplyMediaTrackConstraintsToSettings(
      &*settings, constraints, resolver));
  // The fitness distance
  // (https://w3c.github.io/mediacapture-main/#dfn-fitness-distance) between
  // an ideal constraint and a setting in a settings dictionary is always
  // between 0.0 and 1.0 (inclusive).
  // Therefore, the fitness distance between a constraint set containing only
  // ideal constraints and a settings dictionary (being the sum of the above
  // fitness distances in [0.0, 1.0]) is always finite.
  // On the other hand, the SelectSettings algorithm
  // (https://w3c.github.io/mediacapture-main/#dfn-selectsettings) iterates
  // over the advanced constraint sets and computes the fitness distance
  // between the advanced constraint sets and each settings dictionary
  // candidate and if the fitness distance is finite for one or more settings
  // dictionary candidates, it keeps those settings dictionary candidates.
  //
  // All in all, in this test case all the fitness distances are finite and
  // therefore the SelectSettings algorithm keeps all settings dictionary
  // candidates instead of favouring a particular settings dictionary and
  // therefore `CheckAndApplyMediaTrackConstraintsToSettings` does not set
  // settings in `settings`.
  CheckNoValues(settings);
}

TEST_F(ImageCaptureConstraintTest,
       ApplyFirstAdvancedOverconstrainedConstraints) {
  V8TestingScope scope;
  image_capture_->SetExecutionContext(scope.GetExecutionContext());
  const HeapVector<Member<Point2D>> points_of_interest = {
      CreatePoint2D(0.25, 0.75)};
  auto settings = media::mojom::blink::PhotoSettings::New();

  // Create constraints: {advanced: [{whiteBalanceMode: "..."}]}
  auto* constraint_set = MediaTrackConstraintSet::Create();
  constraint_set->setWhiteBalanceMode(
      MakeGarbageCollected<
          V8UnionConstrainDOMStringParametersOrStringOrStringSequence>(
          all_non_capabilities_->whiteBalanceMode()[0]));
  auto* constraints = MediaTrackConstraints::Create();
  constraints->setAdvanced({constraint_set});
  auto* capture_error = MakeGarbageCollected<CaptureErrorFunction>();
  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(
      scope.GetScriptState());
  resolver->Promise().Catch(scope.GetScriptState(), capture_error);
  // TODO(crbug.com/1408091): This is not spec compliant. This should not fail.
  // Instead, should discard the first advanced constraint set and succeed.
  EXPECT_FALSE(image_capture_->CheckAndApplyMediaTrackConstraintsToSettings(
      &*settings, constraints, resolver));
  scope.PerformMicrotaskCheckpoint();  // Resolve/reject promises.
  EXPECT_TRUE(capture_error->WasCalled());
  EXPECT_EQ(capture_error->Name(), "OverconstrainedError");
  EXPECT_EQ(capture_error->Constraint(), "whiteBalanceMode");

  // Create constraints: {advanced: [{pointsOfInterest: [...], pan: false}]}
  constraint_set = MediaTrackConstraintSet::Create();
  constraint_set->setPointsOfInterest(
      MakeGarbageCollected<V8UnionConstrainPoint2DParametersOrPoint2DSequence>(
          points_of_interest));
  constraint_set->setPan(
      MakeGarbageCollected<V8UnionBooleanOrConstrainDoubleRangeOrDouble>(
          false));
  constraints = MediaTrackConstraints::Create();
  constraints->setAdvanced({constraint_set});
  capture_error = MakeGarbageCollected<CaptureErrorFunction>();
  resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(
      scope.GetScriptState());
  resolver->Promise().Catch(scope.GetScriptState(), capture_error);
  // TODO(crbug.com/1408091): This is not spec compliant. This should not fail.
  // Instead, should discard the first advanced constraint set and succeed.
  EXPECT_FALSE(image_capture_->CheckAndApplyMediaTrackConstraintsToSettings(
      &*settings, constraints, resolver));
  scope.PerformMicrotaskCheckpoint();  // Resolve/reject promises.
  EXPECT_TRUE(capture_error->WasCalled());
  EXPECT_EQ(capture_error->Name(), "OverconstrainedError");
  EXPECT_EQ(capture_error->Constraint(), "pan");

  // Remove capabilities (does not affect pointsOfInterest).
  image_capture_->SetCapabilitiesForTesting(
      MakeGarbageCollected<MediaTrackCapabilities>());
  // Create constraints: {advanced: [{pointsOfInterest: [...], pan: true}]}
  constraint_set = MediaTrackConstraintSet::Create();
  constraint_set->setPointsOfInterest(
      MakeGarbageCollected<V8UnionConstrainPoint2DParametersOrPoint2DSequence>(
          points_of_interest));
  constraint_set->setPan(
      MakeGarbageCollected<V8UnionBooleanOrConstrainDoubleRangeOrDouble>(true));
  constraints = MediaTrackConstraints::Create();
  constraints->setAdvanced({constraint_set});
  capture_error = MakeGarbageCollected<CaptureErrorFunction>();
  resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(
      scope.GetScriptState());
  resolver->Promise().Catch(scope.GetScriptState(), capture_error);
  // TODO(crbug.com/1408091): This is not spec compliant. This should not fail.
  // Instead, should discard the first advanced constraint set and succeed.
  EXPECT_FALSE(image_capture_->CheckAndApplyMediaTrackConstraintsToSettings(
      &*settings, constraints, resolver));
  scope.PerformMicrotaskCheckpoint();  // Resolve/reject promises.
  EXPECT_TRUE(capture_error->WasCalled());
  EXPECT_EQ(capture_error->Name(), "OverconstrainedError");
  EXPECT_EQ(capture_error->Constraint(), "pan");
}

TEST_F(ImageCaptureConstraintTest, ApplyAdvancedBareValueConstraints) {
  V8TestingScope scope;
  image_capture_->SetExecutionContext(scope.GetExecutionContext());
  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(
      scope.GetScriptState());

  // Create constraints:
  //   {advanced: [
  //     {},
  //     {
  //       whiteBalanceMode: "...",
  //       exposureMode: ["...", ...],
  //       focusMode: ["...", ...],
  //       exposureCompensation: ...,
  //       ...
  //     }
  //   ]}
  auto* constraint_set = MediaTrackConstraintSet::Create();
  PopulateConstraintSet<ConstrainWithBareValueCreator>(constraint_set,
                                                       all_capabilities_);
  auto* constraints = MediaTrackConstraints::Create();
  constraints->setAdvanced({MediaTrackConstraintSet::Create(), constraint_set});
  auto settings = media::mojom::blink::PhotoSettings::New();
  // Should apply the constraints to the settings as is and succeed.
  EXPECT_TRUE(image_capture_->CheckAndApplyMediaTrackConstraintsToSettings(
      &*settings, constraints, resolver));
  CheckExactValues(settings, all_capabilities_);
}

TEST_F(ImageCaptureConstraintTest, ApplyAdvancedExactConstraints) {
  V8TestingScope scope;
  image_capture_->SetExecutionContext(scope.GetExecutionContext());
  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(
      scope.GetScriptState());

  // Create constraints:
  //   {advanced: [
  //     {},
  //     {
  //       whiteBalanceMode: {exact: "..."},
  //       exposureMode: {exact: ["...", ...]},
  //       focusMode: {exact: ["...", ...]},
  //       exposureCompensation: {exact: ...},
  //       ...
  //     }
  //   ]}
  auto* constraint_set = MediaTrackConstraintSet::Create();
  PopulateConstraintSet<ConstrainWithExactDictionaryCreator>(constraint_set,
                                                             all_capabilities_);
  auto* constraints = MediaTrackConstraints::Create();
  constraints->setAdvanced({MediaTrackConstraintSet::Create(), constraint_set});
  auto settings = media::mojom::blink::PhotoSettings::New();
  // Should apply the constraints to the settings as is and succeed.
  EXPECT_TRUE(image_capture_->CheckAndApplyMediaTrackConstraintsToSettings(
      &*settings, constraints, resolver));
  CheckExactValues(settings, all_capabilities_);
}

TEST_F(ImageCaptureConstraintTest, ApplyAdvancedIdealConstraints) {
  V8TestingScope scope;
  image_capture_->SetExecutionContext(scope.GetExecutionContext());
  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(
      scope.GetScriptState());

  // Create constraints:
  //   {advanced: [
  //     {},
  //     {
  //       whiteBalanceMode: {ideal: "..."},
  //       exposureMode: {ideal: ["...", ...]},
  //       focusMode: {ideal: ["...", ...]},
  //       exposureCompensation: {ideal: ...},
  //       ...
  //     }
  //   ]}
  auto* constraint_set = MediaTrackConstraintSet::Create();
  PopulateConstraintSet<ConstrainWithIdealDictionaryCreator>(constraint_set,
                                                             all_capabilities_);
  auto* constraints = MediaTrackConstraints::Create();
  constraints->setAdvanced({MediaTrackConstraintSet::Create(), constraint_set});
  auto settings = media::mojom::blink::PhotoSettings::New();
  // Shuold ignore ideal constraints in advanced constraint sets and succeed.
  EXPECT_TRUE(image_capture_->CheckAndApplyMediaTrackConstraintsToSettings(
      &*settings, constraints, resolver));
  // The fitness distance
  // (https://w3c.github.io/mediacapture-main/#dfn-fitness-distance) between
  // an ideal constraint and a setting in a settings dictionary is always
  // between 0.0 and 1.0 (inclusive).
  // Therefore, the fitness distance between a constraint set containing only
  // ideal constraints and a settings dictionary (being the sum of the above
  // fitness distances in [0.0, 1.0]) is always finite.
  // On the other hand, the SelectSettings algorithm
  // (https://w3c.github.io/mediacapture-main/#dfn-selectsett
```