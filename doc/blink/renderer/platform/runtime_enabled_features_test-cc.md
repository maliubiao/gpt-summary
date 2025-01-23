Response: Let's break down the thought process for analyzing this C++ test file.

**1. Initial Understanding of the File's Purpose:**

The filename `runtime_enabled_features_test.cc` immediately suggests that this file is for testing the functionality related to "runtime enabled features."  The inclusion of headers like `<gtest/gtest.h>`, `third_party/blink/public/common/features.h`, and `third_party/blink/renderer/platform/runtime_enabled_features.h` confirms this. Specifically, it's likely testing how features can be toggled on or off during runtime.

**2. Identifying Key Components and Concepts:**

* **`RuntimeEnabledFeatures`:** This is the central class being tested. It likely manages the state (enabled/disabled) of various features.
* **Features:** The code mentions "TestFeature," "TestFeatureImplied," "TestFeatureDependent," and "OriginTrialsSampleAPI." These are the features being toggled and tested.
* **Relationships between Features:** The comments clearly indicate dependencies: "TestFeatureDependent depends_on TestFeatureImplied implied_by TestFeature."  This is a crucial part of the testing logic.
* **Scoped Testing:** The presence of `ScopedTestFeatureForTest`, `ScopedTestFeatureImpliedForTest`, etc., suggests a mechanism for temporarily enabling/disabling features within a specific scope (like a test case).
* **Protected vs. Non-Protected:** The existence of `RuntimeProtectedEnabledFeaturesTestTraits` and corresponding `ScopedTestFeatureProtectedForTest` classes indicates that there's a concept of "protected" features, likely with different access or usage restrictions.
* **Origin Trials:**  The mentions of "OriginTrialsSampleAPI" point to testing the integration with the Origin Trials mechanism, which allows developers to experiment with new web platform features in production.
* **`base::FeatureList`:** The inclusion of `<third_party/blink/public/common/features.h>` and the test `CopiedFromBaseFaetureIf` signals that Blink's runtime enabled features interact with the general Chromium feature flags system managed by `base::FeatureList`.
* **Testing Framework (GTest):** The use of `TEST_F`, `TYPED_TEST_SUITE_P`, `EXPECT_TRUE`, `EXPECT_FALSE` clearly identifies this as a Google Test (GTest) file.

**3. Deconstructing the Code Structure:**

* **Traits Classes (`RuntimeEnabledFeaturesTestTraits`, `RuntimeProtectedEnabledFeaturesTestTraits`):** These classes act as interfaces or strategies, providing a consistent way to interact with `RuntimeEnabledFeatures` and its protected counterpart. This allows for writing generic tests (`AbstractRuntimeEnabledFeaturesTest`) that can be applied to both protected and non-protected features.
* **Abstract Test Class (`AbstractRuntimeEnabledFeaturesTest`):** This is a template class parameterized by the traits class. It contains the core test logic, making it reusable. The `SetUp` and `TearDown` methods ensure a clean state before and after each test.
* **Individual Test Cases (`Relationship`, `ScopedForTest`, `BackupRestore`, etc.):** These are the specific tests that exercise different aspects of the runtime enabled features functionality.
* **`Backup` Class:** This class likely provides a way to save and restore the state of the runtime enabled features, used in the `BackupRestore` test.

**4. Analyzing Individual Test Cases:**

* **`Relationship`:** Tests the basic dependencies and implications between the features by directly setting their enabled states. It verifies that enabling a feature also enables implied features, and that dependent features only work if their dependencies are met.
* **`ScopedForTest`:** Focuses on the behavior of the scoped testing mechanism. It verifies that enabling a feature within a scope only affects its state within that scope. It also tests the interaction of nested scopes.
* **`BackupRestore`:** Tests the `Backup` functionality. It checks if the state of features can be saved and correctly restored after modifications.
* **`OriginTrialsByRuntimeEnabled`:** Specifically tests how the `RuntimeEnabledFeatures` system interacts with Origin Trials. It verifies the implied and dependent relationships in the context of Origin Trials.
* **`CopiedFromBaseFaetureIf`:** Tests the interaction with Chromium's `base::FeatureList`. It checks if the state of a Blink feature can be influenced by the global feature flags.

**5. Connecting to Web Technologies (JavaScript, HTML, CSS):**

This is where we connect the low-level C++ code to the user-facing web technologies. The key is to understand *why* these runtime-enabled features exist. They are used to:

* **Implement experimental features:**  New JavaScript APIs, CSS properties, or HTML elements might be introduced as experimental features, controlled by runtime flags. This allows browser developers to test and gather feedback without fully committing to the feature.
* **A/B testing:**  Different groups of users might have different features enabled to evaluate their impact.
* **Gradual rollout:** Features might be initially disabled and then gradually enabled for more users over time.
* **Platform-specific behavior:** Some features might only be available on certain platforms or under specific conditions.

**6. Identifying Potential User/Programming Errors:**

This is about anticipating how developers or the system itself might misuse or encounter issues with this functionality.

**7. Refining the Explanation:**

After this detailed analysis, we can formulate a clear and comprehensive explanation of the file's purpose, its relation to web technologies, and potential error scenarios. The process involves going from a high-level understanding to a detailed examination of the code and then connecting it back to the broader context of web development.
这个文件 `blink/renderer/platform/runtime_enabled_features_test.cc` 的主要功能是**测试 Blink 渲染引擎中用于控制功能开关的 `RuntimeEnabledFeatures` 机制**。

更具体地说，它测试了以下方面：

**1. 功能开关的基本行为:**

* **启用和禁用功能:** 验证通过 `RuntimeEnabledFeatures` API 可以正确地设置和读取功能的状态（启用或禁用）。
* **功能之间的依赖关系:** 测试功能之间通过 `implied_by` 和 `depends_on` 定义的依赖关系是否生效。例如，如果 Feature A `implied_by` Feature B，那么启用 Feature B 应该同时启用 Feature A。如果 Feature C `depends_on` Feature D，那么 Feature C 只有在 Feature D 也启用的情况下才能启用。

**2. Scoped 功能开关:**

* **临时启用/禁用功能:** 测试 `ScopedTestFeatureForTest` 等类提供的在特定作用域内临时改变功能状态的能力。这对于单元测试非常有用，可以针对特定功能启用或禁用的场景进行测试，而不会影响其他测试。

**3. 功能开关的备份和恢复:**

* **保存和恢复功能状态:** 测试 `RuntimeEnabledFeatures::Backup` 类提供的备份和恢复功能状态的能力。这允许在进行一些可能修改功能状态的操作后，将功能状态恢复到之前的状态。

**4. 与 Origin Trials 的集成:**

* **通过 Runtime Flags 控制 Origin Trials 功能:** 测试通过 `RuntimeEnabledFeatures` 的 API 可以控制由 Origin Trials 机制控制的功能的启用状态。

**5. 与 Chromium Feature Flags 的同步:**

* **从 `base::FeatureList` 获取状态:** 测试 `WebRuntimeFeatures::UpdateStatusFromBaseFeatures()` 函数，验证 Blink 的功能开关可以根据 Chromium 的 `base::FeatureList` 中的 Feature Flags 进行初始化或更新。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

`RuntimeEnabledFeatures` 机制直接关系到 Blink 引擎对 JavaScript, HTML, CSS 新特性的支持。Blink 使用这个机制来控制哪些新的语言特性、API、元素或属性在当前环境下是可用的。这使得 Blink 能够：

* **实现实验性功能:**  新的 JavaScript API、CSS 属性或 HTML 元素可以先以 "flag" 的形式存在，只有在对应的 `RuntimeEnabledFeatures` 被启用后，浏览器才会解析和执行相关的代码。
* **进行 A/B 测试:**  可以通过不同的功能开关配置，将用户分成不同的组，体验不同的功能组合，用于收集数据和评估功能效果。
* **逐步推广新功能:**  一个新功能可能会先在 Canary 或 Dev 版本中启用，然后逐步推广到 Beta 和 Stable 版本，而这个过程可以通过 `RuntimeEnabledFeatures` 进行控制。

**举例说明:**

假设有一个新的 JavaScript API 叫做 `navigator.newFancyAPI()`,  它在 Blink 中由一个名为 `NewFancyAPI` 的 `RuntimeEnabledFeature` 控制。

* **默认禁用:**  在 Blink 的默认配置中，`NewFancyAPI` 可能是禁用的。这意味着如果在网页的 JavaScript 代码中使用了 `navigator.newFancyAPI()`,  浏览器会抛出一个错误，因为这个 API 尚未被识别。
* **启用 Flag:**  Chromium 开发者或用户可以通过命令行参数或 chrome://flags 页面启用 `NewFancyAPI` 这个 flag。
* **`RuntimeEnabledFeatures` 生效:** 当 flag 被启用后，`RuntimeEnabledFeatures::NewFancyAPIEnabled()` 将返回 `true`。
* **JavaScript 可用:**  此时，Blink 引擎会识别 `navigator.newFancyAPI()` 这个 API，网页的 JavaScript 代码可以正常调用它。

类似地，新的 CSS 属性或 HTML 元素也可以通过 `RuntimeEnabledFeatures` 进行控制。例如，一个新的 CSS 属性 `--my-new-property` 可能会被一个名为 `CSSMyNewPropertyEnabled` 的 `RuntimeEnabledFeature` 控制。只有当这个 feature 被启用后，浏览器才会解析和应用使用这个属性的 CSS 规则。

**逻辑推理及假设输入与输出:**

考虑 `TYPED_TEST_P(AbstractRuntimeEnabledFeaturesTest, Relationship)` 这个测试用例。

**假设输入:**

1. 初始状态：`TestFeature`, `TestFeatureImplied`, `TestFeatureDependent` 都是禁用的。
2. 操作：
   * 设置 `TestFeature` 为启用。
   * 设置 `TestFeatureImplied` 为启用。
   * 设置 `TestFeatureDependent` 为启用。
   * 设置 `TestFeatureImplied` 为禁用。
   * 设置 `TestFeature` 为禁用。
   * 设置 `TestFeatureImplied` 为启用。
   * 设置 `TestFeatureDependent` 为禁用。

**逻辑推理:**

* `TestFeatureImplied` 被 `TestFeature` 隐含 (`implied_by`)，所以 `TestFeature` 启用时，`TestFeatureImplied` 也应该启用。
* `TestFeatureDependent` 依赖于 `TestFeatureImplied` (`depends_on`)，所以只有当 `TestFeatureImplied` 启用时，`TestFeatureDependent` 才能启用。

**预期输出:**

| 操作                                  | `TestFeatureEnabled()` | `TestFeatureImpliedEnabled()` | `TestFeatureDependentEnabled()` |
|---------------------------------------|-----------------------|-----------------------------|---------------------------------|
| 初始状态                               | false                 | false                       | false                           |
| 设置 `TestFeature` 为启用             | true                  | true                        | false                           |
| 设置 `TestFeatureImplied` 为启用         | true                  | true                        | false                           |
| 设置 `TestFeatureDependent` 为启用       | true                  | true                        | true                            |
| 设置 `TestFeatureImplied` 为禁用         | true                  | true                        | true                            |
| 设置 `TestFeature` 为禁用             | false                 | false                       | false                           |
| 设置 `TestFeatureImplied` 为启用         | false                 | true                        | true                            |
| 设置 `TestFeatureDependent` 为禁用       | false                 | true                        | false                           |

**用户或编程常见的使用错误及举例说明:**

1. **忘记处理功能未启用的情况:**  开发者可能会直接使用一个由 `RuntimeEnabledFeatures` 控制的 API 或属性，而没有检查对应的 feature 是否已启用。

   ```javascript
   // 假设 NewFancyAPI 默认是禁用的
   if (navigator.newFancyAPI) { // 错误：直接假设 API 存在
       navigator.newFancyAPI();
   }
   ```

   **正确做法:**

   ```javascript
   if (RuntimeEnabledFeatures.newFancyAPIEnabled()) { // 假设有对应的 JavaScript 接口
       navigator.newFancyAPI();
   } else {
       // 提供降级方案或提示用户启用该功能
       console.log("New fancy API is not enabled.");
   }
   ```

2. **在不应该使用的地方修改功能状态:**  直接调用 `RuntimeEnabledFeatures::SetXXXEnabled()` 来修改功能状态应该谨慎，通常只在测试或特定的初始化代码中使用。在普通的网页渲染流程中随意修改可能会导致不可预测的行为。

3. **误解功能之间的依赖关系:**  开发者可能会尝试启用一个依赖于其他功能的功能，但忘记先启用其依赖的功能，导致功能无法正常工作。

4. **在异步操作中错误地假设功能状态:**  如果在异步操作中需要使用由 feature flag 控制的功能，应该在异步操作执行时再次检查功能状态，因为状态可能在异步操作开始到结束之间发生变化。

总而言之，`blink/renderer/platform/runtime_enabled_features_test.cc` 是一个关键的测试文件，它确保了 Blink 引擎中功能开关机制的正确性和可靠性，这对于新功能的开发、测试和推广至关重要。它通过各种测试用例覆盖了功能开关的各个方面，包括基本行为、作用域、备份恢复以及与 Origin Trials 和 Chromium Feature Flags 的集成。理解这个文件的内容有助于深入了解 Blink 引擎如何管理和控制其丰富的功能集。

### 提示词
```
这是目录为blink/renderer/platform/runtime_enabled_features_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/runtime_enabled_features.h"

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/platform/web_runtime_features.h"
#include "third_party/blink/renderer/platform/testing/runtime_enabled_features_test_helpers.h"

namespace blink {

class RuntimeEnabledFeaturesTestTraits {
 public:
  using ScopedTestFeatureForTestType = ScopedTestFeatureForTest;
  using ScopedTestFeatureImpliedForTestType = ScopedTestFeatureImpliedForTest;
  using ScopedTestFeatureDependentForTestType =
      ScopedTestFeatureDependentForTest;

  static bool ScopedForTestSupported() { return true; }

  static ScopedTestFeatureForTestType CreateScopedTestFeatureForTest(
      bool enabled) {
    return ScopedTestFeatureForTest(enabled);
  }

  static ScopedTestFeatureImpliedForTestType
  CreateScopedTestFeatureImpliedForTest(bool enabled) {
    return ScopedTestFeatureImpliedForTest(enabled);
  }

  static ScopedTestFeatureDependentForTestType
  CreateScopedTestFeatureDependentForTest(bool enabled) {
    return ScopedTestFeatureDependentForTest(enabled);
  }

  static bool TestFeatureEnabled() {
    return RuntimeEnabledFeatures::TestFeatureEnabled();
  }

  static bool TestFeatureImpliedEnabled() {
    return RuntimeEnabledFeatures::TestFeatureImpliedEnabled();
  }

  static bool TestFeatureDependentEnabled() {
    return RuntimeEnabledFeatures::TestFeatureDependentEnabled();
  }

  static bool OriginTrialsSampleAPIEnabledByRuntimeFlag() {
    return RuntimeEnabledFeatures::OriginTrialsSampleAPIEnabledByRuntimeFlag();
  }

  static bool OriginTrialsSampleAPIImpliedEnabledByRuntimeFlag() {
    return RuntimeEnabledFeatures::
        OriginTrialsSampleAPIImpliedEnabledByRuntimeFlag();
  }

  static bool OriginTrialsSampleAPIDependentEnabledByRuntimeFlag() {
    return RuntimeEnabledFeatures::
        OriginTrialsSampleAPIDependentEnabledByRuntimeFlag();
  }

  static void SetTestFeatureEnabled(bool enabled) {
    RuntimeEnabledFeatures::SetTestFeatureEnabled(enabled);
  }

  static void SetTestFeatureImpliedEnabled(bool enabled) {
    RuntimeEnabledFeatures::SetTestFeatureImpliedEnabled(enabled);
  }

  static void SetTestFeatureDependentEnabled(bool enabled) {
    RuntimeEnabledFeatures::SetTestFeatureDependentEnabled(enabled);
  }

  static void SetOriginTrialsSampleAPIEnabled(bool enabled) {
    RuntimeEnabledFeatures::SetOriginTrialsSampleAPIEnabled(enabled);
  }

  static void SetOriginTrialsSampleAPIImpliedEnabled(bool enabled) {
    RuntimeEnabledFeatures::SetOriginTrialsSampleAPIImpliedEnabled(enabled);
  }

  static void SetOriginTrialsSampleAPIDependentEnabled(bool enabled) {
    RuntimeEnabledFeatures::SetOriginTrialsSampleAPIDependentEnabled(enabled);
  }
};

class RuntimeProtectedEnabledFeaturesTestTraits {
 public:
  using ScopedTestFeatureForTestType = ScopedTestFeatureProtectedForTest;
  using ScopedTestFeatureImpliedForTestType =
      ScopedTestFeatureProtectedImpliedForTest;
  using ScopedTestFeatureDependentForTestType =
      ScopedTestFeatureProtectedDependentForTest;

  static bool ScopedForTestSupported() {
    // The way the ScopedForTest classes are implemented, they do not work with
    // protected variables in component builds. This is because of the static
    // inline variable use results in the value being allocated in one module,
    // but the protected code being called from a different. So don't run this
    // test for the protected case in component builds.
#if defined(COMPONENT_BUILD)
    return false;
#else
    return true;
#endif
  }

  static ScopedTestFeatureForTestType CreateScopedTestFeatureForTest(
      bool enabled) {
    return ScopedTestFeatureProtectedForTest(enabled);
  }

  static ScopedTestFeatureImpliedForTestType
  CreateScopedTestFeatureImpliedForTest(bool enabled) {
    return ScopedTestFeatureProtectedImpliedForTest(enabled);
  }

  static ScopedTestFeatureDependentForTestType
  CreateScopedTestFeatureDependentForTest(bool enabled) {
    return ScopedTestFeatureProtectedDependentForTest(enabled);
  }

  static bool TestFeatureEnabled() {
    return RuntimeEnabledFeatures::TestFeatureProtectedEnabled();
  }

  static bool TestFeatureImpliedEnabled() {
    return RuntimeEnabledFeatures::TestFeatureProtectedImpliedEnabled();
  }

  static bool TestFeatureDependentEnabled() {
    return RuntimeEnabledFeatures::TestFeatureProtectedDependentEnabled();
  }

  static bool OriginTrialsSampleAPIEnabledByRuntimeFlag() {
    return RuntimeEnabledFeatures::
        ProtectedOriginTrialsSampleAPIEnabledByRuntimeFlag();
  }

  static bool OriginTrialsSampleAPIImpliedEnabledByRuntimeFlag() {
    return RuntimeEnabledFeatures::
        ProtectedOriginTrialsSampleAPIImpliedEnabledByRuntimeFlag();
  }

  static bool OriginTrialsSampleAPIDependentEnabledByRuntimeFlag() {
    return RuntimeEnabledFeatures::
        ProtectedOriginTrialsSampleAPIDependentEnabledByRuntimeFlag();
  }

  static void SetTestFeatureEnabled(bool enabled) {
    RuntimeEnabledFeatures::SetTestFeatureProtectedEnabled(enabled);
  }

  static void SetTestFeatureImpliedEnabled(bool enabled) {
    RuntimeEnabledFeatures::SetTestFeatureProtectedImpliedEnabled(enabled);
  }

  static void SetTestFeatureDependentEnabled(bool enabled) {
    RuntimeEnabledFeatures::SetTestFeatureProtectedDependentEnabled(enabled);
  }

  static void SetOriginTrialsSampleAPIEnabled(bool enabled) {
    RuntimeEnabledFeatures::SetProtectedOriginTrialsSampleAPIEnabled(enabled);
  }

  static void SetOriginTrialsSampleAPIImpliedEnabled(bool enabled) {
    RuntimeEnabledFeatures::SetProtectedOriginTrialsSampleAPIImpliedEnabled(
        enabled);
  }

  static void SetOriginTrialsSampleAPIDependentEnabled(bool enabled) {
    RuntimeEnabledFeatures::SetProtectedOriginTrialsSampleAPIDependentEnabled(
        enabled);
  }
};

template <typename TRuntimeEnabledFeaturesTraits>
class AbstractRuntimeEnabledFeaturesTest : public testing::Test {
 protected:
  using ScopedTestFeatureForTestType =
      typename TRuntimeEnabledFeaturesTraits::ScopedTestFeatureForTestType;
  using ScopedTestFeatureImpliedForTestType =
      typename TRuntimeEnabledFeaturesTraits::
          ScopedTestFeatureImpliedForTestType;
  using ScopedTestFeatureDependentForTestType =
      typename TRuntimeEnabledFeaturesTraits::
          ScopedTestFeatureDependentForTestType;

  void CheckAllDisabled() {
    CHECK(!TestFeatureEnabled());
    CHECK(!TestFeatureImpliedEnabled());
    CHECK(!TestFeatureDependentEnabled());
    CHECK(!OriginTrialsSampleAPIEnabledByRuntimeFlag());
    CHECK(!OriginTrialsSampleAPIImpliedEnabledByRuntimeFlag());
    CHECK(!OriginTrialsSampleAPIDependentEnabledByRuntimeFlag());
  }
  void SetUp() override { CheckAllDisabled(); }
  void TearDown() override {
    backup_.Restore();
    CheckAllDisabled();
  }

  bool ScopedForTestSupported() {
    return TRuntimeEnabledFeaturesTraits::ScopedForTestSupported();
  }

  ScopedTestFeatureForTestType CreateScopedTestFeatureForTest(bool enabled) {
    return TRuntimeEnabledFeaturesTraits::CreateScopedTestFeatureForTest(
        enabled);
  }

  ScopedTestFeatureImpliedForTestType CreateScopedTestFeatureImpliedForTest(
      bool enabled) {
    return TRuntimeEnabledFeaturesTraits::CreateScopedTestFeatureImpliedForTest(
        enabled);
  }

  ScopedTestFeatureDependentForTestType CreateScopedTestFeatureDependentForTest(
      bool enabled) {
    return TRuntimeEnabledFeaturesTraits::
        CreateScopedTestFeatureDependentForTest(enabled);
  }

  bool TestFeatureEnabled() {
    return TRuntimeEnabledFeaturesTraits::TestFeatureEnabled();
  }

  bool TestFeatureImpliedEnabled() {
    return TRuntimeEnabledFeaturesTraits::TestFeatureImpliedEnabled();
  }

  bool TestFeatureDependentEnabled() {
    return TRuntimeEnabledFeaturesTraits::TestFeatureDependentEnabled();
  }

  bool OriginTrialsSampleAPIEnabledByRuntimeFlag() {
    return TRuntimeEnabledFeaturesTraits::
        OriginTrialsSampleAPIEnabledByRuntimeFlag();
  }

  bool OriginTrialsSampleAPIImpliedEnabledByRuntimeFlag() {
    return TRuntimeEnabledFeaturesTraits::
        OriginTrialsSampleAPIImpliedEnabledByRuntimeFlag();
  }

  bool OriginTrialsSampleAPIDependentEnabledByRuntimeFlag() {
    return TRuntimeEnabledFeaturesTraits::
        OriginTrialsSampleAPIDependentEnabledByRuntimeFlag();
  }

  void SetTestFeatureEnabled(bool enabled) {
    TRuntimeEnabledFeaturesTraits::SetTestFeatureEnabled(enabled);
  }

  void SetTestFeatureImpliedEnabled(bool enabled) {
    TRuntimeEnabledFeaturesTraits::SetTestFeatureImpliedEnabled(enabled);
  }

  void SetTestFeatureDependentEnabled(bool enabled) {
    TRuntimeEnabledFeaturesTraits::SetTestFeatureDependentEnabled(enabled);
  }

  void SetOriginTrialsSampleAPIEnabled(bool enabled) {
    TRuntimeEnabledFeaturesTraits::SetOriginTrialsSampleAPIEnabled(enabled);
  }

  void SetOriginTrialsSampleAPIImpliedEnabled(bool enabled) {
    TRuntimeEnabledFeaturesTraits::SetOriginTrialsSampleAPIImpliedEnabled(
        enabled);
  }

  void SetOriginTrialsSampleAPIDependentEnabled(bool enabled) {
    TRuntimeEnabledFeaturesTraits::SetOriginTrialsSampleAPIDependentEnabled(
        enabled);
  }

 private:
  RuntimeEnabledFeatures::Backup backup_;
};

// Test setup:
//   TestFeatureDependent
// depends_on
//   TestFeatureImplied
// implied_by
//   TestFeature
TYPED_TEST_SUITE_P(AbstractRuntimeEnabledFeaturesTest);

TYPED_TEST_P(AbstractRuntimeEnabledFeaturesTest, Relationship) {
  // Internal status: false, false, false.
  EXPECT_FALSE(this->TestFeatureEnabled());
  EXPECT_FALSE(this->TestFeatureImpliedEnabled());
  EXPECT_FALSE(this->TestFeatureDependentEnabled());

  this->SetTestFeatureEnabled(true);
  // Internal status: true, false, false.
  EXPECT_TRUE(this->TestFeatureEnabled());
  // Implied by TestFeature.
  EXPECT_TRUE(this->TestFeatureImpliedEnabled());
  EXPECT_FALSE(this->TestFeatureDependentEnabled());

  this->SetTestFeatureImpliedEnabled(true);
  // Internal status: true, true, false.
  EXPECT_TRUE(this->TestFeatureEnabled());
  EXPECT_TRUE(this->TestFeatureImpliedEnabled());
  EXPECT_FALSE(this->TestFeatureDependentEnabled());

  this->SetTestFeatureDependentEnabled(true);
  // Internal status: true, true, true.
  EXPECT_TRUE(this->TestFeatureEnabled());
  EXPECT_TRUE(this->TestFeatureImpliedEnabled());
  EXPECT_TRUE(this->TestFeatureDependentEnabled());

  this->SetTestFeatureImpliedEnabled(false);
  // Internal status: true, false, true.
  EXPECT_TRUE(this->TestFeatureEnabled());
  // Implied by TestFeature.
  EXPECT_TRUE(this->TestFeatureImpliedEnabled());
  EXPECT_TRUE(this->TestFeatureDependentEnabled());

  this->SetTestFeatureEnabled(false);
  // Internal status: false, false, true.
  EXPECT_FALSE(this->TestFeatureEnabled());
  EXPECT_FALSE(this->TestFeatureImpliedEnabled());
  // Depends on TestFeatureImplied.
  EXPECT_FALSE(this->TestFeatureDependentEnabled());

  this->SetTestFeatureImpliedEnabled(true);
  // Internal status: false, true, true.
  EXPECT_FALSE(this->TestFeatureEnabled());
  EXPECT_TRUE(this->TestFeatureImpliedEnabled());
  EXPECT_TRUE(this->TestFeatureDependentEnabled());

  this->SetTestFeatureDependentEnabled(false);
  // Internal status: false, true, false.
  EXPECT_FALSE(this->TestFeatureEnabled());
  EXPECT_TRUE(this->TestFeatureImpliedEnabled());
  EXPECT_FALSE(this->TestFeatureDependentEnabled());
}

TYPED_TEST_P(AbstractRuntimeEnabledFeaturesTest, ScopedForTest) {
  if (!this->ScopedForTestSupported()) {
    return;
  }
  // Internal status: false, false, false.
  EXPECT_FALSE(this->TestFeatureEnabled());
  EXPECT_FALSE(this->TestFeatureImpliedEnabled());
  EXPECT_FALSE(this->TestFeatureDependentEnabled());
  {
    auto f1 = this->CreateScopedTestFeatureForTest(true);
    // Internal status: true, false, false.
    EXPECT_TRUE(this->TestFeatureEnabled());
    // Implied by TestFeature.
    EXPECT_TRUE(this->TestFeatureImpliedEnabled());
    EXPECT_FALSE(this->TestFeatureDependentEnabled());
    {
      auto f2 = this->CreateScopedTestFeatureImpliedForTest(true);
      // Internal status: true, true, false.
      EXPECT_TRUE(this->TestFeatureEnabled());
      EXPECT_TRUE(this->TestFeatureImpliedEnabled());
      EXPECT_FALSE(this->TestFeatureDependentEnabled());
      {
        auto f3 = this->CreateScopedTestFeatureDependentForTest(true);
        // Internal status: true, true, true.
        EXPECT_TRUE(this->TestFeatureEnabled());
        EXPECT_TRUE(this->TestFeatureImpliedEnabled());
        EXPECT_TRUE(this->TestFeatureDependentEnabled());
        {
          auto f3a = this->CreateScopedTestFeatureDependentForTest(false);
          // Internal status: true, true, true.
          EXPECT_TRUE(this->TestFeatureEnabled());
          EXPECT_TRUE(this->TestFeatureImpliedEnabled());
          EXPECT_FALSE(this->TestFeatureDependentEnabled());
        }
        // Internal status: true, true, true.
        EXPECT_TRUE(this->TestFeatureEnabled());
        EXPECT_TRUE(this->TestFeatureImpliedEnabled());
        EXPECT_TRUE(this->TestFeatureDependentEnabled());
      }
    }
    // Internal status: true, false, false.
    EXPECT_TRUE(this->TestFeatureEnabled());
    // Implied by TestFeature.
    EXPECT_TRUE(this->TestFeatureImpliedEnabled());
    EXPECT_FALSE(this->TestFeatureDependentEnabled());
    {
      auto f2a = this->CreateScopedTestFeatureImpliedForTest(false);
      // Internal status: true, false, false.
      EXPECT_TRUE(this->TestFeatureEnabled());
      // Implied by TestFeature.
      EXPECT_TRUE(this->TestFeatureImpliedEnabled());
      EXPECT_FALSE(this->TestFeatureDependentEnabled());
    }
  }
  // Internal status: false, false, false.
  EXPECT_FALSE(this->TestFeatureEnabled());
  EXPECT_FALSE(this->TestFeatureImpliedEnabled());
  EXPECT_FALSE(this->TestFeatureDependentEnabled());
  {
    auto f3 = this->CreateScopedTestFeatureDependentForTest(true);
    // Internal status: false, false, true.
    EXPECT_FALSE(this->TestFeatureEnabled());
    EXPECT_FALSE(this->TestFeatureImpliedEnabled());
    // Depends on TestFeatureImplied.
    EXPECT_FALSE(this->TestFeatureDependentEnabled());
    {
      auto f2 = this->CreateScopedTestFeatureImpliedForTest(true);
      // Internal status: false, true, true.
      EXPECT_FALSE(this->TestFeatureEnabled());
      EXPECT_TRUE(this->TestFeatureImpliedEnabled());
      EXPECT_TRUE(this->TestFeatureDependentEnabled());
      {
        auto f1 = this->CreateScopedTestFeatureForTest(true);
        // Internal status: true, true, true.
        EXPECT_TRUE(this->TestFeatureEnabled());
        EXPECT_TRUE(this->TestFeatureImpliedEnabled());
        EXPECT_TRUE(this->TestFeatureDependentEnabled());
      }
      // Internal status: false, true, true.
      EXPECT_FALSE(this->TestFeatureEnabled());
      EXPECT_TRUE(this->TestFeatureImpliedEnabled());
      EXPECT_TRUE(this->TestFeatureDependentEnabled());
    }
    // Internal status: false, false, true.
    EXPECT_FALSE(this->TestFeatureEnabled());
    EXPECT_FALSE(this->TestFeatureImpliedEnabled());
    // Depends on TestFeatureImplied.
    EXPECT_FALSE(this->TestFeatureDependentEnabled());
    {
      auto f2 = this->CreateScopedTestFeatureImpliedForTest(true);
      // Internal status: false, true, true.
      EXPECT_FALSE(this->TestFeatureEnabled());
      EXPECT_TRUE(this->TestFeatureImpliedEnabled());
      EXPECT_TRUE(this->TestFeatureDependentEnabled());
    }
  }
  // Internal status: false, false, false.
  EXPECT_FALSE(this->TestFeatureEnabled());
  EXPECT_FALSE(this->TestFeatureImpliedEnabled());
  EXPECT_FALSE(this->TestFeatureDependentEnabled());
}

TYPED_TEST_P(AbstractRuntimeEnabledFeaturesTest, BackupRestore) {
  // Internal status: false, false, false.
  EXPECT_FALSE(this->TestFeatureEnabled());
  EXPECT_FALSE(this->TestFeatureImpliedEnabled());
  EXPECT_FALSE(this->TestFeatureDependentEnabled());

  this->SetTestFeatureEnabled(true);
  this->SetTestFeatureDependentEnabled(true);
  // Internal status: true, false, true.
  EXPECT_TRUE(this->TestFeatureEnabled());
  // Implied by TestFeature.
  EXPECT_TRUE(this->TestFeatureImpliedEnabled());
  EXPECT_TRUE(this->TestFeatureDependentEnabled());

  RuntimeEnabledFeatures::Backup backup;

  this->SetTestFeatureEnabled(false);
  this->SetTestFeatureImpliedEnabled(true);
  this->SetTestFeatureDependentEnabled(false);
  // Internal status: false, true, false.
  EXPECT_FALSE(this->TestFeatureEnabled());
  EXPECT_TRUE(this->TestFeatureImpliedEnabled());
  EXPECT_FALSE(this->TestFeatureDependentEnabled());

  backup.Restore();
  // Should restore the internal status to: true, false, true.
  EXPECT_TRUE(this->TestFeatureEnabled());
  // Implied by TestFeature.
  EXPECT_TRUE(this->TestFeatureImpliedEnabled());
  EXPECT_TRUE(this->TestFeatureDependentEnabled());

  this->SetTestFeatureEnabled(false);
  // Internal status: false, false, true.
  EXPECT_FALSE(this->TestFeatureEnabled());
  EXPECT_FALSE(this->TestFeatureImpliedEnabled());
  // Depends on TestFeatureImplied.
  EXPECT_FALSE(this->TestFeatureDependentEnabled());
}

// Test setup:
// OriginTrialsSampleAPIImplied   impled_by  \
//                                             OriginTrialsSampleAPI
// OriginTrialsSampleAPIDependent depends_on /
TYPED_TEST_P(AbstractRuntimeEnabledFeaturesTest, OriginTrialsByRuntimeEnabled) {
  // Internal status: false, false, false.
  EXPECT_FALSE(this->OriginTrialsSampleAPIEnabledByRuntimeFlag());
  EXPECT_FALSE(this->OriginTrialsSampleAPIImpliedEnabledByRuntimeFlag());
  EXPECT_FALSE(this->OriginTrialsSampleAPIDependentEnabledByRuntimeFlag());

  this->SetOriginTrialsSampleAPIEnabled(true);
  // Internal status: true, false, false.
  EXPECT_TRUE(this->OriginTrialsSampleAPIEnabledByRuntimeFlag());
  // Implied by OriginTrialsSampleAPI.
  EXPECT_TRUE(this->OriginTrialsSampleAPIImpliedEnabledByRuntimeFlag());
  EXPECT_FALSE(this->OriginTrialsSampleAPIDependentEnabledByRuntimeFlag());

  this->SetOriginTrialsSampleAPIImpliedEnabled(true);
  this->SetOriginTrialsSampleAPIDependentEnabled(true);
  // Internal status: true, true, true.
  EXPECT_TRUE(this->OriginTrialsSampleAPIEnabledByRuntimeFlag());
  EXPECT_TRUE(this->OriginTrialsSampleAPIImpliedEnabledByRuntimeFlag());
  EXPECT_TRUE(this->OriginTrialsSampleAPIDependentEnabledByRuntimeFlag());

  this->SetOriginTrialsSampleAPIEnabled(false);
  // Internal status: false, true, true.
  EXPECT_FALSE(this->OriginTrialsSampleAPIEnabledByRuntimeFlag());
  EXPECT_TRUE(this->OriginTrialsSampleAPIImpliedEnabledByRuntimeFlag());
  // Depends on OriginTrialsSampleAPI.
  EXPECT_FALSE(this->OriginTrialsSampleAPIDependentEnabledByRuntimeFlag());
}

TYPED_TEST_P(AbstractRuntimeEnabledFeaturesTest, CopiedFromBaseFaetureIf) {
  using base::FeatureList;
  const base::Feature& kFeature = features::kTestBlinkFeatureDefault;
  ASSERT_TRUE(FeatureList::IsEnabled(kFeature));
  ASSERT_TRUE(FeatureList::GetInstance()->IsFeatureOverridden(kFeature.name));
  ASSERT_FALSE(FeatureList::GetStateIfOverridden(kFeature));
  WebRuntimeFeatures::UpdateStatusFromBaseFeatures();
  EXPECT_FALSE(RuntimeEnabledFeatures::TestBlinkFeatureDefaultEnabled());
}

REGISTER_TYPED_TEST_SUITE_P(AbstractRuntimeEnabledFeaturesTest,
                            Relationship,
                            ScopedForTest,
                            BackupRestore,
                            OriginTrialsByRuntimeEnabled,
                            CopiedFromBaseFaetureIf);

INSTANTIATE_TYPED_TEST_SUITE_P(Base,
                               AbstractRuntimeEnabledFeaturesTest,
                               RuntimeEnabledFeaturesTestTraits);

INSTANTIATE_TYPED_TEST_SUITE_P(Protected,
                               AbstractRuntimeEnabledFeaturesTest,
                               RuntimeProtectedEnabledFeaturesTestTraits);

}  // namespace blink
```