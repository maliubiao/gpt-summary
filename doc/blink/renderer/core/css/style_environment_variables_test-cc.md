Response:
The user wants a summary of the functionality of the given C++ code file.
The file `style_environment_variables_test.cc` seems to contain unit tests for the `StyleEnvironmentVariables` class in the Chromium Blink engine.

Here's a breakdown of the observed functionalities:

1. **Testing CSS Environment Variables:** The tests seem to focus on how CSS environment variables (`env()`) are handled.
2. **Global vs. Document-Specific Variables:** The code tests the behavior of setting and overriding variables at the root (global) level and at the document level.
3. **Invalidation:** The tests check if changes to environment variables correctly invalidate the document, triggering style recalculation and layout updates.
4. **Navigation:** The code examines how navigation affects environment variables.
5. **Predefined Variables:** Tests cover the default values of certain user-agent defined variables (e.g., `safe-area-inset-*`).
6. **Use Counters:**  The tests verify if the usage of environment variables is correctly recorded using use counters for tracking web feature adoption.
7. **Two-Dimensional Variables:**  The code includes tests for a specific type of environment variable that seems to have two-dimensional indexing (e.g., `viewport-segment-*`). This likely relates to viewport segmentation features.
8. **Titlebar Area Variables:** There are tests related to `titlebar-area-*` variables, which are relevant for Progressive Web Apps (PWAs) using the window controls overlay feature.

Based on these observations, I can formulate a summary of the file's purpose.
这是 `blink/renderer/core/css/style_environment_variables_test.cc` 文件的第一部分，它主要负责测试 Blink 渲染引擎中 **CSS 环境变量** 的功能。  具体来说，它测试了以下几个方面：

**功能归纳:**

1. **测试 CSS `env()` 函数:**  验证 CSS 中使用 `env()` 函数引用环境变量时的行为是否正确。
2. **测试全局环境变量:**  测试在根级别设置和修改环境变量对所有文档的影响。
3. **测试文档级环境变量:** 测试在特定文档上设置和修改环境变量的影响，以及它们如何覆盖全局环境变量。
4. **测试环境变量的优先级和覆盖:**  验证文档级环境变量优先于全局环境变量，以及移除文档级环境变量后如何回退到全局环境变量。
5. **测试页面导航对环境变量的影响:**  验证页面导航是否会清除之前设置的文档级环境变量。
6. **测试预设的 UA 定义环境变量:** 验证像 `safe-area-inset-*` 这样的用户代理预定义的环境变量的默认值和行为。
7. **测试环境变量的移除:** 验证移除环境变量后，使用该变量的样式是否会正确更新。
8. **测试多文档环境下的环境变量更新:**  验证在一个页面修改全局环境变量时，其他使用该变量的页面是否会正确失效并更新。
9. **测试使用计数器 (UseCounter):** 验证对 `env()` 函数和特定的 UA 定义环境变量的使用是否会被正确记录，用于统计 web feature 的使用情况。
10. **测试二维环境变量:** 验证带有两个索引的特殊环境变量（例如 `viewport-segment-*`）的设置、更新、回退以及错误使用情况的处理。
11. **测试 Titlebar Area 环境变量 (非 Android 平台):** 验证在支持 Window Controls Overlay 的 PWA 中，`titlebar-area-*` 环境变量的加载和更新。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **CSS:** 该测试文件直接测试 CSS 的 `env()` 函数。
    * **举例:**  在 CSS 中使用 `background-color: env(test, blue);`，这里的 `test` 就是一个环境变量，`blue` 是一个回退值。测试代码会验证当环境变量 `test` 被设置或移除时，元素的背景颜色是否会相应变化。
* **HTML:**  测试文件中会创建简单的 HTML 结构来应用 CSS 样式并观察结果。
    * **举例:**  `<div id="target" style="background-color: env(test);"></div>`，测试代码会查找这个 ID 为 `target` 的元素，并检查其计算出的背景颜色。
* **JavaScript:**  虽然这个测试文件是 C++ 代码，但它测试的功能最终会影响到 JavaScript 中获取元素样式的结果。在实际应用中，JavaScript 可以通过 `getComputedStyle()` 来获取使用了环境变量的样式值。

**逻辑推理 (假设输入与输出):**

* **假设输入:**  在测试用例 `DocumentVariable_AfterLoad` 中，先初始化一个包含使用 `env(test)` 的样式的页面，然后通过 `SetVariableOnDocument("test", "red")` 设置文档级的环境变量 `test` 的值为 "red"。
* **预期输出:**  ID 为 `target` 的元素的计算出的背景颜色应该为红色 (对应 `kTestColorRed`)。这是因为文档级环境变量会覆盖默认值。

**用户或编程常见的使用错误举例:**

* **错误使用环境变量名:** 用户在 CSS 中使用了不存在的环境变量名，例如 `background-color: env(nonexistent-variable);`。测试代码会间接验证这种情况下的回退值是否生效（如果有）。
* **错误地假设全局环境变量总是存在:**  开发者可能会假设某个全局环境变量总是被设置，但实际情况可能并非如此。测试代码会覆盖在没有设置全局变量的情况下，文档级变量或回退值是否能正确生效。
* **在不支持 `env()` 的旧浏览器中使用:** 虽然测试的是 Blink 引擎，但在实际开发中，需要在不支持 CSS 环境变量的旧浏览器上提供兼容方案。

**用户操作如何一步步到达这里 (调试线索):**

1. **开发者编写或修改使用了 CSS 环境变量的网页。** 例如，在 CSS 中使用了 `env(my-custom-color)` 来设置某个元素的颜色。
2. **网页在 Chromium 内核的浏览器中加载。**
3. **Blink 渲染引擎开始解析 CSS，遇到 `env()` 函数。**
4. **`StyleEnvironmentVariables` 类会被调用来解析和查找环境变量的值。**
5. **如果在调试过程中遇到与环境变量相关的问题（例如，样式没有按预期生效），开发者可能会查看 Blink 渲染引擎的源代码。**
6. **他们可能会找到 `style_environment_variables_test.cc` 文件，并通过阅读测试用例来理解环境变量是如何工作的，以及可能存在的问题。**
7. **开发者可能会尝试运行相关的测试用例，或者在自己的代码中模拟测试用例中的场景来定位问题。**
8. **例如，他们可能会发现文档级环境变量没有正确覆盖全局环境变量，或者环境变量的更新没有触发样式的重新计算，这时就可以参考这个测试文件中的相关用例进行排查。**

总而言之，`style_environment_variables_test.cc` 的第一部分定义了大量测试用例，旨在全面验证 Blink 渲染引擎中 CSS 环境变量功能的正确性和健壮性，确保开发者可以按照预期使用 CSS 环境变量。

Prompt: 
```
这是目录为blink/renderer/core/css/style_environment_variables_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/css/style_environment_variables.h"

#include "third_party/blink/renderer/core/css/document_style_environment_variables.h"
#include "third_party/blink/renderer/core/css/properties/longhands.h"
#include "third_party/blink/renderer/core/css/style_engine.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/web_feature.h"
#include "third_party/blink/renderer/core/html/html_element.h"
#include "third_party/blink/renderer/core/style/computed_style.h"
#include "third_party/blink/renderer/core/testing/page_test_base.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/testing/runtime_enabled_features_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"

namespace blink {

namespace {

static const char kVariableName[] = "test";

// red
static const Color kTestColorRed = Color(255, 0, 0);
static const char kVariableTestColor[] = "red";

// blue
static const Color kAltTestColor = Color(0, 0, 255);
static const char kVariableAltTestColor[] = "blue";

// no set
static const Color kNoColor = Color(0, 0, 0, 0);

static const char kSafeAreaInsetExpectedDefault[] = "0px";

}  // namespace

class StyleEnvironmentVariablesTest : public PageTestBase {
 public:
  void TearDown() override {
    StyleEnvironmentVariables::GetRootInstance().ClearForTesting();
  }

  DocumentStyleEnvironmentVariables& GetDocumentVariables() {
    return GetStyleEngine().EnsureEnvironmentVariables();
  }

  void InitializeWithHTML(LocalFrame& frame, const String& html_content) {
    // Sets the inner html and runs the document lifecycle.
    frame.GetDocument()->body()->setInnerHTML(html_content);
    frame.GetDocument()->View()->UpdateAllLifecyclePhasesForTest();
  }

  void InitializeTestPageWithVariableNamed(LocalFrame& frame,
                                           const String& name) {
    InitializeWithHTML(frame,
                       "<style>"
                       "  #target { background-color: env(" +
                           name +
                           "); }"
                           "</style>"
                           "<div>"
                           "  <div id=target></div>"
                           "</div>");
  }

  void InitializeTestPageWithVariableNamed(LocalFrame& frame,
                                           const UADefinedVariable name) {
    InitializeTestPageWithVariableNamed(
        frame, StyleEnvironmentVariables::GetVariableName(
                   name, /*feature_context=*/nullptr));
  }

  void SimulateNavigation() {
    const KURL& url = KURL(NullURL(), "https://www.example.com");
    GetDocument().GetFrame()->Loader().CommitNavigation(
        WebNavigationParams::CreateWithEmptyHTMLForTesting(url),
        nullptr /* extra_data */);
    blink::test::RunPendingTasks();
    ASSERT_EQ(url.GetString(), GetDocument().Url().GetString());
  }

  String GetRootVariableValue(UADefinedVariable name) {
    CSSVariableData* data =
        StyleEnvironmentVariables::GetRootInstance().ResolveVariable(
            StyleEnvironmentVariables::GetVariableName(
                name, /*feature_context=*/nullptr),
            {});
    EXPECT_NE(nullptr, data);
    return data->Serialize();
  }

  void SetVariableOnRoot(const char* name, const String& value) {
    StyleEnvironmentVariables::GetRootInstance().SetVariable(AtomicString(name),
                                                             value);
  }

  void RemoveVariableOnRoot(const char* name) {
    StyleEnvironmentVariables::GetRootInstance().RemoveVariable(
        AtomicString(name));
  }

  void SetVariableOnDocument(const char* name, const String& value) {
    GetDocumentVariables().SetVariable(AtomicString(name), value);
  }

  void RemoveVariableOnDocument(const char* name) {
    GetDocumentVariables().RemoveVariable(AtomicString(name));
  }

  void SetTwoDimensionalVariableOnRoot(UADefinedTwoDimensionalVariable variable,
                                       unsigned first_dimension,
                                       unsigned second_dimension,
                                       const String& value) {
    StyleEnvironmentVariables::GetRootInstance().SetVariable(
        variable, first_dimension, second_dimension, value, nullptr);
  }
};

TEST_F(StyleEnvironmentVariablesTest, DocumentVariable_AfterLoad) {
  InitializeTestPageWithVariableNamed(GetFrame(), kVariableName);
  SetVariableOnDocument(kVariableName, kVariableTestColor);

  // Ensure that the document has been invalidated.
  EXPECT_TRUE(GetDocument().NeedsLayoutTreeUpdate());
  UpdateAllLifecyclePhasesForTest();

  // Check that the element has the background color provided by the variable.
  Element* target = GetDocument().getElementById(AtomicString("target"));
  EXPECT_EQ(kTestColorRed, target->ComputedStyleRef().VisitedDependentColor(
                               GetCSSPropertyBackgroundColor()));
}

TEST_F(StyleEnvironmentVariablesTest, DocumentVariable_Change) {
  SetVariableOnDocument(kVariableName, kVariableAltTestColor);
  InitializeTestPageWithVariableNamed(GetFrame(), kVariableName);

  // Change the variable value after we have loaded the page.
  SetVariableOnDocument(kVariableName, kVariableTestColor);

  // Ensure that the document has been invalidated.
  EXPECT_TRUE(GetDocument().NeedsLayoutTreeUpdate());
  UpdateAllLifecyclePhasesForTest();

  // Check that the element has the background color provided by the variable.
  Element* target = GetDocument().getElementById(AtomicString("target"));
  EXPECT_EQ(kTestColorRed, target->ComputedStyleRef().VisitedDependentColor(
                               GetCSSPropertyBackgroundColor()));
}

TEST_F(StyleEnvironmentVariablesTest,
       DocumentVariable_Override_RemoveDocument) {
  // Set the variable globally.
  SetVariableOnRoot(kVariableName, kVariableAltTestColor);
  InitializeTestPageWithVariableNamed(GetFrame(), kVariableName);

  // Check that the element has the background color provided by the global
  // variable.
  Element* target = GetDocument().getElementById(AtomicString("target"));
  EXPECT_EQ(kAltTestColor, target->ComputedStyleRef().VisitedDependentColor(
                               GetCSSPropertyBackgroundColor()));

  // Change the variable value on the document after we have loaded the page.
  SetVariableOnDocument(kVariableName, kVariableTestColor);

  // Ensure that the document has been invalidated.
  EXPECT_TRUE(GetDocument().NeedsLayoutTreeUpdate());
  UpdateAllLifecyclePhasesForTest();

  // Check that the element has the background color provided by the document
  // variable.
  EXPECT_EQ(kTestColorRed, target->ComputedStyleRef().VisitedDependentColor(
                               GetCSSPropertyBackgroundColor()));

  // Remove the document variable.
  RemoveVariableOnDocument(kVariableName);

  // Ensure that the document has been invalidated.
  EXPECT_TRUE(GetDocument().NeedsLayoutTreeUpdate());
  UpdateAllLifecyclePhasesForTest();

  // Check that the element has the background color provided by the global
  // variable.
  EXPECT_EQ(kAltTestColor, target->ComputedStyleRef().VisitedDependentColor(
                               GetCSSPropertyBackgroundColor()));
}

TEST_F(StyleEnvironmentVariablesTest, DocumentVariable_Override_RemoveGlobal) {
  // Set the variable globally.
  SetVariableOnRoot(kVariableName, kVariableAltTestColor);
  InitializeTestPageWithVariableNamed(GetFrame(), kVariableName);

  // Check that the element has the background color provided by the global
  // variable.
  Element* target = GetDocument().getElementById(AtomicString("target"));
  EXPECT_EQ(kAltTestColor, target->ComputedStyleRef().VisitedDependentColor(
                               GetCSSPropertyBackgroundColor()));

  // Change the variable value on the document after we have loaded the page.
  SetVariableOnDocument(kVariableName, kVariableTestColor);

  // Ensure that the document has been invalidated.
  EXPECT_TRUE(GetDocument().NeedsLayoutTreeUpdate());
  UpdateAllLifecyclePhasesForTest();

  // Check that the element has the background color provided by the document
  // variable.
  EXPECT_EQ(kTestColorRed, target->ComputedStyleRef().VisitedDependentColor(
                               GetCSSPropertyBackgroundColor()));

  // Remove the global variable.
  RemoveVariableOnRoot(kVariableName);

  // Ensure that the document has not been invalidated.
  EXPECT_FALSE(GetDocument().NeedsLayoutTreeUpdate());
}

TEST_F(StyleEnvironmentVariablesTest, DocumentVariable_Preset) {
  SetVariableOnDocument(kVariableName, kVariableTestColor);
  InitializeTestPageWithVariableNamed(GetFrame(), kVariableName);

  // Check that the element has the background color provided by the variable.
  Element* target = GetDocument().getElementById(AtomicString("target"));
  EXPECT_EQ(kTestColorRed, target->ComputedStyleRef().VisitedDependentColor(
                               GetCSSPropertyBackgroundColor()));
}

TEST_F(StyleEnvironmentVariablesTest, DocumentVariable_Remove) {
  SetVariableOnDocument(kVariableName, kVariableTestColor);
  InitializeTestPageWithVariableNamed(GetFrame(), kVariableName);

  // Check that the element has the background color provided by the variable.
  Element* target = GetDocument().getElementById(AtomicString("target"));
  EXPECT_EQ(kTestColorRed, target->ComputedStyleRef().VisitedDependentColor(
                               GetCSSPropertyBackgroundColor()));

  // Change the variable value after we have loaded the page.
  RemoveVariableOnDocument(kVariableName);

  // Ensure that the document has been invalidated.
  EXPECT_TRUE(GetDocument().NeedsLayoutTreeUpdate());
  UpdateAllLifecyclePhasesForTest();

  // Check that the element does not have the background color any more.
  EXPECT_NE(kTestColorRed, target->ComputedStyleRef().VisitedDependentColor(
                               GetCSSPropertyBackgroundColor()));
}

TEST_F(StyleEnvironmentVariablesTest, MultiDocumentInvalidation_FromRoot) {
  InitializeTestPageWithVariableNamed(GetFrame(), kVariableName);

  // Create a second page that uses the variable.
  auto new_page = std::make_unique<DummyPageHolder>(gfx::Size(800, 600));
  InitializeTestPageWithVariableNamed(new_page->GetFrame(), kVariableName);

  // Create an empty page that does not use the variable.
  auto empty_page = std::make_unique<DummyPageHolder>(gfx::Size(800, 600));
  empty_page->GetDocument().View()->UpdateAllLifecyclePhasesForTest();

  SetVariableOnRoot(kVariableName, kVariableTestColor);

  // The first two pages should be invalidated and the empty one should not.
  EXPECT_TRUE(GetDocument().NeedsLayoutTreeUpdate());
  EXPECT_TRUE(new_page->GetDocument().NeedsLayoutTreeUpdate());
  EXPECT_FALSE(empty_page->GetDocument().NeedsLayoutTreeUpdate());
}

TEST_F(StyleEnvironmentVariablesTest, MultiDocumentInvalidation_FromDocument) {
  InitializeTestPageWithVariableNamed(GetFrame(), kVariableName);

  // Create a second page that uses the variable.
  auto new_page = std::make_unique<DummyPageHolder>(gfx::Size(800, 600));
  InitializeTestPageWithVariableNamed(new_page->GetFrame(), kVariableName);

  SetVariableOnDocument(kVariableName, kVariableTestColor);

  // Only the first document should be invalidated.
  EXPECT_TRUE(GetDocument().NeedsLayoutTreeUpdate());
  EXPECT_FALSE(new_page->GetDocument().NeedsLayoutTreeUpdate());
}

TEST_F(StyleEnvironmentVariablesTest, NavigateToClear) {
  SetVariableOnDocument(kVariableName, kVariableTestColor);

  // Simulate a navigation to clear the variables.
  SimulateNavigation();
  InitializeTestPageWithVariableNamed(GetFrame(), kVariableName);

  // Check that the element has no background color.
  Element* target = GetDocument().getElementById(AtomicString("target"));
  EXPECT_EQ(kNoColor, target->ComputedStyleRef().VisitedDependentColor(
                          GetCSSPropertyBackgroundColor()));
}

TEST_F(StyleEnvironmentVariablesTest, GlobalVariable_AfterLoad) {
  InitializeTestPageWithVariableNamed(GetFrame(), kVariableName);
  SetVariableOnRoot(kVariableName, kVariableTestColor);

  // Ensure that the document has been invalidated.
  EXPECT_TRUE(GetDocument().NeedsLayoutTreeUpdate());
  UpdateAllLifecyclePhasesForTest();

  // Check that the element has the background color provided by the variable.
  Element* target = GetDocument().getElementById(AtomicString("target"));
  EXPECT_EQ(kTestColorRed, target->ComputedStyleRef().VisitedDependentColor(
                               GetCSSPropertyBackgroundColor()));
}

TEST_F(StyleEnvironmentVariablesTest, GlobalVariable_Change) {
  SetVariableOnRoot(kVariableName, kVariableAltTestColor);
  InitializeTestPageWithVariableNamed(GetFrame(), kVariableName);

  // Change the variable value after we have loaded the page.
  SetVariableOnRoot(kVariableName, kVariableTestColor);

  // Ensure that the document has been invalidated.
  EXPECT_TRUE(GetDocument().NeedsLayoutTreeUpdate());
  UpdateAllLifecyclePhasesForTest();

  // Check that the element has the background color provided by the variable.
  Element* target = GetDocument().getElementById(AtomicString("target"));
  EXPECT_EQ(kTestColorRed, target->ComputedStyleRef().VisitedDependentColor(
                               GetCSSPropertyBackgroundColor()));
}

TEST_F(StyleEnvironmentVariablesTest, GlobalVariable_DefaultsPresent) {
  EXPECT_EQ(kSafeAreaInsetExpectedDefault,
            GetRootVariableValue(UADefinedVariable::kSafeAreaInsetTop));
  EXPECT_EQ(kSafeAreaInsetExpectedDefault,
            GetRootVariableValue(UADefinedVariable::kSafeAreaInsetLeft));
  EXPECT_EQ(kSafeAreaInsetExpectedDefault,
            GetRootVariableValue(UADefinedVariable::kSafeAreaInsetBottom));
  EXPECT_EQ(kSafeAreaInsetExpectedDefault,
            GetRootVariableValue(UADefinedVariable::kSafeAreaInsetRight));

  EXPECT_EQ(nullptr,
            StyleEnvironmentVariables::GetRootInstance().ResolveVariable(
                AtomicString("test"), {}));
}

TEST_F(StyleEnvironmentVariablesTest, GlobalVariable_Preset) {
  SetVariableOnRoot(kVariableName, kVariableTestColor);
  InitializeTestPageWithVariableNamed(GetFrame(), kVariableName);

  // Check that the element has the background color provided by the variable.
  Element* target = GetDocument().getElementById(AtomicString("target"));
  EXPECT_EQ(kTestColorRed, target->ComputedStyleRef().VisitedDependentColor(
                               GetCSSPropertyBackgroundColor()));
}

TEST_F(StyleEnvironmentVariablesTest, GlobalVariable_Remove) {
  SetVariableOnRoot(kVariableName, kVariableTestColor);
  InitializeTestPageWithVariableNamed(GetFrame(), kVariableName);

  // Check that the element has the background color provided by the variable.
  Element* target = GetDocument().getElementById(AtomicString("target"));
  EXPECT_EQ(kTestColorRed, target->ComputedStyleRef().VisitedDependentColor(
                               GetCSSPropertyBackgroundColor()));

  // Change the variable value after we have loaded the page.
  RemoveVariableOnRoot(kVariableName);

  // Ensure that the document has been invalidated.
  EXPECT_TRUE(GetDocument().NeedsLayoutTreeUpdate());
  UpdateAllLifecyclePhasesForTest();

  // Check that the element does not have the background color any more.
  EXPECT_NE(kTestColorRed, target->ComputedStyleRef().VisitedDependentColor(
                               GetCSSPropertyBackgroundColor()));
}

TEST_F(StyleEnvironmentVariablesTest, RecordUseCounter_IgnoreMediaControls) {
  InitializeWithHTML(GetFrame(), "<video controls />");

  EXPECT_FALSE(GetDocument().IsUseCounted(WebFeature::kCSSEnvironmentVariable));
  EXPECT_FALSE(GetDocument().IsUseCounted(
      WebFeature::kCSSEnvironmentVariable_SafeAreaInsetTop));
  EXPECT_FALSE(GetDocument().IsUseCounted(
      WebFeature::kCSSEnvironmentVariable_SafeAreaInsetLeft));
  EXPECT_FALSE(GetDocument().IsUseCounted(
      WebFeature::kCSSEnvironmentVariable_SafeAreaInsetBottom));
  EXPECT_FALSE(GetDocument().IsUseCounted(
      WebFeature::kCSSEnvironmentVariable_SafeAreaInsetRight));
}

TEST_F(StyleEnvironmentVariablesTest, RecordUseCounter_InvalidProperty) {
  InitializeTestPageWithVariableNamed(GetFrame(), kVariableName);
  EXPECT_TRUE(GetDocument().IsUseCounted(WebFeature::kCSSEnvironmentVariable));
}

TEST_F(StyleEnvironmentVariablesTest, RecordUseCounter_NoVariable) {
  InitializeWithHTML(GetFrame(), "");
  EXPECT_FALSE(GetDocument().IsUseCounted(WebFeature::kCSSEnvironmentVariable));
}

TEST_F(StyleEnvironmentVariablesTest, RecordUseCounter_SafeAreaInsetBottom) {
  InitializeTestPageWithVariableNamed(GetFrame(),
                                      UADefinedVariable::kSafeAreaInsetBottom);

  EXPECT_TRUE(GetDocument().IsUseCounted(WebFeature::kCSSEnvironmentVariable));
  EXPECT_TRUE(GetDocument().IsUseCounted(
      WebFeature::kCSSEnvironmentVariable_SafeAreaInsetBottom));
}

// TODO(https://crbug.com/1430288) remove after data collected (end of '23)
TEST_F(StyleEnvironmentVariablesTest,
       RecordUseCounter_ViewportFitCoverOrSafeAreaInsetBottom) {
  InitializeWithHTML(GetFrame(), "");
  EXPECT_FALSE(GetDocument().IsUseCounted(
      WebFeature::kViewportFitCoverOrSafeAreaInsetBottom));
  InitializeTestPageWithVariableNamed(GetFrame(),
                                      UADefinedVariable::kSafeAreaInsetBottom);
  EXPECT_TRUE(GetDocument().IsUseCounted(
      WebFeature::kViewportFitCoverOrSafeAreaInsetBottom));
}

TEST_F(StyleEnvironmentVariablesTest, RecordUseCounter_SafeAreaInsetLeft) {
  InitializeTestPageWithVariableNamed(GetFrame(),
                                      UADefinedVariable::kSafeAreaInsetLeft);

  EXPECT_TRUE(GetDocument().IsUseCounted(WebFeature::kCSSEnvironmentVariable));
  EXPECT_TRUE(GetDocument().IsUseCounted(
      WebFeature::kCSSEnvironmentVariable_SafeAreaInsetLeft));
}

TEST_F(StyleEnvironmentVariablesTest, RecordUseCounter_SafeAreaInsetRight) {
  InitializeTestPageWithVariableNamed(GetFrame(),
                                      UADefinedVariable::kSafeAreaInsetRight);

  EXPECT_TRUE(GetDocument().IsUseCounted(WebFeature::kCSSEnvironmentVariable));
  EXPECT_TRUE(GetDocument().IsUseCounted(
      WebFeature::kCSSEnvironmentVariable_SafeAreaInsetRight));
}

TEST_F(StyleEnvironmentVariablesTest, RecordUseCounter_SafeAreaInsetTop) {
  InitializeTestPageWithVariableNamed(GetFrame(),
                                      UADefinedVariable::kSafeAreaInsetTop);

  EXPECT_TRUE(GetDocument().IsUseCounted(WebFeature::kCSSEnvironmentVariable));
  EXPECT_TRUE(GetDocument().IsUseCounted(
      WebFeature::kCSSEnvironmentVariable_SafeAreaInsetTop));
}

TEST_F(StyleEnvironmentVariablesTest, KeyboardInset_AfterLoad) {
  // This test asserts that the keyboard inset environment variables are loaded
  // by default.
  CSSVariableData* data =
      StyleEnvironmentVariables::GetRootInstance().ResolveVariable(
          StyleEnvironmentVariables::GetVariableName(
              UADefinedVariable::kKeyboardInsetTop,
              /*feature_context=*/nullptr),
          {});
  EXPECT_TRUE(data);
  data = StyleEnvironmentVariables::GetRootInstance().ResolveVariable(
      StyleEnvironmentVariables::GetVariableName(
          UADefinedVariable::kKeyboardInsetLeft, /*feature_context=*/nullptr),
      {});
  EXPECT_TRUE(data);
  data = StyleEnvironmentVariables::GetRootInstance().ResolveVariable(
      StyleEnvironmentVariables::GetVariableName(
          UADefinedVariable::kKeyboardInsetBottom,
          /*feature_context=*/nullptr),
      {});
  EXPECT_TRUE(data);
  data = StyleEnvironmentVariables::GetRootInstance().ResolveVariable(
      StyleEnvironmentVariables::GetVariableName(
          UADefinedVariable::kKeyboardInsetRight, /*feature_context=*/nullptr),
      {});
  EXPECT_TRUE(data);
  data = StyleEnvironmentVariables::GetRootInstance().ResolveVariable(
      StyleEnvironmentVariables::GetVariableName(
          UADefinedVariable::kKeyboardInsetWidth, /*feature_context=*/nullptr),
      {});
  EXPECT_TRUE(data);
  data = StyleEnvironmentVariables::GetRootInstance().ResolveVariable(
      StyleEnvironmentVariables::GetVariableName(
          UADefinedVariable::kKeyboardInsetHeight,
          /*feature_context=*/nullptr),
      {});
  EXPECT_TRUE(data);
}

TEST_F(StyleEnvironmentVariablesTest, TwoDimensionalVariables_BasicResolve) {
  ScopedViewportSegmentsForTest scoped_feature(true);
  String env_contents("viewport-segment-top 1 0");
  InitializeTestPageWithVariableNamed(GetFrame(), env_contents);
  SetTwoDimensionalVariableOnRoot(
      UADefinedTwoDimensionalVariable::kViewportSegmentTop, 1, 0, "red");

  // Ensure that the document has been invalidated.
  EXPECT_TRUE(GetDocument().NeedsLayoutTreeUpdate());
  UpdateAllLifecyclePhasesForTest();

  // Check that the element has the background color provided by the variable.
  Element* target = GetDocument().getElementById(AtomicString("target"));
  EXPECT_EQ(kTestColorRed, target->ComputedStyleRef().VisitedDependentColor(
                               GetCSSPropertyBackgroundColor()));
}

TEST_F(StyleEnvironmentVariablesTest, TwoDimensionalVariables_UpdateValue) {
  ScopedViewportSegmentsForTest scoped_feature(true);
  String env_contents("viewport-segment-top 1 0");
  InitializeTestPageWithVariableNamed(GetFrame(), env_contents);
  SetTwoDimensionalVariableOnRoot(
      UADefinedTwoDimensionalVariable::kViewportSegmentTop, 1, 0, "red");

  // Ensure that the document has been invalidated.
  EXPECT_TRUE(GetDocument().NeedsLayoutTreeUpdate());
  UpdateAllLifecyclePhasesForTest();

  // Check that the element has the background color provided by the variable.
  Element* target = GetDocument().getElementById(AtomicString("target"));
  EXPECT_EQ(kTestColorRed, target->ComputedStyleRef().VisitedDependentColor(
                               GetCSSPropertyBackgroundColor()));

  SetTwoDimensionalVariableOnRoot(
      UADefinedTwoDimensionalVariable::kViewportSegmentTop, 1, 0, "blue");
  EXPECT_TRUE(GetDocument().NeedsLayoutTreeUpdate());
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(kAltTestColor, target->ComputedStyleRef().VisitedDependentColor(
                               GetCSSPropertyBackgroundColor()));
}

TEST_F(StyleEnvironmentVariablesTest,
       TwoDimensionalVariables_UndefinedFallsBack) {
  ScopedViewportSegmentsForTest scoped_feature(true);
  String env_contents(
      "viewport-segment-width 10 20, env(viewport-segment-width 0 0, blue)");
  InitializeTestPageWithVariableNamed(GetFrame(), env_contents);
  SetTwoDimensionalVariableOnRoot(
      UADefinedTwoDimensionalVariable::kViewportSegmentWidth, 1, 1, "red");

  // Ensure that the document has been invalidated.
  EXPECT_TRUE(GetDocument().NeedsLayoutTreeUpdate());
  UpdateAllLifecyclePhasesForTest();

  // Check that the element has the background color provided by the fallback.
  Element* target = GetDocument().getElementById(AtomicString("target"));
  EXPECT_EQ(kAltTestColor, target->ComputedStyleRef().VisitedDependentColor(
                               GetCSSPropertyBackgroundColor()));
}

TEST_F(StyleEnvironmentVariablesTest,
       TwoDimensionalVariables_IncorrectDimensionsFallsBack) {
  ScopedViewportSegmentsForTest scoped_feature(true);
  String env_contents("viewport-segment-width 0 0 0 0, blue");
  InitializeTestPageWithVariableNamed(GetFrame(), env_contents);
  SetTwoDimensionalVariableOnRoot(
      UADefinedTwoDimensionalVariable::kViewportSegmentWidth, 0, 0, "red");

  // Ensure that the document has been invalidated.
  EXPECT_TRUE(GetDocument().NeedsLayoutTreeUpdate());
  UpdateAllLifecyclePhasesForTest();

  // Check that the element has the background color provided by the fallback.
  Element* target = GetDocument().getElementById(AtomicString("target"));
  EXPECT_EQ(kAltTestColor, target->ComputedStyleRef().VisitedDependentColor(
                               GetCSSPropertyBackgroundColor()));
}

TEST_F(StyleEnvironmentVariablesTest,
       TwoDimensionalVariables_NormalVariableWithDimensionFallsBack) {
  ScopedViewportSegmentsForTest scoped_feature(true);
  String env_contents("safe-area-inset-left 0, blue");
  InitializeTestPageWithVariableNamed(GetFrame(), env_contents);
  SetVariableOnRoot("safe-area-inset-left", "red");

  // Ensure that the document has been invalidated.
  EXPECT_TRUE(GetDocument().NeedsLayoutTreeUpdate());
  UpdateAllLifecyclePhasesForTest();

  // Check that the element has the background color provided by the fallback.
  Element* target = GetDocument().getElementById(AtomicString("target"));
  EXPECT_EQ(kAltTestColor, target->ComputedStyleRef().VisitedDependentColor(
                               GetCSSPropertyBackgroundColor()));
}

TEST_F(StyleEnvironmentVariablesTest,
       TwoDimensionalVariables_NegativeIndicesInvalid) {
  ScopedViewportSegmentsForTest scoped_feature(true);
  String env_contents("viewport-segment-top -1 -1, blue");
  InitializeTestPageWithVariableNamed(GetFrame(), env_contents);
  SetTwoDimensionalVariableOnRoot(
      UADefinedTwoDimensionalVariable::kViewportSegmentTop, 0, 0, "red");
  SetTwoDimensionalVariableOnRoot(
      UADefinedTwoDimensionalVariable::kViewportSegmentTop, 1, 1, "red");

  // Document should not have been invalidated since the value was a parse
  // error and viewport-segment-left is not referenced.
  EXPECT_FALSE(GetDocument().NeedsLayoutTreeUpdate());

  // Check that the element has no cascaded background color.
  Element* target = GetDocument().getElementById(AtomicString("target"));
  EXPECT_EQ(kNoColor, target->ComputedStyleRef().VisitedDependentColor(
                          GetCSSPropertyBackgroundColor()));
}

TEST_F(StyleEnvironmentVariablesTest,
       TwoDimensionalVariables_NonCommaAfterIndexInvalid) {
  ScopedViewportSegmentsForTest scoped_feature(true);
  String env_contents("viewport-segment-left 1 1 ident");
  InitializeTestPageWithVariableNamed(GetFrame(), env_contents);
  SetTwoDimensionalVariableOnRoot(
      UADefinedTwoDimensionalVariable::kViewportSegmentLeft, 1, 1, "red");

  // Document should not have been invalidated since the value was a parse
  // error and viewport-segment-left is not referenced.
  EXPECT_FALSE(GetDocument().NeedsLayoutTreeUpdate());

  // Check that the element has no cascaded background color.
  Element* target = GetDocument().getElementById(AtomicString("target"));
  EXPECT_EQ(kNoColor, target->ComputedStyleRef().VisitedDependentColor(
                          GetCSSPropertyBackgroundColor()));
}

TEST_F(StyleEnvironmentVariablesTest,
       TwoDimensionalVariables_NonIntegerIndicesInvalid) {
  ScopedViewportSegmentsForTest scoped_feature(true);
  String env_contents("viewport-segment-top 0.5 0.5, blue");
  InitializeTestPageWithVariableNamed(GetFrame(), env_contents);
  SetTwoDimensionalVariableOnRoot(
      UADefinedTwoDimensionalVariable::kViewportSegmentTop, 0, 0, "red");
  SetTwoDimensionalVariableOnRoot(
      UADefinedTwoDimensionalVariable::kViewportSegmentTop, 1, 1, "red");

  // Document should not have been invalidated since the value was a parse
  // error and viewport-segment-left is not referenced.
  EXPECT_FALSE(GetDocument().NeedsLayoutTreeUpdate());

  // Check that the element has no cascaded background color.
  Element* target = GetDocument().getElementById(AtomicString("target"));
  EXPECT_EQ(kNoColor, target->ComputedStyleRef().VisitedDependentColor(
                          GetCSSPropertyBackgroundColor()));
}

TEST_F(StyleEnvironmentVariablesTest,
       TwoDimensionalVariables_NoIndicesFallsBack) {
  ScopedViewportSegmentsForTest scoped_feature(true);
  String env_contents("viewport-segment-height, blue");
  InitializeTestPageWithVariableNamed(GetFrame(), env_contents);
  SetTwoDimensionalVariableOnRoot(
      UADefinedTwoDimensionalVariable::kViewportSegmentTop, 0, 0, "red");

  // Document should not have been invalidated since the wrong dimensions can
  // never resolve (and thus the variable has not been 'seen').
  EXPECT_FALSE(GetDocument().NeedsLayoutTreeUpdate());

  // Check that the element has the background color provided by the fallback.
  Element* target = GetDocument().getElementById(AtomicString("target"));
  EXPECT_EQ(kAltTestColor, target->ComputedStyleRef().VisitedDependentColor(
                               GetCSSPropertyBackgroundColor()));
}

TEST_F(StyleEnvironmentVariablesTest, TwoDimensionalVariables_Removal) {
  ScopedViewportSegmentsForTest scoped_feature(true);
  String env_contents("viewport-segment-height 0 0, blue");
  InitializeTestPageWithVariableNamed(GetFrame(), env_contents);
  SetTwoDimensionalVariableOnRoot(
      UADefinedTwoDimensionalVariable::kViewportSegmentHeight, 0, 0, "red");

  // Ensure that the document has been invalidated.
  EXPECT_TRUE(GetDocument().NeedsLayoutTreeUpdate());
  UpdateAllLifecyclePhasesForTest();

  // Check that the element has the background color provided by the variable.
  Element* target = GetDocument().getElementById(AtomicString("target"));
  EXPECT_EQ(kTestColorRed, target->ComputedStyleRef().VisitedDependentColor(
                               GetCSSPropertyBackgroundColor()));

  RemoveVariableOnRoot("viewport-segment-height");
  EXPECT_TRUE(GetDocument().NeedsLayoutTreeUpdate());
  UpdateAllLifecyclePhasesForTest();

  // Check that the element has the background color provided by the fallback.
  EXPECT_EQ(kAltTestColor, target->ComputedStyleRef().VisitedDependentColor(
                               GetCSSPropertyBackgroundColor()));
}

#if !BUILDFLAG(IS_ANDROID)
TEST_F(StyleEnvironmentVariablesTest, TitlebarArea_AfterLoad) {
  // This test asserts that the titlebar area environment variables should be
  // loaded when UpdateWindowControlsOverlay is invoked in LocalFrame for PWAs
  // with display_override "window-controls-overlay".

  // Simulate browser sending the titlebar area bounds.
  GetFrame().UpdateWindowControlsOverlay(gfx::Rect(0, 0, 100, 10));
  String env_contents("titlebar-area-x");
  InitializeTestPageWithVariableNamed(GetFrame(), env_contents);

  // Validate the data is set.
  DocumentStyleEnvironmentVariables& vars =
      GetDocument().GetStyleEngine().EnsureEnvironmentVariables();

  CSSVariableData* data =
      vars.ResolveVariable(StyleEnvironmentVariables::GetVariableName(
                               UADefinedVariable::kTitlebarAreaX,
                               /*feature_context=*/nullptr),
                           {});
  EXPECT_TRUE(data);
  EXPECT_EQ(data->Serialize(), "0px");
  data = vars.ResolveVariable(
      StyleEnvironmentVariables::GetVariableName(
          UADefinedVariable::kTitlebarAreaY, /*feature_context=*/nullptr),
      {});
  EXPECT_TRUE(data);
  EXPECT_EQ(data->Serialize(), "0px");
  data = vars.ResolveVariable(StyleEnvironmentVariables::GetVariableName(
                                  UADefinedVariable::kTitlebarAreaWidth,
                                  /*feature_context=*/nullptr),
                              {});
  EXPECT_TRUE(data);
  EXPECT_EQ(data->Serialize(), "100px");
  data = vars.ResolveVariable(
      StyleEnvironmentVariables::GetVariableName(
          UADefinedVariable::kTitlebarAreaHeight, /*feature_context=*/nullptr),
      {});
  EXPECT_TRUE(data);
  EXPECT_EQ(data->Serialize(), "10px");
}

TEST_F(StyleEnvironmentVariablesTest, TitlebarArea_AfterNavigation) {
  // This test asserts that the titlebar area environment variables should be
  // set after a navigation for PWAs with display_override
  // "window-controls-overlay".

  // Simulate browser sending the titlebar area bounds.
  GetFrame().UpdateWindowControlsOverlay(gfx::Rect(0, 0, 100, 10));
  String env_contents("titlebar-area-x");
  InitializeTestPageWithVariableNamed(GetFrame(), env_contents);

  SimulateNavigation();

  // Validate the data is set after navigation.
  DocumentStyleEnvironmentVariables& vars =
      GetDocument().GetStyleEngine().EnsureEnvironmentVariables();

  CSSVariableData* data =
      vars.ResolveVariable(StyleEnvironmentVariables::GetVariableName(
                               UADefinedVariable::kTitlebarAreaX,
                               /*feature_context=*/nullptr),
                           {});
  EXPECT_TRUE(data);
  EXPECT_EQ(data->Serialize(), "0px");
  data = vars.ResolveVariable(
      StyleEnvironmentVariables::GetVariableName(
          UADefinedVariable::kTitlebarAreaY, /*feature_context=*/nullptr),
      {});
  EXPECT_TRUE(data);
  EXPECT_EQ(data->Serialize(), "0px");
  data = vars.ResolveVariable(StyleEnvironmentVariables::GetVariableName(
               
"""


```