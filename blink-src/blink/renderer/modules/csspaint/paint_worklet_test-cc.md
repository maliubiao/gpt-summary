Response:
Let's break down the thought process for analyzing the `paint_worklet_test.cc` file.

1. **Understand the Core Purpose:** The file name itself, `paint_worklet_test.cc`, strongly suggests it's a testing file for the `PaintWorklet` functionality within the Blink rendering engine. The presence of `#include "testing/gtest/include/gtest/gtest.h"` confirms this.

2. **Identify Key Classes and Concepts:** Scan the `#include` directives and the code itself to identify the main classes involved. We see:
    * `PaintWorklet`: The central class being tested.
    * `PaintWorkletGlobalScope`, `PaintWorkletGlobalScopeProxy`:  Related to the execution environment of the paint worklet.
    * `CSSPaintDefinition`: Represents the registered paint functions.
    * `CSSPaintImageGeneratorImpl`:  Responsible for generating images based on paint worklets.
    * `StylePropertyMapReadOnly`: For accessing CSS property values.
    * `Image`: The resulting image produced by the paint worklet.
    * `DocumentPaintDefinition`: A document-level representation of a paint definition.

3. **Analyze the Test Structure:** Notice the use of `TEST_F` and `TEST_P`. This indicates the use of Google Test framework. `TEST_F` signifies a standard test fixture (`PaintWorkletTest`), while `TEST_P` uses parameterized tests (`MainOrOffThreadPaintWorkletTest`).

4. **Decipher Individual Tests:**  Go through each `TEST_F` and `TEST_P` block and try to understand its specific goal. Look for keywords and actions within the test:
    * `PaintWithNullPaintArguments`:  The name hints at testing the scenario where paint arguments are null. The code confirms this by registering a paint function and then calling `Paint` with `nullptr`.
    * `SinglyRegisteredDocumentDefinitionNotUsed`: This suggests testing the behavior when only one paint function is registered. The code registers one and then checks if it's considered "valid" for painting.
    * `GlobalScopeSelection`: This strongly points to testing the logic of how and when different "global scopes" are used within the paint worklet. The `ExpectSwitchGlobalScope` helper function confirms this.
    * `NativeAndCustomProperties`:  This one is clearly about testing how native CSS properties and custom properties are handled in paint worklets.
    * `ConsistentGlobalScopeOnMainThread` and `ConsistentGlobalScopeCrossThread`: These tests, particularly with the `MainOrOffThreadPaintWorkletTest` fixture, focus on ensuring consistency of paint definitions across different "global scopes" and potentially across threads. The code involves registering paint functions in different scopes and verifying their validity.
    * `AllGlobalScopesMustBeCreated`:  This tests the initialization process, ensuring the correct number of global scopes are created.
    * `GeneratorNotifiedAfterAllRegistrations`:  This focuses on the notification mechanism (`MockObserver`) and verifies that the generator is notified only after all necessary registrations (including cross-thread) are complete.

5. **Identify Relationships to Web Technologies:** Connect the identified classes and test scenarios to their corresponding concepts in JavaScript, HTML, and CSS:
    * `registerPaint()` in JavaScript maps directly to the registration of paint functions tested here.
    * CSS custom properties (`--my-property`) are explicitly tested.
    * The concept of a "paint worklet" itself is a CSS feature for custom image rendering.
    * The tests implicitly involve HTML elements to which these paint worklets could be applied via CSS `background-image` or `border-image`.

6. **Infer Logic and Potential Issues:** Based on the test names and the code, deduce the underlying logic being tested and potential issues the tests aim to prevent:
    * Null pointer dereferences (as in `PaintWithNullPaintArguments`).
    * Incorrect usage of singly registered paint functions.
    * Problems with switching between global scopes.
    * Inconsistent handling of paint definitions across threads.
    * Race conditions or incorrect notification timing for image generators.

7. **Consider User Actions and Debugging:** Think about how a developer might encounter issues related to paint worklets and how these tests help in debugging:
    * A developer might write a `registerPaint()` function with errors.
    * They might try to use a paint function before it's fully registered.
    * They might observe unexpected behavior when multiple paint functions with the same name are registered.
    * Performance issues related to frequent global scope switching could arise. These tests help verify the correctness of the switching logic.

8. **Structure the Output:**  Organize the findings into logical categories like "Functionality," "Relationship to Web Technologies," "Logic and Assumptions," "Common User Errors," and "Debugging Clues." Use clear and concise language, providing code examples where helpful.

9. **Refine and Review:**  Read through the generated explanation, ensuring accuracy and completeness. Check for any ambiguities or areas where more detail could be added. For example, initially, the explanation of "global scopes" might be too abstract, so adding the idea of isolated JavaScript execution contexts would improve clarity.

This methodical approach of identifying the core purpose, analyzing the structure, deciphering individual tests, connecting to web technologies, inferring logic, considering user actions, structuring the output, and refining the explanation leads to a comprehensive understanding of the `paint_worklet_test.cc` file and its role in testing the paint worklet feature.
This C++ source code file, `paint_worklet_test.cc`, is part of the Chromium Blink rendering engine and specifically focuses on **testing the functionality of the `PaintWorklet` class and related components**. Think of it as a unit test suite for the CSS Paint API implementation within Blink.

Here's a breakdown of its functionality, relationships, logic, potential errors, and debugging clues:

**Functionality:**

* **Testing `PaintWorklet` Class:** The primary goal is to verify the correct behavior of the `PaintWorklet` class, which manages the execution and lifecycle of paint worklets.
* **Testing Global Scope Management:** It tests how `PaintWorklet` creates, manages, and switches between different global scopes (JavaScript execution environments) for paint worklets. This is crucial for performance and isolation.
* **Testing Paint Definition Registration:** It checks how paint definitions (registered using `registerPaint()` in JavaScript) are stored, accessed, and invalidated within the `PaintWorklet`.
* **Testing Interaction with `CSSPaintDefinition`:** It verifies the interaction between `PaintWorklet` and `CSSPaintDefinition`, which represents a registered paint function.
* **Testing Image Generation:** It indirectly tests the process of generating images using paint worklets by invoking the `Paint()` method of `CSSPaintDefinition`.
* **Testing Off-Main-Thread Paint (if enabled):**  Some tests specifically target scenarios where CSS Paint is executed off the main thread, ensuring correct behavior in a multithreaded environment.
* **Regression Testing:** Some tests, like `PaintWithNullPaintArguments`, are specifically designed to prevent regressions of previously identified bugs.

**Relationship to JavaScript, HTML, and CSS:**

This test file is intrinsically linked to the CSS Paint API, which allows developers to define custom image rendering logic using JavaScript and CSS.

* **JavaScript:** The tests execute JavaScript code snippets within the paint worklet's global scope using `ClassicScript`. These snippets typically use the `registerPaint()` function to define custom paint functions.
    * **Example:**  The code `registerPaint('foo', class { paint() { } });` registers a paint function named 'foo'.
* **HTML:** While not directly manipulating HTML elements, the tests simulate scenarios where paint worklets would be used in conjunction with HTML. The `ImageResourceObserver` is obtained from a `LayoutObject` associated with the DOM.
* **CSS:** The tests indirectly relate to CSS through the concept of CSS properties and values. The `StylePropertyMapReadOnly` is used to access computed style values, and the tests consider CSS invalidation properties. The `CSSPaintImageGeneratorImpl` is used to represent the CSS `paint()` function.
    * **Example:** The `inputProperties` getter in `registerPaint()` (e.g., `static get inputProperties() { return ['--foo']; }`) defines which CSS custom properties will trigger the paint function.

**Logic and Assumptions (with Input/Output Examples):**

* **Global Scope Switching:** The `GlobalScopeSelection` test verifies that the `PaintWorklet` correctly switches between global scopes after a certain number of paint calls.
    * **Assumption:**  Using multiple global scopes improves performance by reducing contention and allowing parallel execution.
    * **Input (Conceptual):** Trigger multiple paint operations on an element using the same paint worklet.
    * **Output:** The test verifies that the `SelectGlobalScope()` method returns different global scope indices according to the configured `paints_to_switch_` value.
* **Singly Registered Definition:** The `SinglyRegisteredDocumentDefinitionNotUsed` test assumes that a paint definition registered only once shouldn't be used for painting until a second definition with the same name is registered. This is likely a mechanism to ensure the worklet is fully initialized and ready.
    * **Input:** Register a paint function named 'foo' once.
    * **Output:** The `GetValidDocumentDefinitionForTesting()` method of `CSSPaintImageGeneratorImpl` should return `false` (or `true` only when off-main-thread paint is enabled, reflecting a difference in implementation).
* **Consistent Global Scope:** The `ConsistentGlobalScopeOnMainThread` and `ConsistentGlobalScopeCrossThread` tests aim to ensure that paint definitions are consistent across different global scopes and threads. If the definition changes in one scope, it should be reflected and potentially invalidate the definition in other contexts.
    * **Input:** Register the same paint function with different properties in different global scopes.
    * **Output:** The `GetDocumentDefinitionMap()` should reflect the latest valid definition, and older or inconsistent definitions should be invalidated.

**Common User or Programming Errors:**

* **Crashing with Null Paint Arguments:** The `PaintWithNullPaintArguments` test guards against a scenario where the `paint()` function in the worklet is called with null arguments. This could happen if the underlying plumbing isn't correctly set up.
    * **User Error (Conceptual):**  A bug in the Blink engine's CSS Paint implementation leading to incorrect argument passing.
* **Registering the Same Paint Name Multiple Times with Conflicting Definitions:**  The tests related to global scope consistency highlight the potential issue of registering the same paint function name with different `inputProperties` or other characteristics in different scopes. This could lead to unpredictable behavior if not handled correctly.
    * **User Error (JavaScript):**  Intentionally or unintentionally registering the same paint name multiple times with different logic within the worklet script.
* **Incorrectly Assuming a Singly Registered Definition is Ready:** Developers might mistakenly assume that a paint function is ready to use immediately after the first `registerPaint()` call. The `SinglyRegisteredDocumentDefinitionNotUsed` test demonstrates that this might not be the case.
    * **User Error (JavaScript/CSS):**  Trying to use a paint function in CSS immediately after including the worklet script, without considering potential initialization delays or the need for a second registration.

**User Operations Leading to This Code (Debugging Clues):**

A developer investigating issues with CSS Paint in Chromium might end up looking at this test file to understand how the feature is implemented and tested. Here's a likely sequence of steps:

1. **User Reports a Bug:** A user might report that a custom paint worklet isn't rendering correctly, is causing crashes, or has unexpected behavior.
2. **Developer Investigates:** A Chromium developer would start investigating this bug.
3. **Identifying the Relevant Code:** They would identify that the issue lies within the CSS Paint API implementation in Blink. They would likely navigate to the `blink/renderer/modules/csspaint/` directory.
4. **Looking at Tests:** The developer would then look at the test files, such as `paint_worklet_test.cc`, to understand:
    * **Expected Behavior:** What is the intended behavior of the `PaintWorklet`?
    * **Test Coverage:** Are there existing tests covering the specific scenario they are investigating?
    * **Implementation Details:** The tests often reveal implementation details and assumptions.
5. **Running Specific Tests:** The developer might run specific tests within `paint_worklet_test.cc` that seem relevant to the bug.
6. **Modifying Tests or Adding New Ones:** If an existing test fails or there's no test covering the bug, the developer would modify existing tests or add new tests to reproduce and then fix the issue.
7. **Debugging the Implementation:** Using the failing tests as a starting point, the developer would then debug the actual C++ implementation of `PaintWorklet` and related classes to find the root cause of the bug.

**In summary, `paint_worklet_test.cc` is a crucial component for ensuring the correctness and stability of the CSS Paint API implementation in Chromium. It provides a comprehensive suite of tests that cover various aspects of paint worklet management, registration, and execution, including edge cases and potential error scenarios.**

Prompt: 
```
这是目录为blink/renderer/modules/csspaint/paint_worklet_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/csspaint/paint_worklet.h"

#include <memory>
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_gc_controller.h"
#include "third_party/blink/renderer/bindings/core/v8/worker_or_worklet_script_controller.h"
#include "third_party/blink/renderer/core/css/css_syntax_definition.h"
#include "third_party/blink/renderer/core/css/cssom/prepopulated_computed_style_property_map.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/layout/layout_object.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/script/classic_script.h"
#include "third_party/blink/renderer/core/testing/page_test_base.h"
#include "third_party/blink/renderer/modules/csspaint/css_paint_definition.h"
#include "third_party/blink/renderer/modules/csspaint/paint_worklet_global_scope.h"
#include "third_party/blink/renderer/modules/csspaint/paint_worklet_global_scope_proxy.h"
#include "third_party/blink/renderer/platform/graphics/paint_generated_image.h"
#include "third_party/blink/renderer/platform/testing/runtime_enabled_features_test_helpers.h"

namespace blink {
class TestPaintWorklet : public PaintWorklet {
 public:
  explicit TestPaintWorklet(LocalDOMWindow& window) : PaintWorklet(window) {
    ResetIsPaintOffThreadForTesting();
  }

  void SetPaintsToSwitch(int num) { paints_to_switch_ = num; }

  int GetPaintsBeforeSwitching() override { return paints_to_switch_; }

  // We always switch to another global scope so that we can tell how often it
  // was switched in the test.
  wtf_size_t SelectNewGlobalScope() override {
    return (GetActiveGlobalScopeForTesting() + 1) %
           PaintWorklet::kNumGlobalScopesPerThread;
  }

  size_t GetActiveGlobalScope() { return GetActiveGlobalScopeForTesting(); }

 private:
  int paints_to_switch_;
};

class PaintWorkletTest : public PageTestBase {
 public:
  void SetUp() override {
    PageTestBase::SetUp(gfx::Size());
    test_paint_worklet_ =
        MakeGarbageCollected<TestPaintWorklet>(*GetDocument().domWindow());
    proxy_ = test_paint_worklet_->CreateGlobalScope();
  }

  TestPaintWorklet* GetTestPaintWorklet() { return test_paint_worklet_.Get(); }

  size_t SelectGlobalScope(TestPaintWorklet* paint_worklet) {
    return paint_worklet->SelectGlobalScope();
  }

  PaintWorkletGlobalScopeProxy* GetProxy() {
    return PaintWorkletGlobalScopeProxy::From(proxy_.Get());
  }

  ImageResourceObserver* GetImageResourceObserver() {
    return GetDocument().domWindow()->GetFrame()->ContentLayoutObject();
  }

  // Helper function used in GlobalScopeSelection test.
  void ExpectSwitchGlobalScope(bool expect_switch_within_frame,
                               size_t num_paint_calls,
                               int paint_cnt_to_switch,
                               size_t expected_num_paints_before_switch,
                               TestPaintWorklet* paint_worklet_to_test) {
    paint_worklet_to_test->DomWindow()
        ->GetFrame()
        ->View()
        ->UpdateAllLifecyclePhasesForTest();
    paint_worklet_to_test->SetPaintsToSwitch(paint_cnt_to_switch);
    size_t previously_selected_global_scope =
        paint_worklet_to_test->GetActiveGlobalScope();
    size_t global_scope_switch_count = 0u;

    // How many paint calls are there before we switch to another global scope.
    // Because the first paint call in each frame doesn't count as switching,
    // a result of 0 means there is not switching in that frame.
    size_t num_paints_before_switch = 0u;
    for (size_t j = 0; j < num_paint_calls; j++) {
      size_t selected_global_scope = SelectGlobalScope(paint_worklet_to_test);
      if (j == 0) {
        EXPECT_NE(selected_global_scope, previously_selected_global_scope);
      } else if (selected_global_scope != previously_selected_global_scope) {
        num_paints_before_switch = j + 1;
        global_scope_switch_count++;
      }
      previously_selected_global_scope = selected_global_scope;
    }
    EXPECT_LT(global_scope_switch_count, 2u);
    EXPECT_EQ(num_paints_before_switch, expected_num_paints_before_switch);
  }

  void TearDown() override {
    proxy_->TerminateWorkletGlobalScope();
    proxy_ = nullptr;
    PageTestBase::TearDown();
  }

 private:
  Persistent<WorkletGlobalScopeProxy> proxy_;
  Persistent<TestPaintWorklet> test_paint_worklet_;
};

// This is a crash test for crbug.com/803026. At some point, we shipped the
// CSSPaintAPI without shipping the CSSPaintAPIArguments, the result of it is
// that the |paint_arguments| in the CSSPaintDefinition::Paint() becomes
// nullptr and the renderer crashes. This is a regression test to ensure that
// we will never crash.
TEST_F(PaintWorkletTest, PaintWithNullPaintArguments) {
  PaintWorkletGlobalScope* global_scope = GetProxy()->global_scope();
  ClassicScript::CreateUnspecifiedScript(
      "registerPaint('foo', class { paint() { } });")
      ->RunScriptOnScriptState(
          global_scope->ScriptController()->GetScriptState());

  CSSPaintDefinition* definition = global_scope->FindDefinition("foo");
  ASSERT_TRUE(definition);

  ImageResourceObserver* observer = GetImageResourceObserver();
  ASSERT_TRUE(observer);

  const gfx::SizeF container_size(100, 100);
  const LayoutObject& layout_object =
      static_cast<const LayoutObject&>(*observer);
  float zoom = layout_object.StyleRef().EffectiveZoom();
  StylePropertyMapReadOnly* style_map =
      MakeGarbageCollected<PrepopulatedComputedStylePropertyMap>(
          layout_object.GetDocument(), layout_object.StyleRef(),
          definition->NativeInvalidationProperties(),
          definition->CustomInvalidationProperties());
  scoped_refptr<Image> image = PaintGeneratedImage::Create(
      definition->Paint(container_size, zoom, style_map, nullptr),
      container_size);
  EXPECT_NE(image, nullptr);
}

// In this test, we have only one global scope, which means registerPaint is
// called only once, and hence we have only one document paint definition
// registered. In the real world, this document paint definition should not be
// used to paint until we see a second one being registed with the same name.
TEST_F(PaintWorkletTest, SinglyRegisteredDocumentDefinitionNotUsed) {
  PaintWorklet* paint_worklet_to_test =
      PaintWorklet::From(*GetFrame().GetDocument()->domWindow());
  paint_worklet_to_test->ResetIsPaintOffThreadForTesting();

  PaintWorkletGlobalScope* global_scope = GetProxy()->global_scope();
  ClassicScript::CreateUnspecifiedScript(
      "registerPaint('foo', class { paint() { } });")
      ->RunScriptOnScriptState(
          global_scope->ScriptController()->GetScriptState());

  CSSPaintImageGeneratorImpl* generator =
      static_cast<CSSPaintImageGeneratorImpl*>(
          CSSPaintImageGeneratorImpl::Create("foo", GetDocument(), nullptr));
  EXPECT_TRUE(generator);
  EXPECT_EQ(generator->GetRegisteredDefinitionCountForTesting(), 1u);
  DocumentPaintDefinition* definition;
  // Please refer to CSSPaintImageGeneratorImpl::GetValidDocumentDefinition for
  // the logic.
  if (RuntimeEnabledFeatures::OffMainThreadCSSPaintEnabled()) {
    EXPECT_TRUE(generator->GetValidDocumentDefinitionForTesting(definition));
  } else {
    EXPECT_FALSE(generator->GetValidDocumentDefinitionForTesting(definition));
    EXPECT_FALSE(definition);
  }
}

// In this test, we set a list of "paints_to_switch" numbers, and in each frame,
// we switch to a new global scope when the number of paint calls is >= the
// corresponding number.
TEST_F(PaintWorkletTest, GlobalScopeSelection) {
  TestPaintWorklet* paint_worklet_to_test = GetTestPaintWorklet();

  ExpectSwitchGlobalScope(false, 5, 1, 0, paint_worklet_to_test);
  ExpectSwitchGlobalScope(true, 15, 10, 10, paint_worklet_to_test);
  // In the last one where |paints_to_switch| is 20, there is no switching after
  // the first paint call.
  ExpectSwitchGlobalScope(false, 10, 20, 0, paint_worklet_to_test);
}

TEST_F(PaintWorkletTest, NativeAndCustomProperties) {
  ScopedOffMainThreadCSSPaintForTest off_main_thread_css_paint(true);
  Vector<CSSPropertyID> native_invalidation_properties = {
      CSSPropertyID::kColor,
      CSSPropertyID::kZoom,
      CSSPropertyID::kTop,
  };
  Vector<String> custom_invalidation_properties = {
      "--my-property",
      "--another-property",
  };

  TestPaintWorklet* paint_worklet_to_test = GetTestPaintWorklet();
  paint_worklet_to_test->RegisterMainThreadDocumentPaintDefinition(
      "foo", native_invalidation_properties, custom_invalidation_properties,
      Vector<CSSSyntaxDefinition>(), true);

  CSSPaintImageGeneratorImpl* generator =
      MakeGarbageCollected<CSSPaintImageGeneratorImpl>(paint_worklet_to_test,
                                                       "foo");
  EXPECT_NE(generator, nullptr);
  EXPECT_EQ(generator->NativeInvalidationProperties().size(), 3u);
  EXPECT_EQ(generator->CustomInvalidationProperties().size(), 2u);
  EXPECT_TRUE(generator->HasAlpha());
}

class MainOrOffThreadPaintWorkletTest
    : public PageTestBase,
      public ::testing::WithParamInterface<bool>,
      private ScopedOffMainThreadCSSPaintForTest {
 public:
  MainOrOffThreadPaintWorkletTest()
      : ScopedOffMainThreadCSSPaintForTest(GetParam()) {}
};

INSTANTIATE_TEST_SUITE_P(All,
                         MainOrOffThreadPaintWorkletTest,
                         ::testing::Bool());

class MockObserver final : public CSSPaintImageGenerator::Observer {
 public:
  MOCK_METHOD0(PaintImageGeneratorReady, void());
};

TEST_P(MainOrOffThreadPaintWorkletTest, ConsistentGlobalScopeOnMainThread) {
  PaintWorklet* paint_worklet_to_test =
      PaintWorklet::From(*GetFrame().GetDocument()->domWindow());
  paint_worklet_to_test->ResetIsPaintOffThreadForTesting();

  MockObserver* observer = MakeGarbageCollected<MockObserver>();
  CSSPaintImageGeneratorImpl* generator_foo =
      MakeGarbageCollected<CSSPaintImageGeneratorImpl>(
          observer, paint_worklet_to_test, "foo");
  paint_worklet_to_test->AddPendingGenerator("foo", generator_foo);
  CSSPaintImageGeneratorImpl* generator_bar =
      MakeGarbageCollected<CSSPaintImageGeneratorImpl>(
          observer, paint_worklet_to_test, "bar");
  paint_worklet_to_test->AddPendingGenerator("bar", generator_bar);

  // The generator should not fire unless it is the second registration
  // for the main thread case
  EXPECT_CALL(*observer, PaintImageGeneratorReady).Times(0);

  Vector<Persistent<PaintWorkletGlobalScope>> global_scopes;
  for (wtf_size_t i = 0; i < PaintWorklet::kNumGlobalScopesPerThread; ++i) {
    paint_worklet_to_test->AddGlobalScopeForTesting();
    global_scopes.push_back(
        PaintWorkletGlobalScopeProxy::From(
            paint_worklet_to_test->GetGlobalScopesForTesting()[i])
            ->global_scope());
  }

  String foo0 = R"JS(registerPaint('foo', class {
        static get inputProperties() { return ['--foo0']; }
        paint() {}
      });)JS";
  String foo1 = R"JS(registerPaint('foo', class {
        static get inputProperties() { return ['--foo1']; }
        paint() {}
      });)JS";
  String bar = R"JS(registerPaint('bar', class {
        static get inputProperties() { return ['--bar']; }
        paint() {}
      });)JS";

  ClassicScript::CreateUnspecifiedScript(foo0)->RunScriptOnScriptState(
      global_scopes[0]->ScriptController()->GetScriptState());

  EXPECT_TRUE(global_scopes[0]->FindDefinition("foo"));
  EXPECT_TRUE(paint_worklet_to_test->GetDocumentDefinitionMap().at("foo"));

  ClassicScript::CreateUnspecifiedScript(foo1)->RunScriptOnScriptState(
      global_scopes[1]->ScriptController()->GetScriptState());

  // foo0 and foo1 have the same name but different definitions, therefore
  // this definition must become invalid.
  EXPECT_FALSE(paint_worklet_to_test->GetDocumentDefinitionMap().at("foo"));

  ClassicScript::CreateUnspecifiedScript(bar)->RunScriptOnScriptState(
      global_scopes[0]->ScriptController()->GetScriptState());

  EXPECT_TRUE(global_scopes[0]->FindDefinition("bar"));
  EXPECT_TRUE(paint_worklet_to_test->GetDocumentDefinitionMap().at("bar"));

  // When running in main-thread mode, the generator is now ready after this
  // call. For off-thread, we are still waiting on the cross-thread
  // registration.
  if (!RuntimeEnabledFeatures::OffMainThreadCSSPaintEnabled())
    EXPECT_CALL(*observer, PaintImageGeneratorReady).Times(1);

  ClassicScript::CreateUnspecifiedScript(bar)->RunScriptOnScriptState(
      global_scopes[1]->ScriptController()->GetScriptState());

  EXPECT_TRUE(paint_worklet_to_test->GetDocumentDefinitionMap().at("bar"));
}

// TODO(crbug.com/1430318): All/MainOrOffThreadPaintWorkletTest.
// AllGlobalScopesMustBeCreated/1 is failing on Linux TSan Tests.
#if defined(THREAD_SANITIZER)
#define MAYBE_AllGlobalScopesMustBeCreated DISABLED_AllGlobalScopesMustBeCreated
#else
#define MAYBE_AllGlobalScopesMustBeCreated AllGlobalScopesMustBeCreated
#endif
TEST_P(MainOrOffThreadPaintWorkletTest, MAYBE_AllGlobalScopesMustBeCreated) {
  PaintWorklet* paint_worklet_to_test =
      MakeGarbageCollected<PaintWorklet>(*GetFrame().DomWindow());
  paint_worklet_to_test->ResetIsPaintOffThreadForTesting();

  EXPECT_TRUE(paint_worklet_to_test->GetGlobalScopesForTesting().empty());

  std::unique_ptr<PaintWorkletPaintDispatcher> dispatcher =
      std::make_unique<PaintWorkletPaintDispatcher>();
  Persistent<PaintWorkletProxyClient> proxy_client =
      MakeGarbageCollected<PaintWorkletProxyClient>(
          1, paint_worklet_to_test,
          GetFrame().GetTaskRunner(TaskType::kInternalDefault),
          dispatcher->GetWeakPtr(), nullptr);
  paint_worklet_to_test->SetProxyClientForTesting(proxy_client);

  while (paint_worklet_to_test->NeedsToCreateGlobalScopeForTesting()) {
    paint_worklet_to_test->AddGlobalScopeForTesting();
  }

  if (RuntimeEnabledFeatures::OffMainThreadCSSPaintEnabled()) {
    EXPECT_EQ(paint_worklet_to_test->GetGlobalScopesForTesting().size(),
              2 * PaintWorklet::kNumGlobalScopesPerThread);
  } else {
    EXPECT_EQ(paint_worklet_to_test->GetGlobalScopesForTesting().size(),
              PaintWorklet::kNumGlobalScopesPerThread);
  }
}

TEST_F(PaintWorkletTest, ConsistentGlobalScopeCrossThread) {
  ScopedOffMainThreadCSSPaintForTest off_main_thread_css_paint(true);
  PaintWorklet* paint_worklet_to_test =
      PaintWorklet::From(*GetFrame().GetDocument()->domWindow());
  paint_worklet_to_test->ResetIsPaintOffThreadForTesting();

  MockObserver* observer = MakeGarbageCollected<MockObserver>();
  CSSPaintImageGeneratorImpl* generator_foo =
      MakeGarbageCollected<CSSPaintImageGeneratorImpl>(
          observer, paint_worklet_to_test, "foo");
  paint_worklet_to_test->AddPendingGenerator("foo", generator_foo);
  CSSPaintImageGeneratorImpl* generator_bar =
      MakeGarbageCollected<CSSPaintImageGeneratorImpl>(
          observer, paint_worklet_to_test, "bar");
  paint_worklet_to_test->AddPendingGenerator("bar", generator_bar);
  CSSPaintImageGeneratorImpl* generator_loo =
      MakeGarbageCollected<CSSPaintImageGeneratorImpl>(
          observer, paint_worklet_to_test, "loo");
  paint_worklet_to_test->AddPendingGenerator("loo", generator_loo);
  CSSPaintImageGeneratorImpl* generator_gar =
      MakeGarbageCollected<CSSPaintImageGeneratorImpl>(
          observer, paint_worklet_to_test, "gar");
  paint_worklet_to_test->AddPendingGenerator("gar", generator_gar);

  // None of the situations covered in this test should cause the generator to
  // fire.
  EXPECT_CALL(*observer, PaintImageGeneratorReady).Times(0);

  Vector<Persistent<PaintWorkletGlobalScope>> global_scopes;
  for (wtf_size_t i = 0; i < PaintWorklet::kNumGlobalScopesPerThread; ++i) {
    paint_worklet_to_test->AddGlobalScopeForTesting();
    global_scopes.push_back(
        PaintWorkletGlobalScopeProxy::From(
            paint_worklet_to_test->GetGlobalScopesForTesting()[i])
            ->global_scope());
  }

  String foo0 = R"JS(registerPaint('foo', class {
        static get inputProperties() { return ['--foo0']; }
        paint() {}
      });)JS";
  String foo1 = R"JS(registerPaint('foo', class {
        static get inputProperties() { return ['--foo1']; }
        paint() {}
      });)JS";
  String bar0 = R"JS(registerPaint('bar', class {
        static get inputProperties() { return ['--bar0']; }
        paint() {}
      });)JS";
  String loo0 = R"JS(registerPaint('loo', class {
        static get inputProperties() { return ['--loo0']; }
        paint() {}
      });)JS";
  String loo1 = R"JS(registerPaint('loo', class {
        static get inputProperties() { return ['--loo1']; }
        paint() {}
      });)JS";
  String gar0 = R"JS(registerPaint('gar', class {
        static get inputProperties() { return ['--gar0']; }
        paint() {}
      });)JS";

  // Definition invalidated before cross thread check
  ClassicScript::CreateUnspecifiedScript(foo0)->RunScriptOnScriptState(
      global_scopes[0]->ScriptController()->GetScriptState());

  EXPECT_TRUE(global_scopes[0]->FindDefinition("foo"));
  EXPECT_TRUE(paint_worklet_to_test->GetDocumentDefinitionMap().at("foo"));

  ClassicScript::CreateUnspecifiedScript(foo1)->RunScriptOnScriptState(
      global_scopes[1]->ScriptController()->GetScriptState());

  EXPECT_FALSE(paint_worklet_to_test->GetDocumentDefinitionMap().at("foo"));

  CSSPaintDefinition* definition = global_scopes[0]->FindDefinition("foo");
  Vector<String> foo_custom_properties;
  for (const auto& s : definition->CustomInvalidationProperties()) {
    foo_custom_properties.push_back(s);
  }

  paint_worklet_to_test->RegisterMainThreadDocumentPaintDefinition(
      "foo", definition->NativeInvalidationProperties(), foo_custom_properties,
      definition->InputArgumentTypes(),
      definition->GetPaintRenderingContext2DSettings()->alpha());

  EXPECT_FALSE(paint_worklet_to_test->GetDocumentDefinitionMap().at("foo"));

  // Definition invalidated by cross thread check
  ClassicScript::CreateUnspecifiedScript(bar0)->RunScriptOnScriptState(
      global_scopes[0]->ScriptController()->GetScriptState());

  EXPECT_TRUE(global_scopes[0]->FindDefinition("bar"));
  EXPECT_TRUE(paint_worklet_to_test->GetDocumentDefinitionMap().at("bar"));

  ClassicScript::CreateUnspecifiedScript(bar0)->RunScriptOnScriptState(
      global_scopes[1]->ScriptController()->GetScriptState());

  EXPECT_TRUE(paint_worklet_to_test->GetDocumentDefinitionMap().at("bar"));

  definition = global_scopes[0]->FindDefinition("bar");

  // Manually change the custom properties
  Vector<String> bar_custom_properties({"--bar1"});

  paint_worklet_to_test->RegisterMainThreadDocumentPaintDefinition(
      "bar", definition->NativeInvalidationProperties(), bar_custom_properties,
      definition->InputArgumentTypes(),
      definition->GetPaintRenderingContext2DSettings()->alpha());

  // Although the main thread definitions were the same, the definition sent
  // cross thread differed from the main thread definitions so it must become
  // invalid.
  EXPECT_FALSE(paint_worklet_to_test->GetDocumentDefinitionMap().at("bar"));

  // Definition invalidated by second main thread call after cross thread check
  ClassicScript::CreateUnspecifiedScript(loo0)->RunScriptOnScriptState(
      global_scopes[0]->ScriptController()->GetScriptState());

  EXPECT_TRUE(global_scopes[0]->FindDefinition("loo"));
  EXPECT_TRUE(paint_worklet_to_test->GetDocumentDefinitionMap().at("loo"));

  definition = global_scopes[0]->FindDefinition("loo");
  Vector<String> loo_custom_properties;
  for (const auto& s : definition->CustomInvalidationProperties()) {
    loo_custom_properties.push_back(s);
  }

  paint_worklet_to_test->RegisterMainThreadDocumentPaintDefinition(
      "loo", definition->NativeInvalidationProperties(), loo_custom_properties,
      definition->InputArgumentTypes(),
      definition->GetPaintRenderingContext2DSettings()->alpha());

  EXPECT_TRUE(paint_worklet_to_test->GetDocumentDefinitionMap().at("loo"));

  ClassicScript::CreateUnspecifiedScript(loo1)->RunScriptOnScriptState(
      global_scopes[1]->ScriptController()->GetScriptState());

  // Although the first main thread call and the cross thread definition are the
  // same, the second main thread call differs so the definition must become
  // invalid
  EXPECT_FALSE(paint_worklet_to_test->GetDocumentDefinitionMap().at("loo"));

  // Definition invalidated by cross thread check before second main thread call
  ClassicScript::CreateUnspecifiedScript(gar0)->RunScriptOnScriptState(
      global_scopes[0]->ScriptController()->GetScriptState());

  EXPECT_TRUE(global_scopes[0]->FindDefinition("gar"));
  EXPECT_TRUE(paint_worklet_to_test->GetDocumentDefinitionMap().at("gar"));

  definition = global_scopes[0]->FindDefinition("gar");

  // Manually change custom properties
  Vector<String> gar_custom_properties({"--gar1"});

  paint_worklet_to_test->RegisterMainThreadDocumentPaintDefinition(
      "gar", definition->NativeInvalidationProperties(), gar_custom_properties,
      definition->InputArgumentTypes(),
      definition->GetPaintRenderingContext2DSettings()->alpha());

  EXPECT_FALSE(paint_worklet_to_test->GetDocumentDefinitionMap().at("gar"));

  ClassicScript::CreateUnspecifiedScript(gar0)->RunScriptOnScriptState(
      global_scopes[1]->ScriptController()->GetScriptState());

  // Although the main thread definitions were the same, the definition sent
  // cross thread differed from the main thread definitions so it must stay
  // invalid.
  EXPECT_FALSE(paint_worklet_to_test->GetDocumentDefinitionMap().at("gar"));
}

TEST_F(PaintWorkletTest, GeneratorNotifiedAfterAllRegistrations) {
  ScopedOffMainThreadCSSPaintForTest off_main_thread_css_paint(true);
  PaintWorklet* paint_worklet_to_test =
      PaintWorklet::From(*GetFrame().GetDocument()->domWindow());
  paint_worklet_to_test->ResetIsPaintOffThreadForTesting();

  MockObserver* observer = MakeGarbageCollected<MockObserver>();
  CSSPaintImageGeneratorImpl* generator =
      MakeGarbageCollected<CSSPaintImageGeneratorImpl>(
          observer, paint_worklet_to_test, "foo");
  paint_worklet_to_test->AddPendingGenerator("foo", generator);

  // The generator should not fire until the cross thread check
  EXPECT_CALL(*observer, PaintImageGeneratorReady).Times(0);

  Vector<Persistent<PaintWorkletGlobalScope>> global_scopes;
  for (wtf_size_t i = 0; i < PaintWorklet::kNumGlobalScopesPerThread; ++i) {
    paint_worklet_to_test->AddGlobalScopeForTesting();
    global_scopes.push_back(
        PaintWorkletGlobalScopeProxy::From(
            paint_worklet_to_test->GetGlobalScopesForTesting()[i])
            ->global_scope());
  }

  String foo = R"JS(registerPaint('foo', class {
        static get inputProperties() { return ['--foo']; }
        paint() {}
      });)JS";

  ClassicScript::CreateUnspecifiedScript(foo)->RunScriptOnScriptState(
      global_scopes[0]->ScriptController()->GetScriptState());

  EXPECT_TRUE(global_scopes[0]->FindDefinition("foo"));
  EXPECT_TRUE(paint_worklet_to_test->GetDocumentDefinitionMap().at("foo"));

  ClassicScript::CreateUnspecifiedScript(foo)->RunScriptOnScriptState(
      global_scopes[1]->ScriptController()->GetScriptState());

  EXPECT_TRUE(paint_worklet_to_test->GetDocumentDefinitionMap().at("foo"));

  CSSPaintDefinition* definition = global_scopes[0]->FindDefinition("foo");
  Vector<String> custom_properties;
  for (const auto& s : definition->CustomInvalidationProperties()) {
    custom_properties.push_back(s);
  }

  // The cross thread check should cause the generator to fire
  EXPECT_CALL(*observer, PaintImageGeneratorReady).Times(1);

  paint_worklet_to_test->RegisterMainThreadDocumentPaintDefinition(
      "foo", definition->NativeInvalidationProperties(), custom_properties,
      definition->InputArgumentTypes(),
      definition->GetPaintRenderingContext2DSettings()->alpha());

  EXPECT_TRUE(paint_worklet_to_test->GetDocumentDefinitionMap().at("foo"));
}

}  // namespace blink

"""

```