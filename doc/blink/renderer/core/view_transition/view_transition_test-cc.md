Response:
The user wants to understand the functionality of the `view_transition_test.cc` file in the Chromium Blink engine. I need to analyze the provided code snippet and identify its purpose, its relation to web technologies (JavaScript, HTML, CSS), provide examples of logical reasoning based on input and output, highlight potential user or programming errors, and summarize its core function.

**Plan:**

1. **Identify the main purpose of the file:**  The file name strongly suggests it contains unit tests for the View Transition API.
2. **Analyze imports:** The included headers provide clues about the functionalities being tested (e.g., `ViewTransition`, `DOMViewTransition`, `Document`, `Element`, `CSS`).
3. **Examine the `ViewTransitionTest` class:** This class sets up the testing environment and likely contains individual test cases.
4. **Analyze the test cases:** Each `TEST_P` function represents a specific aspect of the View Transition API being tested. I'll focus on understanding what each test aims to verify.
5. **Relate to web technologies:** Identify how the tests interact with HTML (DOM manipulation), CSS (styling and `view-transition-name`), and JavaScript (using promises and callbacks).
6. **Infer logical reasoning:** For certain tests, I can deduce the expected output based on the input and the behavior of the View Transition API.
7. **Identify potential errors:** Based on the tests, I can infer common mistakes users or developers might make when using the API.
8. **Summarize the file's functionality.**
```
这是目录为blink/renderer/core/view_transition/view_transition_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能,
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/view_transition/view_transition.h"

#include <memory>

#include "base/check_op.h"
#include "base/memory/scoped_refptr.h"
#include "base/task/single_thread_task_runner.h"
#include "base/test/scoped_feature_list.h"
#include "cc/view_transition/view_transition_request.h"
#include "third_party/blink/public/web/web_settings.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_tester.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_testing.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_view_transition_callback.h"
#include "third_party/blink/renderer/core/css/style_change_reason.h"
#include "third_party/blink/renderer/core/css/style_engine.h"
#include "third_party/blink/renderer/core/dom/abort_signal.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/dom_token_list.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/dom/pseudo_element.h"
#include "third_party/blink/renderer/core/frame/frame_test_helpers.h"
#include "third_party/blink/renderer/core/html/html_element.h"
#include "third_party/blink/renderer/core/html/html_head_element.h"
#include "third_party/blink/renderer/core/inspector/inspector_style_resolver.h"
#include "third_party/blink/renderer/core/layout/layout_shift_tracker.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/layout/physical_box_fragment.h"
#include "third_party/blink/renderer/core/navigation_api/navigation_api.h"
#include "third_party/blink/renderer/core/navigation_api/navigation_history_entry.h"
#include "third_party/blink/renderer/core/paint/paint_and_raster_invalidation_test.h"
#include "third_party/blink/renderer/core/paint/paint_layer.h"
#include "third_party/blink/renderer/core/style/computed_style_constants.h"
#include "third_party/blink/renderer/core/testing/core_unit_test_helper.h"
#include "third_party/blink/renderer/core/testing/mock_function_scope.h"
#include "third_party/blink/renderer/core/timing/layout_shift.h"
#include "third_party/blink/renderer/core/view_transition/dom_view_transition.h"
#include "third_party/blink/renderer/core/view_transition/view_transition_supplement.h"
#include "third_party/blink/renderer/core/view_transition/view_transition_utils.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#third_party/blink/renderer/platform/graphics/compositing/paint_artifact_compositor.h"
#include "third_party/blink/renderer/platform/testing/find_cc_layer.h"
#include "third_party/blink/renderer/platform/testing/paint_test_configurations.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"
#include "third_party/blink/renderer/platform/wtf/allocator/allocator.h"
#include "third_party/blink/renderer/platform/wtf/text/atomic_string.h"
#include "v8/include/v8-external.h"
#include "v8/include/v8-function-callback.h"
#include "v8/include/v8-function.h"
#include "v8/include/v8-value.h"

namespace blink {

class ViewTransitionTest : public testing::Test,
                           public PaintTestConfigurations,
                           private ScopedViewTransitionOnNavigationForTest {
 public:
  ViewTransitionTest() : ScopedViewTransitionOnNavigationForTest(true) {}

  void SetUp() override {
    web_view_helper_ = std::make_unique<frame_test_helpers::WebViewHelper>();
    web_view_helper_->Initialize();
    web_view_helper_->Resize(gfx::Size(200, 200));
    GetDocument().GetSettings()->SetPreferCompositingToLCDTextForTesting(true);
  }

  void TearDown() override { web_view_helper_.reset(); }

  ScriptState* GetScriptState() {
    return ToScriptStateForMainWorld(
        web_view_helper_->GetWebView()->MainFrameImpl()->GetFrame());
  }

  Document& GetDocument() {
    return *web_view_helper_->GetWebView()
                ->MainFrameImpl()
                ->GetFrame()
                ->GetDocument();
  }

  bool ElementIsComposited(const char* id) {
    return !CcLayersByDOMElementId(RootCcLayer(), id).empty();
  }

  // Testing the compositor interaction is not in scope for these unittests. So,
  // instead of setting up a full commit flow, simulate it by calling the commit
  // callback directly.
  void UpdateAllLifecyclePhasesAndFinishDirectives() {
    UpdateAllLifecyclePhasesForTest();
    for (auto& callback :
         LayerTreeHost()->TakeViewTransitionCallbacksForTesting()) {
      std::move(callback).Run({});
    }
  }

  cc::LayerTreeHost* LayerTreeHost() {
    return web_view_helper_->LocalMainFrame()
        ->FrameWidgetImpl()
        ->LayerTreeHostForTesting();
  }

  const cc::Layer* RootCcLayer() {
    return paint_artifact_compositor()->RootLayer();
  }

  LocalFrameView* GetLocalFrameView() {
    return web_view_helper_->LocalMainFrame()->GetFrameView();
  }

  LayoutShiftTracker& GetLayoutShiftTracker() {
    return GetLocalFrameView()->GetLayoutShiftTracker();
  }

  PaintArtifactCompositor* paint_artifact_compositor() {
    return GetLocalFrameView()->GetPaintArtifactCompositor();
  }

  void SetHtmlInnerHTML(const String& content) {
    GetDocument().body()->setInnerHTML(content);
    UpdateAllLifecyclePhasesForTest();
  }

  void UpdateAllLifecyclePhasesForTest() {
    web_view_helper_->GetWebView()->MainFrameWidget()->UpdateAllLifecyclePhases(
        DocumentUpdateReason::kTest);
  }

  using State = ViewTransition::State;

  State GetState(DOMViewTransition* transition) const {
    return transition->GetViewTransitionForTest()->state_;
  }

  void FinishTransition() {
    auto* transition = ViewTransitionUtils::GetTransition(GetDocument());
    if (transition)
      transition->SkipTransition();
  }

  bool ShouldCompositeForViewTransition(Element* e) {
    auto* layout_object = e->GetLayoutObject();
    auto* transition = ViewTransitionUtils::GetTransition(GetDocument());
    return layout_object && transition &&
           transition->NeedsViewTransitionEffectNode(*layout_object);
  }

  void ValidatePseudoElementTree(
      const Vector<WTF::AtomicString>& view_transition_names,
      bool has_incoming_image) {
    auto* transition_pseudo = GetDocument().documentElement()->GetPseudoElement(
        kPseudoIdViewTransition);
    ASSERT_TRUE(transition_pseudo);
    EXPECT_TRUE(transition_pseudo->GetComputedStyle());
    EXPECT_TRUE(transition_pseudo->GetLayoutObject());

    PseudoElement* previous_container = nullptr;
    for (const auto& view_transition_name : view_transition_names) {
      SCOPED_TRACE(view_transition_name);
      auto* container_pseudo = transition_pseudo->GetPseudoElement(
          kPseudoIdViewTransitionGroup, view_transition_name);
      ASSERT_TRUE(container_pseudo);
      EXPECT_TRUE(container_pseudo->GetComputedStyle());
      EXPECT_TRUE(container_pseudo->GetLayoutObject());

      if (previous_container) {
        EXPECT_EQ(LayoutTreeBuilderTraversal::NextSibling(*previous_container),
                  container_pseudo);
      }
      previous_container = container_pseudo;

      auto* image_wrapper_pseudo = container_pseudo->GetPseudoElement(
          kPseudoIdViewTransitionImagePair, view_transition_name);

      auto* outgoing_image = image_wrapper_pseudo->GetPseudoElement(
          kPseudoIdViewTransitionOld, view_transition_name);
      ASSERT_TRUE(outgoing_image);
      EXPECT_TRUE(outgoing_image->GetComputedStyle());
      EXPECT_TRUE(outgoing_image->GetLayoutObject());

      auto* incoming_image = image_wrapper_pseudo->GetPseudoElement(
          kPseudoIdViewTransitionNew, view_transition_name);

      if (!has_incoming_image) {
        ASSERT_FALSE(incoming_image);
        continue;
      }

      ASSERT_TRUE(incoming_image);
      EXPECT_TRUE(incoming_image->GetComputedStyle());
      EXPECT_TRUE(incoming_image->GetLayoutObject());
    }
  }

 protected:
  test::TaskEnvironment task_environment;

  std::unique_ptr<frame_test_helpers::WebViewHelper> web_view_helper_;
};

INSTANTIATE_PAINT_TEST_SUITE_P(ViewTransitionTest);

TEST_P(ViewTransitionTest, LayoutShift) {
  SetHtmlInnerHTML(R"HTML(
    <style>
      .shared {
        width: 100px;
        height: 100px;
        view-transition-name: shared;
        contain: layout;
        background: green;
      }
    </style>
    <div id=target class=shared></div>
  )HTML");

  ScriptState* script_state = GetScriptState();
  ScriptState::Scope scope(script_state);

  MockFunctionScope funcs(script_state);
  auto* view_transition_callback = V8ViewTransitionCallback::Create(
      funcs.ExpectCall()->ToV8Function(script_state));

  auto* transition = ViewTransitionSupplement::startViewTransition(
      script_state, GetDocument(), view_transition_callback,
      IGNORE_EXCEPTION_FOR_TESTING);

  ScriptPromiseTester finished_tester(script_state,
                                      transition->finished(script_state));
  EXPECT_EQ(GetState(transition), State::kCaptureTagDiscovery);

  UpdateAllLifecyclePhasesAndFinishDirectives();
  EXPECT_EQ(GetState(transition), State::kDOMCallbackRunning);

  // We should have a start request from the async callback passed to start()
  // resolving.
  test::RunPendingTasks();
  auto start_requests =
      ViewTransitionSupplement::From(GetDocument())->TakePendingRequests();
  EXPECT_FALSE(start_requests.empty());
  EXPECT_EQ(GetState(transition), State::kAnimating);

  // We should have a transition pseudo
  auto* transition_pseudo = GetDocument().documentElement()->GetPseudoElement(
      kPseudoIdViewTransition);
  ASSERT_TRUE(transition_pseudo);
  auto* container_pseudo = transition_pseudo->GetPseudoElement(
      kPseudoIdViewTransitionGroup, AtomicString("shared"));
  ASSERT_TRUE(container_pseudo);
  auto* container_box = To<LayoutBox>(container_pseudo->GetLayoutObject());
  EXPECT_EQ(PhysicalSize(100, 100), container_box->Size());

  // View transition elements should not cause a layout shift.
  auto* target = To<LayoutBox>(
      GetDocument().getElementById(AtomicString("target"))->GetLayoutObject());
  EXPECT_FLOAT_EQ(0, GetLayoutShiftTracker().Score());
  EXPECT_EQ(PhysicalSize(100, 100), target->Size());

  FinishTransition();
  finished_tester.WaitUntilSettled();
}

TEST_P(ViewTransitionTest, TransitionCreatesNewObject) {
  ScriptState* script_state = GetScriptState();
  ScriptState::Scope scope(script_state);

  MockFunctionScope funcs(script_state);
  auto* first_callback = V8ViewTransitionCallback::Create(
      funcs.ExpectCall()->ToV8Function(script_state));
  auto* second_callback = V8ViewTransitionCallback::Create(
      funcs.ExpectCall()->ToV8Function(script_state));

  auto* first_transition = ViewTransitionSupplement::startViewTransition(
      script_state, GetDocument(), first_callback,
      IGNORE_EXCEPTION_FOR_TESTING);
  auto* second_transition = ViewTransitionSupplement::startViewTransition(
      script_state, GetDocument(), second_callback,
      IGNORE_EXCEPTION_FOR_TESTING);

  EXPECT_TRUE(first_transition);
  EXPECT_EQ(GetState(first_transition), State::kAborted);
  EXPECT_TRUE(second_transition);
  EXPECT_NE(first_transition, second_transition);

  test::RunPendingTasks();
  UpdateAllLifecyclePhasesAndFinishDirectives();
}

TEST_P(ViewTransitionTest, TransitionReadyPromiseResolves) {
  ScriptState* script_state = GetScriptState();
  ScriptState::Scope scope(script_state);

  MockFunctionScope funcs(script_state);
  auto* view_transition_callback = V8ViewTransitionCallback::Create(
      funcs.ExpectCall()->ToV8Function(script_state));

  auto* transition = ViewTransitionSupplement::startViewTransition(
      script_state, GetDocument(), view_transition_callback,
      IGNORE_EXCEPTION_FOR_TESTING);

  ScriptPromiseTester promise_tester(script_state,
                                     transition->ready(script_state));

  EXPECT_EQ(GetState(transition), State::kCaptureTagDiscovery);
  UpdateAllLifecyclePhasesAndFinishDirectives();
  EXPECT_EQ(GetState(transition), State::kDOMCallbackRunning);

  test::RunPendingTasks();
  UpdateAllLifecyclePhasesAndFinishDirectives();
  EXPECT_EQ(GetState(transition), State::kAnimating);

  promise_tester.WaitUntilSettled();
  EXPECT_TRUE(promise_tester.IsFulfilled());

  FinishTransition();
}

TEST_P(ViewTransitionTest, PrepareTransitionElementsWantToBeComposited) {
  SetHtmlInnerHTML(R"HTML(
    <style>
      /* TODO(crbug.com/1336462): html.css is parsed before runtime flags are enabled */
      html { view-transition-name: root; }
      div { width: 100px; height: 100px; contain: paint }
      #e1 { view-transition-name: e1; }
      #e3 { view-transition-name: e3; }
    </style>

    <div id=e1></div>
    <div id=e2></div>
    <div id=e3></div>
  )HTML");

  auto* e1 = GetDocument().getElementById(AtomicString("e1"));
  auto* e2 = GetDocument().getElementById(AtomicString("e2"));
  auto* e3 = GetDocument().getElementById(AtomicString("e3"));

  ScriptState* script_state = GetScriptState();
  ScriptState::Scope scope(script_state);

  MockFunctionScope funcs(script_state);
  auto* view_transition_callback = V8ViewTransitionCallback::Create(
      funcs.ExpectCall()->ToV8Function(script_state));

  auto* transition = ViewTransitionSupplement::startViewTransition(
      script_state, GetDocument(), view_transition_callback,
      IGNORE_EXCEPTION_FOR_TESTING);

  EXPECT_EQ(GetState(transition), State::kCaptureTagDiscovery);
  EXPECT_FALSE(ShouldCompositeForViewTransition(e1));
  EXPECT_FALSE(ShouldCompositeForViewTransition(e2));
  EXPECT_FALSE(ShouldCompositeForViewTransition(e3));

  // Update the lifecycle while keeping the transition active.
  UpdateAllLifecyclePhasesForTest();

  EXPECT_EQ(GetState(transition), State::kCapturing);
  EXPECT_TRUE(ShouldCompositeForViewTransition(e1));
  EXPECT_FALSE(ShouldCompositeForViewTransition(e2));
  EXPECT_TRUE(ShouldCompositeForViewTransition(e3));

  EXPECT_TRUE(ElementIsComposited("e1"));
  EXPECT_FALSE(ElementIsComposited("e2"));
  EXPECT_TRUE(ElementIsComposited("e3"));

  UpdateAllLifecyclePhasesAndFinishDirectives();

  EXPECT_FALSE(ShouldCompositeForViewTransition(e1));
  EXPECT_FALSE(ShouldCompositeForViewTransition(e2));
  EXPECT_FALSE(ShouldCompositeForViewTransition(e3));

  // We need to actually run the lifecycle in order to see the full effect of
  // finishing directives.
  UpdateAllLifecyclePhasesForTest();

  EXPECT_FALSE(ElementIsComposited("e1"));
  EXPECT_FALSE(ElementIsComposited("e2"));
  EXPECT_FALSE(ElementIsComposited("e3"));

  FinishTransition();
  test::RunPendingTasks();
}

TEST_P(ViewTransitionTest, StartTransitionElementsWantToBeComposited) {
  SetHtmlInnerHTML(R"HTML(
    <style>
      /* TODO(crbug.com/1336462): html.css is parsed before runtime flags are enabled */
      html { view-transition-name: root; }
      div { contain: paint; width: 100px; height: 100px; background: blue; }
    </style>
    <div id=e1></div>
    <div id=e2></div>
    <div id=e3></div>
  )HTML");

  auto* e1 = GetDocument().getElementById(AtomicString("e1"));
  auto* e2 = GetDocument().getElementById(AtomicString("e2"));
  auto* e3 = GetDocument().getElementById(AtomicString("e3"));

  ScriptState* script_state = GetScriptState();
  ScriptState::Scope scope(script_state);
  DummyExceptionStateForTesting exception_state;

  // Set two of the elements to be shared.
  e1->setAttribute(html_names::kStyleAttr,
                   AtomicString("view-transition-name: e1"));
  e3->setAttribute(html_names::kStyleAttr,
                   AtomicString("view-transition-name: e3"));

  struct Data {
    STACK_ALLOCATED();

   public:
    Data(Document& document,
         ScriptState* script_state,
         ExceptionState& exception_state,
         Element* e1,
         Element* e2)
        : document(document),
          script_state(script_state),
          exception_state(exception_state),
          e1(e1),
          e2(e2) {}

    Document& document;
    ScriptState* script_state;
    ExceptionState& exception_state;
    Element* e1;
    Element* e2;
  };
  Data data(GetDocument(), script_state, exception_state, e1, e2);

  // This callback sets the elements for the start phase of the transition.
  auto start_setup_lambda =
      [](const v8::FunctionCallbackInfo<v8::Value>& info) {
        auto* data =
            static_cast<Data*>(info.Data().As<v8::External>()->Value());
        data->document.getElementById(AtomicString("e1"))
            ->setAttribute(html_names::kStyleAttr, g_empty_atom);
        data->document.getElementById(AtomicString("e3"))
            ->setAttribute(html_names::kStyleAttr, g_empty_atom);
        data->e1->setAttribute(html_names::kStyleAttr,
                               AtomicString("view-transition-name: e1"));
        data->e2->setAttribute(html_names::kStyleAttr,
                               AtomicString("view-transition-name: e2"));
      };
  auto start_setup_callback =
      v8::Function::New(script_state->GetContext(), start_setup_lambda,
                        v8::External::New(script_state->GetIsolate(), &data))
          .ToLocalChecked();

  ViewTransitionSupplement::startViewTransition(
      script_state, GetDocument(),
      V8ViewTransitionCallback::Create(start_setup_callback), exception_state);

  UpdateAllLifecyclePhasesForTest();
  EXPECT_TRUE(ShouldCompositeForViewTransition(e1));
  EXPECT_FALSE(ShouldCompositeForViewTransition(e2));
  EXPECT_TRUE(ShouldCompositeForViewTransition(e3));

  UpdateAllLifecyclePhasesAndFinishDirectives();
  test::RunPendingTasks();

  EXPECT_TRUE(ShouldCompositeForViewTransition(e1));
  EXPECT_TRUE(ShouldCompositeForViewTransition(e2));
  EXPECT_FALSE(ShouldCompositeForViewTransition(e3));

  FinishTransition();
  test::RunPendingTasks();
}

TEST_P(ViewTransitionTest, TransitionCleanedUpBeforePromiseResolution) {
  ScriptState* script_state = GetScriptState();
  ScriptState::Scope scope(script_state);

  MockFunctionScope funcs(script_state);
  auto* view_transition_callback = V8ViewTransitionCallback::Create(
      funcs.ExpectCall()->ToV8Function(script_state));

  auto* transition = ViewTransitionSupplement::startViewTransition(
      script_state, GetDocument(), view_transition_callback,
      IGNORE_EXCEPTION_FOR_TESTING);
  ScriptPromiseTester promise_tester(script_state,
                                     transition->finished(script_state));

  // ActiveScriptWrappable should keep the transition alive.
  ThreadState::Current()->CollectAllGarbageForTesting();

  EXPECT_EQ(GetState(transition), State::kCaptureTagDiscovery);
  UpdateAllLifecyclePhasesAndFinishDirectives();
  EXPECT_EQ(GetState(transition), State::kDOMCallbackRunning);

  test::RunPendingTasks();
  EXPECT_EQ(GetState(transition), State::kAnimating);
  UpdateAllLifecyclePhasesAndFinishDirectives();
  FinishTransition();
  promise_tester.WaitUntilSettled();
  // There is no current way to successfully finish a transition from a
  // unittest. Web tests focus on successful completion tests.
  EXPECT_TRUE(promise_tester.IsFulfilled());
}

TEST_P(ViewTransitionTest, RenderingPausedTest) {
  ScriptState* script_state = GetScriptState();
  ScriptState::Scope scope(script_state);

  MockFunctionScope funcs(script_state);
  auto* view_transition_callback = V8ViewTransitionCallback::Create(
      funcs.ExpectCall()->ToV8Function(script_state));

  auto* transition = ViewTransitionSupplement::startViewTransition(
      script_state, GetDocument(), view_transition_callback,
      IGNORE_EXCEPTION_FOR_TESTING);

  ScriptPromiseTester finished_tester(script_state,
                                      transition->finished(script_state));
  EXPECT_EQ(GetState(transition), State::kCaptureTagDiscovery);

  UpdateAllLifecyclePhasesForTest();
  GetDocument().GetPage()->GetChromeClient().WillCommitCompositorFrame();

  // Visual updates paused during capture phase.
  EXPECT_TRUE(LayerTreeHost()->IsRenderingPaused());

  UpdateAllLifecyclePhasesAndFinishDirectives();
  EXPECT_EQ(GetState(transition), State::kDOMCallbackRunning);

  // Visual updates are stalled between captured and start.
  EXPECT_TRUE(LayerTreeHost()->IsRenderingPaused());

  test::RunPendingTasks();
  EXPECT_EQ(GetState(transition), State::kAnimating);
  UpdateAllLifecyclePhasesAndFinishDirectives();

  // Visual updates are restored on start.
  EXPECT_FALSE(LayerTreeHost()->IsRenderingPaused());

  FinishTransition();
  finished_tester.WaitUntilSettled();
  EXPECT_TRUE(finished_tester.IsFulfilled());
}

TEST_P(ViewTransitionTest, Abandon) {
  ScriptState* script_state = GetScriptState();
  ScriptState::Scope scope(script_state);

  MockFunctionScope funcs(script_state);
  auto* view_transition_callback = V8ViewTransitionCallback::Create(
      funcs.ExpectCall()->ToV8Function(script_state));

  auto* transition = ViewTransitionSupplement::startViewTransition(
      script_state, GetDocument(), view_transition_callback,
      IGNORE_EXCEPTION_FOR_TESTING);
  ScriptPromiseTester finished_tester(script_state,
                                      transition->finished(script_state));
  EXPECT_EQ(GetState(transition), State::kCaptureTagDiscovery);

  transition->skipTransition();
  test::RunPendingTasks();

  finished_tester.WaitUntilSettled();
  EXPECT_TRUE(finished_tester.IsFulfilled());
}

// Checks that the pseudo element tree is correctly build for ::transition*
// pseudo elements.
TEST_P(ViewTransitionTest, ViewTransitionPseudoTree) {
  SetHtmlInnerHTML(R"HTML(
    <style>
      /* TODO(crbug.com/1336462): html.css is parsed before runtime flags are enabled */
      html { view-transition-name: root; }
      div { width: 100px; height: 100px; contain: paint; background: blue }
    </style>

    <div id=e1 style="view-transition-name: e1"></div>
    <div id=e2 style="view-transition-name: e2"></div>
    <div id=e3 style="view-transition-name: e3"></div>
  )HTML");

  ScriptState* script_state = GetScriptState();
  ScriptState::Scope scope(script_state);
  DummyExceptionStateForTesting exception_state;

  struct Data {
    STACK_ALLOCATED();

   public:
    Data(ScriptState* script_state,
         ExceptionState& exception_state,
         Document& document)
        : script_state(script_state),
          exception_state(exception_state),
          document(document) {}

    ScriptState* script_state;
    ExceptionState& exception_state;
    Document& document;
  };
  Data data(script_state, exception_state, GetDocument());

  // This callback sets the elements for the start phase of the transition.
  auto start_setup_lambda =
      [](const v8::FunctionCallbackInfo<v8::Value>& info) {};
  auto start_setup_callback =
      v8::Function::New(script_state->GetContext(), start_setup_lambda,
                        v8::External::New(script_state->GetIsolate(), &data))
          .ToLocalChecked();

  auto* transition = ViewTransitionSupplement::startViewTransition(
      script_state, GetDocument(),
      V8ViewTransitionCallback::Create(start_setup_callback),
      ASSERT_NO_EXCEPTION);

  UpdateAllLifecyclePhasesForTest();

  // The prepare phase should generate the pseudo tree.
  const Vector<AtomicString> view_transition_names = {
      AtomicString("root"), AtomicString("e1"), AtomicString("e2"),
      AtomicString("e3")};
  ValidatePseudoElementTree(view_transition_names, false);

  // Finish the prepare phase, mutate the DOM and start the animation.
  UpdateAllLifecyclePhasesAndFinishDirectives();
  SetHtmlInnerHTML(R"HTML(
    <style>
      /* TODO(crbug.com/1336462): html.css is parsed before runtime flags are enabled */
      html { view-transition-name: root; }
      div { width: 200px; height: 200px; contain: paint }
    </style>

    <div id=e1 style="view-transition-name: e1"></div>
    <div id=e2 style="view-transition-name: e2"></div>
    <div id=e3 style="view-transition-name: e3"></div>
  )HTML");
  test::RunPendingTasks();
  EXPECT_EQ(GetState(transition), State::kAnimating);

  // The start phase should generate pseudo elements for rendering new live
  // content.
  UpdateAllLifecyclePhasesAndFinishDirectives();
  ValidatePseudoElementTree(view_transition_names, true);

  // Finish the animations which should remove the pseudo element tree.
  FinishTransition();
  UpdateAllLifecyclePhasesAndFinishDirectives();
  EXPECT_FALSE(GetDocument().documentElement()->GetPseudoElement(
      kPseudoIdViewTransition));
}

TEST_P(ViewTransitionTest, ViewTransitionElementInvalidation) {
  SetHtmlInnerHTML(R"HTML(
    <style>
      /* TODO(crbug.com/1336462): html.css is parsed before runtime flags are enabled */
      html { view-transition-name: root; }
      div {
        width: 100px;
        height: 100px;
        contain: paint;
        view-transition-name: shared;
      }
    </style>

    <div id=element></div>
  )HTML");

  auto* element = GetDocument().getElementById(AtomicString("element"));

  ScriptState* script_state = GetScriptState();
  ScriptState::Scope scope(script_state);

  auto start_setup_lambda =
      [](const v8::FunctionCallbackInfo<v8::Value>& info) {};

  // This callback sets the elements for the start phase of the transition.
  auto start_setup_callback =
      v8::Function::New(script_state->GetContext(), start_setup_lambda, {})
          .ToLocalChecked();

  auto* transition = ViewTransitionSupplement::startViewTransition(
      script_state, GetDocument(),
      V8ViewTransitionCallback::Create(start_setup_callback),
      ASSERT_NO_EXCEPTION);

  UpdateAllLifecyclePhasesForTest();

  // Finish the prepare phase, mutate the DOM and start the animation.
  UpdateAllLifecyclePhasesAndFinishDirectives();
  test::RunPendingTasks();
  EXPECT_EQ(GetState(transition), State::kAnimating);

  // The start phase should generate pseudo elements for rendering new live
  // content.
  UpdateAllLifecyclePhasesAndFinishDirectives();

  EXPECT_FALSE(element->GetLayoutObject()->NeedsPaintPropertyUpdate());

  // Finish the animations which should remove the pseudo element tree.
  FinishTransition();

  EXPECT_TRUE(element->GetLayoutObject()->NeedsPaintPropertyUpdate());

  UpdateAllLifecyclePhasesAndFinishDirectives();
}

namespace {
void AssertOnlyViewTransitionElementsInvalidated(
    PaintArtifactCompositor* compositor) {
  const char kViewTransition[] = "view-transition";
  const char kLayoutViewTransition[] = "ViewTransition";
  compositor->ForAllContentLayersForTesting(
      [&](ContentLayerClientImpl* client) {
        if (::testing::Matcher<std::string>(
                ::testing::ContainsRegex(kViewTransition))
                .Matches(client->Layer().DebugName())) {
          return;
        }
        if (::testing::Matcher<std::string>(
                ::testing::ContainsRegex(kLayoutViewTransition))
                .Matches(client->Layer().DebugName())) {
          return;
        }
        auto* tracking = client->GetRasterInvalidator().GetTracking();
        EXPECT_FALSE(tracking->HasInvalidations())
            << client->Layer().DebugName();
        for (const auto& invalidation : tracking->Invalidations()) {
          LOG(ERROR) << "Invalidation " << invalidation;
        }
      });
}
}  // namespace

TEST_P(ViewTransitionTest, NoInvalidationOnRoot) {
  SetHtmlInnerHTML(R"HTML(
    <style>
      /* TODO(crbug.com/1336462): html.css is parsed before runtime flags are enabled */
      html { view-transition-name: root; backgrond: grey; }
      #element {
        width: 100px;
        height: 100px;
        view-transition-name: shared;
        will-change: transform;
      
### 提示词
```
这是目录为blink/renderer/core/view_transition/view_transition_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/view_transition/view_transition.h"

#include <memory>

#include "base/check_op.h"
#include "base/memory/scoped_refptr.h"
#include "base/task/single_thread_task_runner.h"
#include "base/test/scoped_feature_list.h"
#include "cc/view_transition/view_transition_request.h"
#include "third_party/blink/public/web/web_settings.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_tester.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_testing.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_view_transition_callback.h"
#include "third_party/blink/renderer/core/css/style_change_reason.h"
#include "third_party/blink/renderer/core/css/style_engine.h"
#include "third_party/blink/renderer/core/dom/abort_signal.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/dom_token_list.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/dom/pseudo_element.h"
#include "third_party/blink/renderer/core/frame/frame_test_helpers.h"
#include "third_party/blink/renderer/core/html/html_element.h"
#include "third_party/blink/renderer/core/html/html_head_element.h"
#include "third_party/blink/renderer/core/inspector/inspector_style_resolver.h"
#include "third_party/blink/renderer/core/layout/layout_shift_tracker.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/layout/physical_box_fragment.h"
#include "third_party/blink/renderer/core/navigation_api/navigation_api.h"
#include "third_party/blink/renderer/core/navigation_api/navigation_history_entry.h"
#include "third_party/blink/renderer/core/paint/paint_and_raster_invalidation_test.h"
#include "third_party/blink/renderer/core/paint/paint_layer.h"
#include "third_party/blink/renderer/core/style/computed_style_constants.h"
#include "third_party/blink/renderer/core/testing/core_unit_test_helper.h"
#include "third_party/blink/renderer/core/testing/mock_function_scope.h"
#include "third_party/blink/renderer/core/timing/layout_shift.h"
#include "third_party/blink/renderer/core/view_transition/dom_view_transition.h"
#include "third_party/blink/renderer/core/view_transition/view_transition_supplement.h"
#include "third_party/blink/renderer/core/view_transition/view_transition_utils.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/graphics/compositing/paint_artifact_compositor.h"
#include "third_party/blink/renderer/platform/testing/find_cc_layer.h"
#include "third_party/blink/renderer/platform/testing/paint_test_configurations.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"
#include "third_party/blink/renderer/platform/wtf/allocator/allocator.h"
#include "third_party/blink/renderer/platform/wtf/text/atomic_string.h"
#include "v8/include/v8-external.h"
#include "v8/include/v8-function-callback.h"
#include "v8/include/v8-function.h"
#include "v8/include/v8-value.h"

namespace blink {

class ViewTransitionTest : public testing::Test,
                           public PaintTestConfigurations,
                           private ScopedViewTransitionOnNavigationForTest {
 public:
  ViewTransitionTest() : ScopedViewTransitionOnNavigationForTest(true) {}

  void SetUp() override {
    web_view_helper_ = std::make_unique<frame_test_helpers::WebViewHelper>();
    web_view_helper_->Initialize();
    web_view_helper_->Resize(gfx::Size(200, 200));
    GetDocument().GetSettings()->SetPreferCompositingToLCDTextForTesting(true);
  }

  void TearDown() override { web_view_helper_.reset(); }

  ScriptState* GetScriptState() {
    return ToScriptStateForMainWorld(
        web_view_helper_->GetWebView()->MainFrameImpl()->GetFrame());
  }

  Document& GetDocument() {
    return *web_view_helper_->GetWebView()
                ->MainFrameImpl()
                ->GetFrame()
                ->GetDocument();
  }

  bool ElementIsComposited(const char* id) {
    return !CcLayersByDOMElementId(RootCcLayer(), id).empty();
  }

  // Testing the compositor interaction is not in scope for these unittests. So,
  // instead of setting up a full commit flow, simulate it by calling the commit
  // callback directly.
  void UpdateAllLifecyclePhasesAndFinishDirectives() {
    UpdateAllLifecyclePhasesForTest();
    for (auto& callback :
         LayerTreeHost()->TakeViewTransitionCallbacksForTesting()) {
      std::move(callback).Run({});
    }
  }

  cc::LayerTreeHost* LayerTreeHost() {
    return web_view_helper_->LocalMainFrame()
        ->FrameWidgetImpl()
        ->LayerTreeHostForTesting();
  }

  const cc::Layer* RootCcLayer() {
    return paint_artifact_compositor()->RootLayer();
  }

  LocalFrameView* GetLocalFrameView() {
    return web_view_helper_->LocalMainFrame()->GetFrameView();
  }

  LayoutShiftTracker& GetLayoutShiftTracker() {
    return GetLocalFrameView()->GetLayoutShiftTracker();
  }

  PaintArtifactCompositor* paint_artifact_compositor() {
    return GetLocalFrameView()->GetPaintArtifactCompositor();
  }

  void SetHtmlInnerHTML(const String& content) {
    GetDocument().body()->setInnerHTML(content);
    UpdateAllLifecyclePhasesForTest();
  }

  void UpdateAllLifecyclePhasesForTest() {
    web_view_helper_->GetWebView()->MainFrameWidget()->UpdateAllLifecyclePhases(
        DocumentUpdateReason::kTest);
  }

  using State = ViewTransition::State;

  State GetState(DOMViewTransition* transition) const {
    return transition->GetViewTransitionForTest()->state_;
  }

  void FinishTransition() {
    auto* transition = ViewTransitionUtils::GetTransition(GetDocument());
    if (transition)
      transition->SkipTransition();
  }

  bool ShouldCompositeForViewTransition(Element* e) {
    auto* layout_object = e->GetLayoutObject();
    auto* transition = ViewTransitionUtils::GetTransition(GetDocument());
    return layout_object && transition &&
           transition->NeedsViewTransitionEffectNode(*layout_object);
  }

  void ValidatePseudoElementTree(
      const Vector<WTF::AtomicString>& view_transition_names,
      bool has_incoming_image) {
    auto* transition_pseudo = GetDocument().documentElement()->GetPseudoElement(
        kPseudoIdViewTransition);
    ASSERT_TRUE(transition_pseudo);
    EXPECT_TRUE(transition_pseudo->GetComputedStyle());
    EXPECT_TRUE(transition_pseudo->GetLayoutObject());

    PseudoElement* previous_container = nullptr;
    for (const auto& view_transition_name : view_transition_names) {
      SCOPED_TRACE(view_transition_name);
      auto* container_pseudo = transition_pseudo->GetPseudoElement(
          kPseudoIdViewTransitionGroup, view_transition_name);
      ASSERT_TRUE(container_pseudo);
      EXPECT_TRUE(container_pseudo->GetComputedStyle());
      EXPECT_TRUE(container_pseudo->GetLayoutObject());

      if (previous_container) {
        EXPECT_EQ(LayoutTreeBuilderTraversal::NextSibling(*previous_container),
                  container_pseudo);
      }
      previous_container = container_pseudo;

      auto* image_wrapper_pseudo = container_pseudo->GetPseudoElement(
          kPseudoIdViewTransitionImagePair, view_transition_name);

      auto* outgoing_image = image_wrapper_pseudo->GetPseudoElement(
          kPseudoIdViewTransitionOld, view_transition_name);
      ASSERT_TRUE(outgoing_image);
      EXPECT_TRUE(outgoing_image->GetComputedStyle());
      EXPECT_TRUE(outgoing_image->GetLayoutObject());

      auto* incoming_image = image_wrapper_pseudo->GetPseudoElement(
          kPseudoIdViewTransitionNew, view_transition_name);

      if (!has_incoming_image) {
        ASSERT_FALSE(incoming_image);
        continue;
      }

      ASSERT_TRUE(incoming_image);
      EXPECT_TRUE(incoming_image->GetComputedStyle());
      EXPECT_TRUE(incoming_image->GetLayoutObject());
    }
  }

 protected:
  test::TaskEnvironment task_environment;

  std::unique_ptr<frame_test_helpers::WebViewHelper> web_view_helper_;
};

INSTANTIATE_PAINT_TEST_SUITE_P(ViewTransitionTest);

TEST_P(ViewTransitionTest, LayoutShift) {
  SetHtmlInnerHTML(R"HTML(
    <style>
      .shared {
        width: 100px;
        height: 100px;
        view-transition-name: shared;
        contain: layout;
        background: green;
      }
    </style>
    <div id=target class=shared></div>
  )HTML");

  ScriptState* script_state = GetScriptState();
  ScriptState::Scope scope(script_state);

  MockFunctionScope funcs(script_state);
  auto* view_transition_callback = V8ViewTransitionCallback::Create(
      funcs.ExpectCall()->ToV8Function(script_state));

  auto* transition = ViewTransitionSupplement::startViewTransition(
      script_state, GetDocument(), view_transition_callback,
      IGNORE_EXCEPTION_FOR_TESTING);

  ScriptPromiseTester finished_tester(script_state,
                                      transition->finished(script_state));
  EXPECT_EQ(GetState(transition), State::kCaptureTagDiscovery);

  UpdateAllLifecyclePhasesAndFinishDirectives();
  EXPECT_EQ(GetState(transition), State::kDOMCallbackRunning);

  // We should have a start request from the async callback passed to start()
  // resolving.
  test::RunPendingTasks();
  auto start_requests =
      ViewTransitionSupplement::From(GetDocument())->TakePendingRequests();
  EXPECT_FALSE(start_requests.empty());
  EXPECT_EQ(GetState(transition), State::kAnimating);

  // We should have a transition pseudo
  auto* transition_pseudo = GetDocument().documentElement()->GetPseudoElement(
      kPseudoIdViewTransition);
  ASSERT_TRUE(transition_pseudo);
  auto* container_pseudo = transition_pseudo->GetPseudoElement(
      kPseudoIdViewTransitionGroup, AtomicString("shared"));
  ASSERT_TRUE(container_pseudo);
  auto* container_box = To<LayoutBox>(container_pseudo->GetLayoutObject());
  EXPECT_EQ(PhysicalSize(100, 100), container_box->Size());

  // View transition elements should not cause a layout shift.
  auto* target = To<LayoutBox>(
      GetDocument().getElementById(AtomicString("target"))->GetLayoutObject());
  EXPECT_FLOAT_EQ(0, GetLayoutShiftTracker().Score());
  EXPECT_EQ(PhysicalSize(100, 100), target->Size());

  FinishTransition();
  finished_tester.WaitUntilSettled();
}

TEST_P(ViewTransitionTest, TransitionCreatesNewObject) {
  ScriptState* script_state = GetScriptState();
  ScriptState::Scope scope(script_state);

  MockFunctionScope funcs(script_state);
  auto* first_callback = V8ViewTransitionCallback::Create(
      funcs.ExpectCall()->ToV8Function(script_state));
  auto* second_callback = V8ViewTransitionCallback::Create(
      funcs.ExpectCall()->ToV8Function(script_state));

  auto* first_transition = ViewTransitionSupplement::startViewTransition(
      script_state, GetDocument(), first_callback,
      IGNORE_EXCEPTION_FOR_TESTING);
  auto* second_transition = ViewTransitionSupplement::startViewTransition(
      script_state, GetDocument(), second_callback,
      IGNORE_EXCEPTION_FOR_TESTING);

  EXPECT_TRUE(first_transition);
  EXPECT_EQ(GetState(first_transition), State::kAborted);
  EXPECT_TRUE(second_transition);
  EXPECT_NE(first_transition, second_transition);

  test::RunPendingTasks();
  UpdateAllLifecyclePhasesAndFinishDirectives();
}

TEST_P(ViewTransitionTest, TransitionReadyPromiseResolves) {
  ScriptState* script_state = GetScriptState();
  ScriptState::Scope scope(script_state);

  MockFunctionScope funcs(script_state);
  auto* view_transition_callback = V8ViewTransitionCallback::Create(
      funcs.ExpectCall()->ToV8Function(script_state));

  auto* transition = ViewTransitionSupplement::startViewTransition(
      script_state, GetDocument(), view_transition_callback,
      IGNORE_EXCEPTION_FOR_TESTING);

  ScriptPromiseTester promise_tester(script_state,
                                     transition->ready(script_state));

  EXPECT_EQ(GetState(transition), State::kCaptureTagDiscovery);
  UpdateAllLifecyclePhasesAndFinishDirectives();
  EXPECT_EQ(GetState(transition), State::kDOMCallbackRunning);

  test::RunPendingTasks();
  UpdateAllLifecyclePhasesAndFinishDirectives();
  EXPECT_EQ(GetState(transition), State::kAnimating);

  promise_tester.WaitUntilSettled();
  EXPECT_TRUE(promise_tester.IsFulfilled());

  FinishTransition();
}

TEST_P(ViewTransitionTest, PrepareTransitionElementsWantToBeComposited) {
  SetHtmlInnerHTML(R"HTML(
    <style>
      /* TODO(crbug.com/1336462): html.css is parsed before runtime flags are enabled */
      html { view-transition-name: root; }
      div { width: 100px; height: 100px; contain: paint }
      #e1 { view-transition-name: e1; }
      #e3 { view-transition-name: e3; }
    </style>

    <div id=e1></div>
    <div id=e2></div>
    <div id=e3></div>
  )HTML");

  auto* e1 = GetDocument().getElementById(AtomicString("e1"));
  auto* e2 = GetDocument().getElementById(AtomicString("e2"));
  auto* e3 = GetDocument().getElementById(AtomicString("e3"));

  ScriptState* script_state = GetScriptState();
  ScriptState::Scope scope(script_state);

  MockFunctionScope funcs(script_state);
  auto* view_transition_callback = V8ViewTransitionCallback::Create(
      funcs.ExpectCall()->ToV8Function(script_state));

  auto* transition = ViewTransitionSupplement::startViewTransition(
      script_state, GetDocument(), view_transition_callback,
      IGNORE_EXCEPTION_FOR_TESTING);

  EXPECT_EQ(GetState(transition), State::kCaptureTagDiscovery);
  EXPECT_FALSE(ShouldCompositeForViewTransition(e1));
  EXPECT_FALSE(ShouldCompositeForViewTransition(e2));
  EXPECT_FALSE(ShouldCompositeForViewTransition(e3));

  // Update the lifecycle while keeping the transition active.
  UpdateAllLifecyclePhasesForTest();

  EXPECT_EQ(GetState(transition), State::kCapturing);
  EXPECT_TRUE(ShouldCompositeForViewTransition(e1));
  EXPECT_FALSE(ShouldCompositeForViewTransition(e2));
  EXPECT_TRUE(ShouldCompositeForViewTransition(e3));

  EXPECT_TRUE(ElementIsComposited("e1"));
  EXPECT_FALSE(ElementIsComposited("e2"));
  EXPECT_TRUE(ElementIsComposited("e3"));

  UpdateAllLifecyclePhasesAndFinishDirectives();

  EXPECT_FALSE(ShouldCompositeForViewTransition(e1));
  EXPECT_FALSE(ShouldCompositeForViewTransition(e2));
  EXPECT_FALSE(ShouldCompositeForViewTransition(e3));

  // We need to actually run the lifecycle in order to see the full effect of
  // finishing directives.
  UpdateAllLifecyclePhasesForTest();

  EXPECT_FALSE(ElementIsComposited("e1"));
  EXPECT_FALSE(ElementIsComposited("e2"));
  EXPECT_FALSE(ElementIsComposited("e3"));

  FinishTransition();
  test::RunPendingTasks();
}

TEST_P(ViewTransitionTest, StartTransitionElementsWantToBeComposited) {
  SetHtmlInnerHTML(R"HTML(
    <style>
      /* TODO(crbug.com/1336462): html.css is parsed before runtime flags are enabled */
      html { view-transition-name: root; }
      div { contain: paint; width: 100px; height: 100px; background: blue; }
    </style>
    <div id=e1></div>
    <div id=e2></div>
    <div id=e3></div>
  )HTML");

  auto* e1 = GetDocument().getElementById(AtomicString("e1"));
  auto* e2 = GetDocument().getElementById(AtomicString("e2"));
  auto* e3 = GetDocument().getElementById(AtomicString("e3"));

  ScriptState* script_state = GetScriptState();
  ScriptState::Scope scope(script_state);
  DummyExceptionStateForTesting exception_state;

  // Set two of the elements to be shared.
  e1->setAttribute(html_names::kStyleAttr,
                   AtomicString("view-transition-name: e1"));
  e3->setAttribute(html_names::kStyleAttr,
                   AtomicString("view-transition-name: e3"));

  struct Data {
    STACK_ALLOCATED();

   public:
    Data(Document& document,
         ScriptState* script_state,
         ExceptionState& exception_state,
         Element* e1,
         Element* e2)
        : document(document),
          script_state(script_state),
          exception_state(exception_state),
          e1(e1),
          e2(e2) {}

    Document& document;
    ScriptState* script_state;
    ExceptionState& exception_state;
    Element* e1;
    Element* e2;
  };
  Data data(GetDocument(), script_state, exception_state, e1, e2);

  // This callback sets the elements for the start phase of the transition.
  auto start_setup_lambda =
      [](const v8::FunctionCallbackInfo<v8::Value>& info) {
        auto* data =
            static_cast<Data*>(info.Data().As<v8::External>()->Value());
        data->document.getElementById(AtomicString("e1"))
            ->setAttribute(html_names::kStyleAttr, g_empty_atom);
        data->document.getElementById(AtomicString("e3"))
            ->setAttribute(html_names::kStyleAttr, g_empty_atom);
        data->e1->setAttribute(html_names::kStyleAttr,
                               AtomicString("view-transition-name: e1"));
        data->e2->setAttribute(html_names::kStyleAttr,
                               AtomicString("view-transition-name: e2"));
      };
  auto start_setup_callback =
      v8::Function::New(script_state->GetContext(), start_setup_lambda,
                        v8::External::New(script_state->GetIsolate(), &data))
          .ToLocalChecked();

  ViewTransitionSupplement::startViewTransition(
      script_state, GetDocument(),
      V8ViewTransitionCallback::Create(start_setup_callback), exception_state);

  UpdateAllLifecyclePhasesForTest();
  EXPECT_TRUE(ShouldCompositeForViewTransition(e1));
  EXPECT_FALSE(ShouldCompositeForViewTransition(e2));
  EXPECT_TRUE(ShouldCompositeForViewTransition(e3));

  UpdateAllLifecyclePhasesAndFinishDirectives();
  test::RunPendingTasks();

  EXPECT_TRUE(ShouldCompositeForViewTransition(e1));
  EXPECT_TRUE(ShouldCompositeForViewTransition(e2));
  EXPECT_FALSE(ShouldCompositeForViewTransition(e3));

  FinishTransition();
  test::RunPendingTasks();
}

TEST_P(ViewTransitionTest, TransitionCleanedUpBeforePromiseResolution) {
  ScriptState* script_state = GetScriptState();
  ScriptState::Scope scope(script_state);

  MockFunctionScope funcs(script_state);
  auto* view_transition_callback = V8ViewTransitionCallback::Create(
      funcs.ExpectCall()->ToV8Function(script_state));

  auto* transition = ViewTransitionSupplement::startViewTransition(
      script_state, GetDocument(), view_transition_callback,
      IGNORE_EXCEPTION_FOR_TESTING);
  ScriptPromiseTester promise_tester(script_state,
                                     transition->finished(script_state));

  // ActiveScriptWrappable should keep the transition alive.
  ThreadState::Current()->CollectAllGarbageForTesting();

  EXPECT_EQ(GetState(transition), State::kCaptureTagDiscovery);
  UpdateAllLifecyclePhasesAndFinishDirectives();
  EXPECT_EQ(GetState(transition), State::kDOMCallbackRunning);

  test::RunPendingTasks();
  EXPECT_EQ(GetState(transition), State::kAnimating);
  UpdateAllLifecyclePhasesAndFinishDirectives();
  FinishTransition();
  promise_tester.WaitUntilSettled();
  // There is no current way to successfully finish a transition from a
  // unittest. Web tests focus on successful completion tests.
  EXPECT_TRUE(promise_tester.IsFulfilled());
}

TEST_P(ViewTransitionTest, RenderingPausedTest) {
  ScriptState* script_state = GetScriptState();
  ScriptState::Scope scope(script_state);

  MockFunctionScope funcs(script_state);
  auto* view_transition_callback = V8ViewTransitionCallback::Create(
      funcs.ExpectCall()->ToV8Function(script_state));

  auto* transition = ViewTransitionSupplement::startViewTransition(
      script_state, GetDocument(), view_transition_callback,
      IGNORE_EXCEPTION_FOR_TESTING);

  ScriptPromiseTester finished_tester(script_state,
                                      transition->finished(script_state));
  EXPECT_EQ(GetState(transition), State::kCaptureTagDiscovery);

  UpdateAllLifecyclePhasesForTest();
  GetDocument().GetPage()->GetChromeClient().WillCommitCompositorFrame();

  // Visual updates paused during capture phase.
  EXPECT_TRUE(LayerTreeHost()->IsRenderingPaused());

  UpdateAllLifecyclePhasesAndFinishDirectives();
  EXPECT_EQ(GetState(transition), State::kDOMCallbackRunning);

  // Visual updates are stalled between captured and start.
  EXPECT_TRUE(LayerTreeHost()->IsRenderingPaused());

  test::RunPendingTasks();
  EXPECT_EQ(GetState(transition), State::kAnimating);
  UpdateAllLifecyclePhasesAndFinishDirectives();

  // Visual updates are restored on start.
  EXPECT_FALSE(LayerTreeHost()->IsRenderingPaused());

  FinishTransition();
  finished_tester.WaitUntilSettled();
  EXPECT_TRUE(finished_tester.IsFulfilled());
}

TEST_P(ViewTransitionTest, Abandon) {
  ScriptState* script_state = GetScriptState();
  ScriptState::Scope scope(script_state);

  MockFunctionScope funcs(script_state);
  auto* view_transition_callback = V8ViewTransitionCallback::Create(
      funcs.ExpectCall()->ToV8Function(script_state));

  auto* transition = ViewTransitionSupplement::startViewTransition(
      script_state, GetDocument(), view_transition_callback,
      IGNORE_EXCEPTION_FOR_TESTING);
  ScriptPromiseTester finished_tester(script_state,
                                      transition->finished(script_state));
  EXPECT_EQ(GetState(transition), State::kCaptureTagDiscovery);

  transition->skipTransition();
  test::RunPendingTasks();

  finished_tester.WaitUntilSettled();
  EXPECT_TRUE(finished_tester.IsFulfilled());
}

// Checks that the pseudo element tree is correctly build for ::transition*
// pseudo elements.
TEST_P(ViewTransitionTest, ViewTransitionPseudoTree) {
  SetHtmlInnerHTML(R"HTML(
    <style>
      /* TODO(crbug.com/1336462): html.css is parsed before runtime flags are enabled */
      html { view-transition-name: root; }
      div { width: 100px; height: 100px; contain: paint; background: blue }
    </style>

    <div id=e1 style="view-transition-name: e1"></div>
    <div id=e2 style="view-transition-name: e2"></div>
    <div id=e3 style="view-transition-name: e3"></div>
  )HTML");

  ScriptState* script_state = GetScriptState();
  ScriptState::Scope scope(script_state);
  DummyExceptionStateForTesting exception_state;

  struct Data {
    STACK_ALLOCATED();

   public:
    Data(ScriptState* script_state,
         ExceptionState& exception_state,
         Document& document)
        : script_state(script_state),
          exception_state(exception_state),
          document(document) {}

    ScriptState* script_state;
    ExceptionState& exception_state;
    Document& document;
  };
  Data data(script_state, exception_state, GetDocument());

  // This callback sets the elements for the start phase of the transition.
  auto start_setup_lambda =
      [](const v8::FunctionCallbackInfo<v8::Value>& info) {};
  auto start_setup_callback =
      v8::Function::New(script_state->GetContext(), start_setup_lambda,
                        v8::External::New(script_state->GetIsolate(), &data))
          .ToLocalChecked();

  auto* transition = ViewTransitionSupplement::startViewTransition(
      script_state, GetDocument(),
      V8ViewTransitionCallback::Create(start_setup_callback),
      ASSERT_NO_EXCEPTION);

  UpdateAllLifecyclePhasesForTest();

  // The prepare phase should generate the pseudo tree.
  const Vector<AtomicString> view_transition_names = {
      AtomicString("root"), AtomicString("e1"), AtomicString("e2"),
      AtomicString("e3")};
  ValidatePseudoElementTree(view_transition_names, false);

  // Finish the prepare phase, mutate the DOM and start the animation.
  UpdateAllLifecyclePhasesAndFinishDirectives();
  SetHtmlInnerHTML(R"HTML(
    <style>
      /* TODO(crbug.com/1336462): html.css is parsed before runtime flags are enabled */
      html { view-transition-name: root; }
      div { width: 200px; height: 200px; contain: paint }
    </style>

    <div id=e1 style="view-transition-name: e1"></div>
    <div id=e2 style="view-transition-name: e2"></div>
    <div id=e3 style="view-transition-name: e3"></div>
  )HTML");
  test::RunPendingTasks();
  EXPECT_EQ(GetState(transition), State::kAnimating);

  // The start phase should generate pseudo elements for rendering new live
  // content.
  UpdateAllLifecyclePhasesAndFinishDirectives();
  ValidatePseudoElementTree(view_transition_names, true);

  // Finish the animations which should remove the pseudo element tree.
  FinishTransition();
  UpdateAllLifecyclePhasesAndFinishDirectives();
  EXPECT_FALSE(GetDocument().documentElement()->GetPseudoElement(
      kPseudoIdViewTransition));
}

TEST_P(ViewTransitionTest, ViewTransitionElementInvalidation) {
  SetHtmlInnerHTML(R"HTML(
    <style>
      /* TODO(crbug.com/1336462): html.css is parsed before runtime flags are enabled */
      html { view-transition-name: root; }
      div {
        width: 100px;
        height: 100px;
        contain: paint;
        view-transition-name: shared;
      }
    </style>

    <div id=element></div>
  )HTML");

  auto* element = GetDocument().getElementById(AtomicString("element"));

  ScriptState* script_state = GetScriptState();
  ScriptState::Scope scope(script_state);

  auto start_setup_lambda =
      [](const v8::FunctionCallbackInfo<v8::Value>& info) {};

  // This callback sets the elements for the start phase of the transition.
  auto start_setup_callback =
      v8::Function::New(script_state->GetContext(), start_setup_lambda, {})
          .ToLocalChecked();

  auto* transition = ViewTransitionSupplement::startViewTransition(
      script_state, GetDocument(),
      V8ViewTransitionCallback::Create(start_setup_callback),
      ASSERT_NO_EXCEPTION);

  UpdateAllLifecyclePhasesForTest();

  // Finish the prepare phase, mutate the DOM and start the animation.
  UpdateAllLifecyclePhasesAndFinishDirectives();
  test::RunPendingTasks();
  EXPECT_EQ(GetState(transition), State::kAnimating);

  // The start phase should generate pseudo elements for rendering new live
  // content.
  UpdateAllLifecyclePhasesAndFinishDirectives();

  EXPECT_FALSE(element->GetLayoutObject()->NeedsPaintPropertyUpdate());

  // Finish the animations which should remove the pseudo element tree.
  FinishTransition();

  EXPECT_TRUE(element->GetLayoutObject()->NeedsPaintPropertyUpdate());

  UpdateAllLifecyclePhasesAndFinishDirectives();
}

namespace {
void AssertOnlyViewTransitionElementsInvalidated(
    PaintArtifactCompositor* compositor) {
  const char kViewTransition[] = "view-transition";
  const char kLayoutViewTransition[] = "ViewTransition";
  compositor->ForAllContentLayersForTesting(
      [&](ContentLayerClientImpl* client) {
        if (::testing::Matcher<std::string>(
                ::testing::ContainsRegex(kViewTransition))
                .Matches(client->Layer().DebugName())) {
          return;
        }
        if (::testing::Matcher<std::string>(
                ::testing::ContainsRegex(kLayoutViewTransition))
                .Matches(client->Layer().DebugName())) {
          return;
        }
        auto* tracking = client->GetRasterInvalidator().GetTracking();
        EXPECT_FALSE(tracking->HasInvalidations())
            << client->Layer().DebugName();
        for (const auto& invalidation : tracking->Invalidations()) {
          LOG(ERROR) << "Invalidation " << invalidation;
        }
      });
}
}  // namespace

TEST_P(ViewTransitionTest, NoInvalidationOnRoot) {
  SetHtmlInnerHTML(R"HTML(
    <style>
      /* TODO(crbug.com/1336462): html.css is parsed before runtime flags are enabled */
      html { view-transition-name: root; backgrond: grey; }
      #element {
        width: 100px;
        height: 100px;
        view-transition-name: shared;
        will-change: transform;
      }
    </style>

    <div id=element></div>
    <div>test</div>
  )HTML");

  // Run all lifecycle phases to ensure paint is clean.
  UpdateAllLifecyclePhasesForTest();

  GetDocument().View()->SetTracksRasterInvalidations(true);

  ScriptState* script_state = GetScriptState();
  ScriptState::Scope scope(script_state);

  auto start_setup_lambda =
      [](const v8::FunctionCallbackInfo<v8::Value>& info) {};

  // This callback sets the elements for the start phase of the transition.
  auto start_setup_callback =
      v8::Function::New(script_state->GetContext(), start_setup_lambda, {})
          .ToLocalChecked();

  auto* compositor = GetLocalFrameView()->GetPaintArtifactCompositor();
  auto* transition = ViewTransitionSupplement::startViewTransition(
      script_state, GetDocument(),
      V8ViewTransitionCallback::Create(start_setup_callback),
      ASSERT_NO_EXCEPTION);

  UpdateAllLifecyclePhasesForTest();
  {
    SCOPED_TRACE("old dom capture");
    AssertOnlyViewTransitionElementsInvalidated(compositor);
  }

  // Finish the prepare phase, mutate the DOM and start the animation.
  UpdateAllLifecyclePhasesAndFinishDirectives();
  test::RunPendingTasks();
  EXPECT_EQ(GetState(transition), State::kAnimating);

  // The start phase should generate pseudo elements for rendering new live
  // content.
  UpdateAllLifecyclePhasesAndFinishDirectives();
  {
    SCOPED_TRACE("animation started");
    AssertOnlyViewTransitionElementsInvalidated(compositor);
  }

  // Finish the animations which should remove the pseudo element tree.
  FinishTransition();
  UpdateAllLifecyclePhasesAndFinishDirectives();
  {
    SCOPED_TRACE("transition finished");
    AssertOnlyViewTransitionElementsInvalidated(compositor);
  }
}

TEST_P(ViewTransitionTest, InspectorStyleResolver) {
  SetHtmlInnerHTML(R"HTML(
    <style>
      /* TODO(crbug.com/1336462): html.css is parsed before runtime flags are enabled */
      html { view-transition-name: root; }
      ::view-transition {
        background-color: red;
      }
      ::view-transition-group(foo) {
        background-color: blue;
      }
      ::view-transition-image-pair(foo) {
        background-color: lightblue;
      }
      ::view-transition-new(foo) {
        background-color: black;
      }
      ::view-transition-old(foo) {
        background-color: grey;
      }
      div {
        view-transition-name: foo;
        width: 100px;
        height: 100px;
        contain: paint;
      }
    </style>
    <div></div>
  )HTML");

  ScriptState* script_state = GetScriptState();
  ScriptState::Scope scope(script_state);

  auto start_setup_lambda =
      [](const v8::FunctionCallbackInfo<v8::Value>& info) {};

  // This callback sets the elements for the start phase of the transition.
  auto start_setup_callback =
      v8::Function::New(script_state->GetContext(), start_setup_lambda, {})
          .ToLocalChecked();

  auto* transition = ViewTransitionSupplement::startViewTransition(
      script_state, GetDocument(),
      V8ViewTransitionCallback::Create(start_setup_callback),
      ASSERT_NO_EXCEPTION);

  UpdateAllLifecyclePhasesForTest();

  // Finish the prepare phase, mutate the DOM and start the animation.
  UpdateAllLifecyclePhasesAndFinishDirectives();
  test::RunPendingTasks();
  EXPECT_EQ(GetState(transition), State::kAnimating);

  struct TestCase {
    PseudoId pseudo_id;
    bool uses_tags;
    String user_rule;
  };
  TestCase test_cases[] = {
      {kPseudoIdViewTransition, false,
       "::view-transition { background-color: red; }"},
      {kPseudoIdViewTransitionGroup, true,
       "::view-transition-group(foo) { background-color: blue; }"},
      {kPseudoIdViewTransitionImagePair, true,
       "::view-transition-image-pair(foo) { background-color: lightblue; }"},
      {kPseudoIdViewTransitionNew, true,
       "::view-transition-new(foo) { background-color: black; }"},
      {kPseudoIdViewTransitionOld, true,
       "::view-transition-old(foo) { background-color: grey; }"}};

  for (const auto& test_case : test_cases) {
    InspectorStyleResolver resolver(
        GetDocument().documentElement(), test_case.pseudo_id,
        test_case.uses_tags ? AtomicString("foo") : g_null_atom);
    auto* pseudo_element_rules = resolver.MatchedRules();

    // The resolver collects developer and UA rules.
    EXPECT_GT(pseudo_element_rules->size(), 1u);
    EXPECT_EQ(pseudo_element_rules->back().first->cssText(),
              test_case.user_rule);
  }

  InspectorStyleResolver parent_resolver(GetDocument().documentElement(),
                                         kPseudoIdNone, g_null_atom);
  for (const auto& test_case : test_cases) {
    SCOPED_TRACE(PseudoElementTagName(test_case.pseudo_id));
    Member<InspectorCSSMatchedRules> matched_rules_for_pseudo;

    bool found_rule_for_root = false;
    for (const auto& matched_rules : parent_resolver.PseudoElementRules()) {
      if (matched_rules
```