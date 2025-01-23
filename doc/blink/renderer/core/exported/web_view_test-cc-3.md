Response:
The user wants a summary of the functionality of the provided C++ code snippet from `web_view_test.cc`. This involves analyzing the test cases and identifying the core functionalities being tested. The user also asks about relationships to JavaScript, HTML, and CSS, examples of logical reasoning with input/output, common user/programming errors, and how a user might reach this code (debugging).

Here's a breakdown of the code's functionalities based on the test names and the operations within the tests:

1. **Focus Management (IME and Autofill):**  Several tests (`MoveFocusToNextFocusableElementForImeAndAutofill`, `MoveFocusToNextFocusableElementForImeAndAutofillWithTabIndexElements`, `MoveFocusToNextFocusableElementForImeAndAutofillWithDisabledAndReadonlyElements`) focus on how the browser moves focus between elements in a form, especially for IME (Input Method Editor) and autofill purposes. This involves:
    - **Forward and Backward Navigation:** Simulating pressing Tab or Shift+Tab.
    - **`tabindex` Attribute:**  Testing how the `tabindex` attribute affects the order of focus.
    - **`disabled` and `readonly` Attributes:** Verifying that disabled or readonly elements are skipped during focus navigation.
    - **Non-editable Elements:** Checking the behavior when focusing on non-form elements within a form.

2. **Device Emulation:** The `ExitingDeviceEmulationResetsPageScale` test checks if disabling device emulation correctly resets the page scale factor.

3. **History and State Restoration:**  The `HistoryResetScrollAndScaleState` and `BackForwardRestoreScroll` tests verify how the browser handles scroll position and page scale when navigating through history (back/forward). This includes saving and restoring the state.

4. **Fullscreen Mode:** The `FullscreenNoResetScroll`, `FullscreenBackgroundColor`, and `FullscreenRemovalTiming` tests deal with the behavior of the browser when entering and exiting fullscreen mode. This includes:
    - **Preserving Scroll Position:** Ensuring the scroll position isn't lost when going fullscreen.
    - **Backdrop Color:**  Verifying that the background color in fullscreen is taken from the backdrop element.
    - **Top Layer Removal:** Testing the timing of removing fullscreen elements from the top layer.

5. **Printing:** The `PrintWithXHRInFlight` test checks if printing is correctly handled even when there are ongoing XMLHttpRequests (XHR).

6. **Drag and Drop:** The `DragDropURL` test examines how the browser handles dragging and dropping URLs into the window and whether navigation occurs. It also checks a setting to disable drag-and-drop navigation.

7. **Gesture Handling:** Several tests involving `SimulateGestureAtElement`, `SimulateGestureAtElementById`, `SimulateTapEventAtElement`, and `SimulateTapEventAtElementById`, `LongPressEmptyDiv`, and `LongPressObject` focus on how the browser handles touch gestures like taps and long presses on different elements.

8. **Date/Time Chooser:** The `ClientTapHandlingNullWebViewClient` test touches on the interaction with external components, indirectly related to date/time choosers as it deals with event handling when no specific client is provided.

Now, let's address the specific points in the user's request.
```cpp
ements[i].element_id));
    EXPECT_EQ(current_focus, document->FocusedElement());
    next_previous_flags =
        active_input_method_controller->ComputeWebTextInputNextPreviousFlags();
    EXPECT_EQ(focused_elements[i].next_previous_flags, next_previous_flags);
    next_focus = document->GetPage()
                     ->GetFocusController()
                     .NextFocusableElementForImeAndAutofill(
                         current_focus, mojom::blink::FocusType::kForward);
    if (next_focus) {
      EXPECT_EQ(next_focus->GetIdAttribute(),
                focused_elements[i + 1].element_id);
    }
    web_view->MainFrameImpl()->GetFrame()->AdvanceFocusForIME(
        mojom::blink::FocusType::kForward);
  }
  // Now focus will stay on previous focus itself, because it has no next
  // element.
  EXPECT_EQ(current_focus, document->FocusedElement());

  // Backward Navigation in form1 with PREVIOUS
  for (size_t i = std::size(focused_elements); i-- > 0;) {
    current_focus =
        document->getElementById(AtomicString(focused_elements[i].element_id));
    EXPECT_EQ(current_focus, document->FocusedElement());
    next_previous_flags =
        active_input_method_controller->ComputeWebTextInputNextPreviousFlags();
    EXPECT_EQ(focused_elements[i].next_previous_flags, next_previous_flags);
    next_focus = document->GetPage()
                     ->GetFocusController()
                     .NextFocusableElementForImeAndAutofill(
                         current_focus, mojom::blink::FocusType::kBackward);
    if (next_focus) {
      EXPECT_EQ(next_focus->GetIdAttribute(),
                focused_elements[i - 1].element_id);
    }
    web_view->MainFrameImpl()->GetFrame()->AdvanceFocusForIME(
        mojom::blink::FocusType::kBackward);
  }
  // Now focus will stay on previous focus itself, because it has no previous
  // element.
  EXPECT_EQ(current_focus, document->FocusedElement());

  // Setting a non editable element as focus in form1, and ensuring editable
  // navigation is fine in forward and backward.
  Element* anchor2 = document->getElementById(AtomicString("anchor2"));
  anchor2->Focus();
  next_previous_flags =
      active_input_method_controller->ComputeWebTextInputNextPreviousFlags();
  // No Next/Previous element for non-form control elements inside form.
  EXPECT_EQ(0, next_previous_flags);
  next_focus = document->GetPage()
                   ->GetFocusController()
                   .NextFocusableElementForImeAndAutofill(
                       anchor2, mojom::blink::FocusType::kForward);
  EXPECT_EQ(next_focus, nullptr);
  web_view->MainFrameImpl()->GetFrame()->AdvanceFocusForIME(
      mojom::blink::FocusType::kForward);
  // Since anchor is not a form control element, next/previous element will
  // be null, hence focus will stay same as it is.
  EXPECT_EQ(anchor2, document->FocusedElement());
  next_focus = document->GetPage()
                   ->GetFocusController()
                   .NextFocusableElementForImeAndAutofill(
                       anchor2, mojom::blink::FocusType::kBackward);
  EXPECT_EQ(next_focus, nullptr);
  web_view->MainFrameImpl()->GetFrame()->AdvanceFocusForIME(
      mojom::blink::FocusType::kBackward);
  EXPECT_EQ(anchor2, document->FocusedElement());

  web_view_helper_.Reset();
}

TEST_F(WebViewTest,
       MoveFocusToNextFocusableElementForImeAndAutofillWithTabIndexElements) {
  const std::string test_file =
      "advance_focus_in_form_with_tabindex_elements.html";
  RegisterMockedHttpURLLoad(test_file);
  WebViewImpl* web_view =
      web_view_helper_.InitializeAndLoad(base_url_ + test_file);
  web_view->MainFrameImpl()->GetFrame()->SetInitialFocus(false);
  Document* document = web_view->MainFrameImpl()->GetFrame()->GetDocument();
  WebInputMethodController* active_input_method_controller =
      web_view->MainFrameImpl()
          ->FrameWidget()
          ->GetActiveWebInputMethodController();
  const int default_text_input_flags = kWebTextInputFlagNone;

  struct FocusedElement {
    const char* element_id;
    int next_previous_flags;
  } focused_elements[] = {
      {"textarea6",
       default_text_input_flags | kWebTextInputFlagHaveNextFocusableElement},
      {"input5", default_text_input_flags |
                     kWebTextInputFlagHaveNextFocusableElement |
                     kWebTextInputFlagHavePreviousFocusableElement},
      {"contenteditable4", kWebTextInputFlagHaveNextFocusableElement |
                               kWebTextInputFlagHavePreviousFocusableElement},
      {"input6", default_text_input_flags |
                     kWebTextInputFlagHavePreviousFocusableElement},
  };

  // Forward Navigation in form with NEXT which has tabindex attribute
  // which differs visual order.
  Element* text_area6 = document->getElementById(AtomicString("textarea6"));
  text_area6->Focus();
  Element* current_focus = nullptr;
  Element* next_focus = nullptr;
  int next_previous_flags;
  for (size_t i = 0; i < std::size(focused_elements); ++i) {
    current_focus =
        document->getElementById(AtomicString(focused_elements[i].element_id));
    EXPECT_EQ(current_focus, document->FocusedElement());
    next_previous_flags =
        active_input_method_controller->ComputeWebTextInputNextPreviousFlags();
    EXPECT_EQ(focused_elements[i].next_previous_flags, next_previous_flags);
    next_focus = document->GetPage()
                     ->GetFocusController()
                     .NextFocusableElementForImeAndAutofill(
                         current_focus, mojom::blink::FocusType::kForward);
    if (next_focus) {
      EXPECT_EQ(next_focus->GetIdAttribute(),
                focused_elements[i + 1].element_id);
    }
    web_view->MainFrameImpl()->GetFrame()->AdvanceFocusForIME(
        mojom::blink::FocusType::kForward);
  }
  // No next editable element which is focusable with proper tab index, hence
  // staying on previous focus.
  EXPECT_EQ(current_focus, document->FocusedElement());

  // Backward Navigation in form with PREVIOUS which has tabindex attribute
  // which differs visual order.
  for (size_t i = std::size(focused_elements); i-- > 0;) {
    current_focus =
        document->getElementById(AtomicString(focused_elements[i].element_id));
    EXPECT_EQ(current_focus, document->FocusedElement());
    next_previous_flags =
        active_input_method_controller->ComputeWebTextInputNextPreviousFlags();
    EXPECT_EQ(focused_elements[i].next_previous_flags, next_previous_flags);
    next_focus = document->GetPage()
                     ->GetFocusController()
                     .NextFocusableElementForImeAndAutofill(
                         current_focus, mojom::blink::FocusType::kBackward);
    if (next_focus) {
      EXPECT_EQ(next_focus->GetIdAttribute(),
                focused_elements[i - 1].element_id);
    }
    web_view->MainFrameImpl()->GetFrame()->AdvanceFocusForIME(
        mojom::blink::FocusType::kBackward);
  }
  // Now focus will stay on previous focus itself, because it has no previous
  // element.
  EXPECT_EQ(current_focus, document->FocusedElement());

  // Setting an element which has invalid tabindex and ensuring it is not
  // modifying further navigation.
  Element* content_editable5 =
      document->getElementById(AtomicString("contenteditable5"));
  content_editable5->Focus();
  Element* input6 = document->getElementById(AtomicString("input6"));
  next_focus = document->GetPage()
                   ->GetFocusController()
                   .NextFocusableElementForImeAndAutofill(
                       content_editable5, mojom::blink::FocusType::kForward);
  EXPECT_EQ(next_focus, input6);
  web_view->MainFrameImpl()->GetFrame()->AdvanceFocusForIME(
      mojom::blink::FocusType::kForward);
  EXPECT_EQ(input6, document->FocusedElement());
  content_editable5->Focus();
  next_focus = document->GetPage()
                   ->GetFocusController()
                   .NextFocusableElementForImeAndAutofill(
                       content_editable5, mojom::blink::FocusType::kBackward);
  EXPECT_EQ(next_focus, text_area6);
  web_view->MainFrameImpl()->GetFrame()->AdvanceFocusForIME(
      mojom::blink::FocusType::kBackward);
  EXPECT_EQ(text_area6, document->FocusedElement());

  web_view_helper_.Reset();
}

TEST_F(
    WebViewTest,
    MoveFocusToNextFocusableElementForImeAndAutofillWithDisabledAndReadonlyElements) {
  const std::string test_file =
      "advance_focus_in_form_with_disabled_and_readonly_elements.html";
  RegisterMockedHttpURLLoad(test_file);
  WebViewImpl* web_view =
      web_view_helper_.InitializeAndLoad(base_url_ + test_file);
  web_view->MainFrameImpl()->GetFrame()->SetInitialFocus(false);
  Document* document = web_view->MainFrameImpl()->GetFrame()->GetDocument();
  WebInputMethodController* active_input_method_controller =
      web_view->MainFrameImpl()
          ->FrameWidget()
          ->GetActiveWebInputMethodController();

  struct FocusedElement {
    const char* element_id;
    int next_previous_flags;
  } focused_elements[] = {
      {"contenteditable6", kWebTextInputFlagHaveNextFocusableElement},
      {"contenteditable7", kWebTextInputFlagHavePreviousFocusableElement},
  };
  // Forward Navigation in form with NEXT which has has disabled/enabled
  // elements which will gets skipped during navigation.
  Element* content_editable6 =
      document->getElementById(AtomicString("contenteditable6"));
  content_editable6->Focus();
  Element* current_focus = nullptr;
  Element* next_focus = nullptr;
  int next_previous_flags;
  for (size_t i = 0; i < std::size(focused_elements); ++i) {
    current_focus =
        document->getElementById(AtomicString(focused_elements[i].element_id));
    EXPECT_EQ(current_focus, document->FocusedElement());
    next_previous_flags =
        active_input_method_controller->ComputeWebTextInputNextPreviousFlags();
    EXPECT_EQ(focused_elements[i].next_previous_flags, next_previous_flags);
    next_focus = document->GetPage()
                     ->GetFocusController()
                     .NextFocusableElementForImeAndAutofill(
                         current_focus, mojom::blink::FocusType::kForward);
    if (next_focus) {
      EXPECT_EQ(next_focus->GetIdAttribute(),
                focused_elements[i + 1].element_id);
    }
    web_view->MainFrameImpl()->GetFrame()->AdvanceFocusForIME(
        mojom::blink::FocusType::kForward);
  }
  // No next editable element which is focusable, hence staying on previous
  // focus.
  EXPECT_EQ(current_focus, document->FocusedElement());

  // Backward Navigation in form with PREVIOUS which has has
  // disabled/enabled elements which will gets skipped during navigation.
  for (size_t i = std::size(focused_elements); i-- > 0;) {
    current_focus =
        document->getElementById(AtomicString(focused_elements[i].element_id));
    EXPECT_EQ(current_focus, document->FocusedElement());
    next_previous_flags =
        active_input_method_controller->ComputeWebTextInputNextPreviousFlags();
    EXPECT_EQ(focused_elements[i].next_previous_flags, next_previous_flags);
    next_focus = document->GetPage()
                     ->GetFocusController()
                     .NextFocusableElementForImeAndAutofill(
                         current_focus, mojom::blink::FocusType::kBackward);
    if (next_focus) {
      EXPECT_EQ(next_focus->GetIdAttribute(),
                focused_elements[i - 1].element_id);
    }
    web_view->MainFrameImpl()->GetFrame()->AdvanceFocusForIME(
        mojom::blink::FocusType::kBackward);
  }
  // Now focus will stay on previous focus itself, because it has no previous
  // element.
  EXPECT_EQ(current_focus, document->FocusedElement());

  web_view_helper_.Reset();
}

TEST_F(WebViewTest, ExitingDeviceEmulationResetsPageScale) {
  RegisterMockedHttpURLLoad("200-by-300.html");
  WebViewImpl* web_view_impl =
      web_view_helper_.InitializeAndLoad(base_url_ + "200-by-300.html");
  web_view_impl->MainFrameViewWidget()->Resize(gfx::Size(200, 300));

  float page_scale_expected = web_view_impl->PageScaleFactor();

  DeviceEmulationParams params;
  params.screen_type = mojom::EmulatedScreenType::kDesktop;
  params.device_scale_factor = 0;
  params.scale = 1;

  web_view_impl->EnableDeviceEmulation(params);

  web_view_impl->SetPageScaleFactor(2);

  web_view_impl->DisableDeviceEmulation();

  EXPECT_EQ(page_scale_expected, web_view_impl->PageScaleFactor());
}

TEST_F(WebViewTest, HistoryResetScrollAndScaleState) {
  RegisterMockedHttpURLLoad("200-by-300.html");
  WebViewImpl* web_view_impl =
      web_view_helper_.InitializeAndLoad(base_url_ + "200-by-300.html");
  web_view_impl->MainFrameViewWidget()->Resize(gfx::Size(100, 150));
  UpdateAllLifecyclePhases();
  EXPECT_EQ(gfx::PointF(), web_view_impl->MainFrameImpl()->GetScrollOffset());

  // Make the page scale and scroll with the given paremeters.
  web_view_impl->SetPageScaleFactor(2.0f);
  web_view_impl->MainFrameImpl()->SetScrollOffset(gfx::PointF(94, 111));
  EXPECT_EQ(2.0f, web_view_impl->PageScaleFactor());
  EXPECT_EQ(94, web_view_impl->MainFrameImpl()->GetScrollOffset().x());
  EXPECT_EQ(111, web_view_impl->MainFrameImpl()->GetScrollOffset().y());
  auto* main_frame_local =
      To<LocalFrame>(web_view_impl->GetPage()->MainFrame());
  main_frame_local->Loader().SaveScrollState();
  EXPECT_EQ(2.0f, main_frame_local->Loader()
                      .GetDocumentLoader()
                      ->GetHistoryItem()
                      ->GetViewState()
                      ->page_scale_factor_);
  EXPECT_EQ(94, main_frame_local->Loader()
                    .GetDocumentLoader()
                    ->GetHistoryItem()
                    ->GetViewState()
                    ->scroll_offset_.x());
  EXPECT_EQ(111, main_frame_local->Loader()
                     .GetDocumentLoader()
                     ->GetHistoryItem()
                     ->GetViewState()
                     ->scroll_offset_.y());

  // Confirm that resetting the page state resets the saved scroll position.
  web_view_impl->ResetScrollAndScaleState();
  EXPECT_EQ(1.0f, web_view_impl->PageScaleFactor());
  EXPECT_EQ(gfx::PointF(), web_view_impl->MainFrameImpl()->GetScrollOffset());
  EXPECT_FALSE(main_frame_local->Loader()
                   .GetDocumentLoader()
                   ->GetHistoryItem()
                   ->GetViewState()
                   .has_value());
}

TEST_F(WebViewTest, BackForwardRestoreScroll) {
  RegisterMockedHttpURLLoad("back_forward_restore_scroll.html");
  WebViewImpl* web_view_impl = web_view_helper_.InitializeAndLoad(
      base_url_ + "back_forward_restore_scroll.html");
  web_view_impl->MainFrameViewWidget()->Resize(gfx::Size(640, 480));
  web_view_impl->MainFrameWidget()->UpdateAllLifecyclePhases(
      DocumentUpdateReason::kTest);

  // Emulate a user scroll
  web_view_impl->MainFrameImpl()->SetScrollOffset(gfx::PointF(0, 900));
  auto* main_frame_local =
      To<LocalFrame>(web_view_impl->GetPage()->MainFrame());
  Persistent<HistoryItem> item1 =
      main_frame_local->Loader().GetDocumentLoader()->GetHistoryItem();

  // Click an anchor
  FrameLoadRequest request_a(
      main_frame_local->DomWindow(),
      ResourceRequest(main_frame_local->GetDocument()->CompleteURL("#a")));
  main_frame_local->Loader().StartNavigation(request_a);
  Persistent<HistoryItem> item2 =
      main_frame_local->Loader().GetDocumentLoader()->GetHistoryItem();

  // Go back, then forward, then back again.
  main_frame_local->Loader().GetDocumentLoader()->CommitSameDocumentNavigation(
      item1->Url(), WebFrameLoadType::kBackForward, item1.Get(),
      ClientRedirectPolicy::kNotClientRedirect,
      /*has_transient_user_activation=*/false, /*initiator_origin=*/nullptr,
      /*is_synchronously_committed=*/false, /*source_element=*/nullptr,
      mojom::blink::TriggeringEventInfo::kNotFromEvent,
      /*is_browser_initiated=*/true, /*has_ua_visual_transition,=*/false,
      /*soft_navigation_heuristics_task_id=*/std::nullopt);
  main_frame_local->Loader().GetDocumentLoader()->CommitSameDocumentNavigation(
      item2->Url(), WebFrameLoadType::kBackForward, item2.Get(),
      ClientRedirectPolicy::kNotClientRedirect,
      /*has_transient_user_activation=*/false, /*initiator_origin=*/nullptr,
      /*is_synchronously_committed=*/false, /*source_element=*/nullptr,
      mojom::blink::TriggeringEventInfo::kNotFromEvent,
      /*is_browser_initiated=*/true, /*has_ua_visual_transition,=*/false,
      /*soft_navigation_heuristics_task_id=*/std::nullopt);
  main_frame_local->Loader().GetDocumentLoader()->CommitSameDocumentNavigation(
      item1->Url(), WebFrameLoadType::kBackForward, item1.Get(),
      ClientRedirectPolicy::kNotClientRedirect,
      /*has_transient_user_activation=*/false, /*initiator_origin=*/nullptr,
      /*is_synchronously_committed=*/false, /*source_element=*/nullptr,
      mojom::blink::TriggeringEventInfo::kNotFromEvent,
      /*is_browser_initiated=*/true, /*has_ua_visual_transition,=*/false,
      /*soft_navigation_heuristics_task_id=*/std::nullopt);
  web_view_impl->MainFrameWidget()->UpdateAllLifecyclePhases(
      DocumentUpdateReason::kTest);

  // Click a different anchor
  FrameLoadRequest request_b(
      main_frame_local->DomWindow(),
      ResourceRequest(main_frame_local->GetDocument()->CompleteURL("#b")));
  main_frame_local->Loader().StartNavigation(request_b);
  Persistent<HistoryItem> item3 =
      main_frame_local->Loader().GetDocumentLoader()->GetHistoryItem();
  web_view_impl->MainFrameWidget()->UpdateAllLifecyclePhases(
      DocumentUpdateReason::kTest);

  // Go back, then forward. The scroll position should be properly set on the
  // forward navigation.
  main_frame_local->Loader().GetDocumentLoader()->CommitSameDocumentNavigation(
      item1->Url(), WebFrameLoadType::kBackForward, item1.Get(),
      ClientRedirectPolicy::kNotClientRedirect,
      /*has_transient_user_activation=*/false, /*initiator_origin=*/nullptr,
      /*is_synchronously_committed=*/false, /*source_element=*/nullptr,
      mojom::blink::TriggeringEventInfo::kNotFromEvent,
      /*is_browser_initiated=*/true, /*has_ua_visual_transition,=*/false,
      /*soft_navigation_heuristics_task_id=*/std::nullopt);

  main_frame_local->Loader().GetDocumentLoader()->CommitSameDocumentNavigation(
      item3->Url(), WebFrameLoadType::kBackForward, item3.Get(),
      ClientRedirectPolicy::kNotClientRedirect,
      /*has_transient_user_activation=*/false, /*initiator_origin=*/nullptr,
      /*is_synchronously_committed=*/false, /*source_element=*/nullptr,
      mojom::blink::TriggeringEventInfo::kNotFromEvent,
      /*is_browser_initiated=*/true, /*has_ua_visual_transition,=*/false,
      /*soft_navigation_heuristics_task_id=*/std::nullopt);
  // The scroll offset is only applied via invoking the anchor via the main
  // lifecycle, or a forced layout.
  // TODO(chrishtr): At the moment, WebLocalFrameImpl::GetScrollOffset() does
  // not force a layout. Script-exposed scroll offset-reading methods do,
  // however. It seems wrong not to force a layout.
  EXPECT_EQ(0, web_view_impl->MainFrameImpl()->GetScrollOffset().x());
  EXPECT_GT(web_view_impl->MainFrameImpl()->GetScrollOffset().y(), 2000);
}

// Tests that scroll offset modified during fullscreen is preserved when
// exiting fullscreen.
TEST_F(WebViewTest, FullscreenNoResetScroll) {
  RegisterMockedHttpURLLoad("fullscreen_style.html");
  WebViewImpl* web_view_impl =
      web_view_helper_.InitializeAndLoad(base_url_ + "fullscreen_style.html");
  web_view_impl->MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  UpdateAllLifecyclePhases();

  // Scroll the page down.
  web_view_impl->MainFrameImpl()->SetScrollOffset(gfx::PointF(0, 2000));
  ASSERT_EQ(2000, web_view_impl->MainFrameImpl()->GetScrollOffset().y());

  // Enter fullscreen.
  LocalFrame* frame = web_view_impl->MainFrameImpl()->GetFrame();
  Element* element = frame->GetDocument()->documentElement();
  LocalFrame::NotifyUserActivation(
      frame, mojom::UserActivationNotificationType::kTest);
  Fullscreen::RequestFullscreen(*element);
  web_view_impl->DidEnterFullscreen();
  UpdateAllLifecyclePhases();

  // Assert the scroll position on the document element doesn't change.
  ASSERT_EQ(2000, web_view_impl->MainFrameImpl()->GetScrollOffset().y());

  web_view_impl->MainFrameImpl()->SetScrollOffset(gfx::PointF(0, 2100));

  web_view_impl->DidExitFullscreen();
  UpdateAllLifecyclePhases();

  EXPECT_EQ(2100, web_view_impl->MainFrameImpl()->GetScrollOffset().y());
}

// Tests that background color is read from the backdrop on fullscreen.
TEST_F(WebViewTest, FullscreenBackgroundColor) {
  RegisterMockedHttpURLLoad("fullscreen_style.html");
  WebViewImpl* web_view_impl =
      web_view_helper_.InitializeAndLoad(base_url_ + "fullscreen_style.html");
  web_view_impl->MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  UpdateAllLifecyclePhases();
  EXPECT_EQ(SK_ColorWHITE, web_view_impl->BackgroundColor());

  // Enter fullscreen.
  LocalFrame* frame = web_view_impl->MainFrameImpl()->GetFrame();
  Element* element =
      frame->GetDocument()->getElementById(AtomicString("fullscreenElement"));
  ASSERT_TRUE(element);
  LocalFrame::NotifyUserActivation(
      frame, mojom::UserActivationNotificationType::kTest);
  Fullscreen::RequestFullscreen(*element);
  web_view_impl->DidEnterFullscreen();
  UpdateAllLifecyclePhases();

  EXPECT_EQ(SK_ColorYELLOW, web_view_impl->BackgroundColor());
}

static void ExitFullscreen(Document& document) {
  Fullscreen::FullyExitFullscreen(document);
  Fullscreen::DidExitFullscreen(document);
  EXPECT_EQ(Fullscreen::FullscreenElementFrom(document), nullptr);
}

// Tests that the removal from the top layer is scheduled.
TEST_F(WebViewTest, FullscreenRemovalTiming) {
  RegisterMockedHttpURLLoad("fullscreen_style.html");
  WebViewImpl* web_view_impl =
      web_view_helper_.InitializeAndLoad(base_url_ + "fullscreen_style.html");
  web_view_impl->MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  UpdateAllLifecyclePhases();

  // Enter fullscreen.
  LocalFrame* frame = web_view_impl->MainFrameImpl()->GetFrame();
  Document* document = frame->GetDocument();
  ASSERT_TRUE(document);
  Element* element =
      document->getElementById(AtomicString("fullscreenElement"));
  ASSERT_TRUE(element);
  LocalFrame::NotifyUserActivation(
      frame, mojom::UserActivationNotificationType::kTest);
  Fullscreen::RequestFullscreen(*element);
  web_view_impl->DidEnterFullscreen();
  UpdateAllLifecyclePhases();
  EXPECT_TRUE(element->IsInTopLayer());

  ExitFullscreen(*document);
  EXPECT_TRUE(element->IsInTopLayer());
  UpdateAllLifecyclePhases();
  EXPECT_FALSE(element->IsInTopLayer());
}

class PrintWebFrameClient : public frame_test_helpers::TestWebFrameClient {
 public:
  PrintWebFrameClient() = default;

  // WebLocalFrameClient overrides:
  void ScriptedPrint() override { print_called_ = true; }

  bool PrintCalled() const { return print_called_; }

 private:
  bool print_called_ = false;
};

TEST_F(WebViewTest, PrintWithXHRInFlight) {
  PrintWebFrameClient client;
  RegisterMockedHttpURLLoad("print_with_xhr_inflight.html");
  WebViewImpl* web_view_impl = web_view_helper_.InitializeAndLoad(
      base_url_ + "print_with_xhr_inflight.html", &client, nullptr);

  ASSERT_TRUE(To<LocalFrame>(web_view_impl->GetPage()->MainFrame())
                  ->GetDocument()
                  ->LoadEventFinished());
  EXPECT_TRUE(client.PrintCalled());
  web_view_helper_.Reset();
}

static void DragAndDropURL(WebViewImpl* web_view, const std::string& url) {
  WebDragData drag_data;
  WebDragData::StringItem item;
  item.type = "text/uri-list";
  item.data = WebString::FromUTF8(url);
  drag_data.AddItem(item);

  const gfx::PointF client_point;
  const gfx::PointF screen_point;
  WebFrameWidget* widget = web_view->MainFrameImpl()->FrameWidget();
  widget->DragTargetDragEnter(drag_data, client_point, screen_point,
                              kDragOperationCopy, 0, base::DoNothing());
  widget->DragTargetDrop(drag_data, client_point, screen_point, 0,
                         base::DoNothing());
  frame_test_helpers::PumpPendingRequestsForFrameToLoad(
      web_view->MainFrameImpl());
}

TEST_F(WebViewTest, DragDropURL) {
  RegisterMockedHttpURLLoad("foo.html");
  RegisterMockedHttpURLLoad("bar.html");

  const std::string foo_url = base_url_ + "foo.html";
  const std::string bar_url = base_url_ + "bar.html";

  WebViewImpl* web_view = web_view_helper_.InitializeAndLoad(foo_url);

  ASSERT_TRUE(web_view);

  // Drag and drop barUrl and verify that we've navigated to it.
  DragAndDropURL(web_view, bar_url);
  EXPECT_EQ(bar_url,
            web_view->MainFrameImpl()->GetDocument().Url().GetString().Utf8());

  // Drag and drop fooUrl and verify that we've navigated back to it.
  DragAndDropURL(web_view, foo_url);
  EXPECT_EQ(foo_url,
            web_view->MainFrameImpl()->GetDocument().Url().GetString().Utf8());

  // Disable navigation on drag-and-drop.
  auto renderer_preferences = web_view->GetRendererPreferences();
  renderer_preferences.can_accept_load_drops = false;
  web_view->SetRendererPreferences(renderer_preferences);

  // Attempt to drag and drop to barUrl and verify that no navigation has
  // occurred.
  DragAndDropURL(web_view, bar_url);
  EXPECT_EQ(foo_url,
            web_view->MainFrameImpl()->GetDocument().Url().GetString().Utf8());
}

bool WebViewTest::SimulateGestureAtElement(WebInputEvent::Type type,
                                           Element* element) {
  if (!element || !element->GetLayoutObject())
    return false;

  DCHECK(web_view_helper_.GetWebView());
  element->scrollIntoViewIfNeeded();

  gfx::Point center =
      web_view_helper_.GetWebView()
          ->MainFrameImpl()
          ->GetFrameView()
          ->FrameToScreen(element->GetLayoutObject()->AbsoluteBoundingBoxRect())
          .CenterPoint();

  WebGestureEvent event(type, WebInputEvent::kNoModifiers,
                        WebInputEvent::GetStaticTimeStampForTests(),
                        WebGestureDevice::kTouchscreen);
  event.SetPositionInWidget(gfx::PointF(center));

  web_view_helper_.GetWebView()->MainFrameWidget()->HandleInputEvent(
      WebCoalescedInputEvent(event, ui::LatencyInfo()));
  RunPendingTasks();
  return true;
}

bool WebViewTest::SimulateGestureAtElementById(WebInputEvent::Type type,
                                               const WebString& id) {
  DCHECK(web_view_helper_.GetWebView());
  Element* element = static_cast<Element*>(
      web
### 提示词
```
这是目录为blink/renderer/core/exported/web_view_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第4部分，共9部分，请归纳一下它的功能
```

### 源代码
```cpp
lements[i].element_id));
    EXPECT_EQ(current_focus, document->FocusedElement());
    next_previous_flags =
        active_input_method_controller->ComputeWebTextInputNextPreviousFlags();
    EXPECT_EQ(focused_elements[i].next_previous_flags, next_previous_flags);
    next_focus = document->GetPage()
                     ->GetFocusController()
                     .NextFocusableElementForImeAndAutofill(
                         current_focus, mojom::blink::FocusType::kForward);
    if (next_focus) {
      EXPECT_EQ(next_focus->GetIdAttribute(),
                focused_elements[i + 1].element_id);
    }
    web_view->MainFrameImpl()->GetFrame()->AdvanceFocusForIME(
        mojom::blink::FocusType::kForward);
  }
  // Now focus will stay on previous focus itself, because it has no next
  // element.
  EXPECT_EQ(current_focus, document->FocusedElement());

  // Backward Navigation in form1 with PREVIOUS
  for (size_t i = std::size(focused_elements); i-- > 0;) {
    current_focus =
        document->getElementById(AtomicString(focused_elements[i].element_id));
    EXPECT_EQ(current_focus, document->FocusedElement());
    next_previous_flags =
        active_input_method_controller->ComputeWebTextInputNextPreviousFlags();
    EXPECT_EQ(focused_elements[i].next_previous_flags, next_previous_flags);
    next_focus = document->GetPage()
                     ->GetFocusController()
                     .NextFocusableElementForImeAndAutofill(
                         current_focus, mojom::blink::FocusType::kBackward);
    if (next_focus) {
      EXPECT_EQ(next_focus->GetIdAttribute(),
                focused_elements[i - 1].element_id);
    }
    web_view->MainFrameImpl()->GetFrame()->AdvanceFocusForIME(
        mojom::blink::FocusType::kBackward);
  }
  // Now focus will stay on previous focus itself, because it has no previous
  // element.
  EXPECT_EQ(current_focus, document->FocusedElement());

  // Setting a non editable element as focus in form1, and ensuring editable
  // navigation is fine in forward and backward.
  Element* anchor2 = document->getElementById(AtomicString("anchor2"));
  anchor2->Focus();
  next_previous_flags =
      active_input_method_controller->ComputeWebTextInputNextPreviousFlags();
  // No Next/Previous element for non-form control elements inside form.
  EXPECT_EQ(0, next_previous_flags);
  next_focus = document->GetPage()
                   ->GetFocusController()
                   .NextFocusableElementForImeAndAutofill(
                       anchor2, mojom::blink::FocusType::kForward);
  EXPECT_EQ(next_focus, nullptr);
  web_view->MainFrameImpl()->GetFrame()->AdvanceFocusForIME(
      mojom::blink::FocusType::kForward);
  // Since anchor is not a form control element, next/previous element will
  // be null, hence focus will stay same as it is.
  EXPECT_EQ(anchor2, document->FocusedElement());
  next_focus = document->GetPage()
                   ->GetFocusController()
                   .NextFocusableElementForImeAndAutofill(
                       anchor2, mojom::blink::FocusType::kBackward);
  EXPECT_EQ(next_focus, nullptr);
  web_view->MainFrameImpl()->GetFrame()->AdvanceFocusForIME(
      mojom::blink::FocusType::kBackward);
  EXPECT_EQ(anchor2, document->FocusedElement());

  web_view_helper_.Reset();
}

TEST_F(WebViewTest,
       MoveFocusToNextFocusableElementForImeAndAutofillWithTabIndexElements) {
  const std::string test_file =
      "advance_focus_in_form_with_tabindex_elements.html";
  RegisterMockedHttpURLLoad(test_file);
  WebViewImpl* web_view =
      web_view_helper_.InitializeAndLoad(base_url_ + test_file);
  web_view->MainFrameImpl()->GetFrame()->SetInitialFocus(false);
  Document* document = web_view->MainFrameImpl()->GetFrame()->GetDocument();
  WebInputMethodController* active_input_method_controller =
      web_view->MainFrameImpl()
          ->FrameWidget()
          ->GetActiveWebInputMethodController();
  const int default_text_input_flags = kWebTextInputFlagNone;

  struct FocusedElement {
    const char* element_id;
    int next_previous_flags;
  } focused_elements[] = {
      {"textarea6",
       default_text_input_flags | kWebTextInputFlagHaveNextFocusableElement},
      {"input5", default_text_input_flags |
                     kWebTextInputFlagHaveNextFocusableElement |
                     kWebTextInputFlagHavePreviousFocusableElement},
      {"contenteditable4", kWebTextInputFlagHaveNextFocusableElement |
                               kWebTextInputFlagHavePreviousFocusableElement},
      {"input6", default_text_input_flags |
                     kWebTextInputFlagHavePreviousFocusableElement},
  };

  // Forward Navigation in form with NEXT which has tabindex attribute
  // which differs visual order.
  Element* text_area6 = document->getElementById(AtomicString("textarea6"));
  text_area6->Focus();
  Element* current_focus = nullptr;
  Element* next_focus = nullptr;
  int next_previous_flags;
  for (size_t i = 0; i < std::size(focused_elements); ++i) {
    current_focus =
        document->getElementById(AtomicString(focused_elements[i].element_id));
    EXPECT_EQ(current_focus, document->FocusedElement());
    next_previous_flags =
        active_input_method_controller->ComputeWebTextInputNextPreviousFlags();
    EXPECT_EQ(focused_elements[i].next_previous_flags, next_previous_flags);
    next_focus = document->GetPage()
                     ->GetFocusController()
                     .NextFocusableElementForImeAndAutofill(
                         current_focus, mojom::blink::FocusType::kForward);
    if (next_focus) {
      EXPECT_EQ(next_focus->GetIdAttribute(),
                focused_elements[i + 1].element_id);
    }
    web_view->MainFrameImpl()->GetFrame()->AdvanceFocusForIME(
        mojom::blink::FocusType::kForward);
  }
  // No next editable element which is focusable with proper tab index, hence
  // staying on previous focus.
  EXPECT_EQ(current_focus, document->FocusedElement());

  // Backward Navigation in form with PREVIOUS which has tabindex attribute
  // which differs visual order.
  for (size_t i = std::size(focused_elements); i-- > 0;) {
    current_focus =
        document->getElementById(AtomicString(focused_elements[i].element_id));
    EXPECT_EQ(current_focus, document->FocusedElement());
    next_previous_flags =
        active_input_method_controller->ComputeWebTextInputNextPreviousFlags();
    EXPECT_EQ(focused_elements[i].next_previous_flags, next_previous_flags);
    next_focus = document->GetPage()
                     ->GetFocusController()
                     .NextFocusableElementForImeAndAutofill(
                         current_focus, mojom::blink::FocusType::kBackward);
    if (next_focus) {
      EXPECT_EQ(next_focus->GetIdAttribute(),
                focused_elements[i - 1].element_id);
    }
    web_view->MainFrameImpl()->GetFrame()->AdvanceFocusForIME(
        mojom::blink::FocusType::kBackward);
  }
  // Now focus will stay on previous focus itself, because it has no previous
  // element.
  EXPECT_EQ(current_focus, document->FocusedElement());

  // Setting an element which has invalid tabindex and ensuring it is not
  // modifying further navigation.
  Element* content_editable5 =
      document->getElementById(AtomicString("contenteditable5"));
  content_editable5->Focus();
  Element* input6 = document->getElementById(AtomicString("input6"));
  next_focus = document->GetPage()
                   ->GetFocusController()
                   .NextFocusableElementForImeAndAutofill(
                       content_editable5, mojom::blink::FocusType::kForward);
  EXPECT_EQ(next_focus, input6);
  web_view->MainFrameImpl()->GetFrame()->AdvanceFocusForIME(
      mojom::blink::FocusType::kForward);
  EXPECT_EQ(input6, document->FocusedElement());
  content_editable5->Focus();
  next_focus = document->GetPage()
                   ->GetFocusController()
                   .NextFocusableElementForImeAndAutofill(
                       content_editable5, mojom::blink::FocusType::kBackward);
  EXPECT_EQ(next_focus, text_area6);
  web_view->MainFrameImpl()->GetFrame()->AdvanceFocusForIME(
      mojom::blink::FocusType::kBackward);
  EXPECT_EQ(text_area6, document->FocusedElement());

  web_view_helper_.Reset();
}

TEST_F(
    WebViewTest,
    MoveFocusToNextFocusableElementForImeAndAutofillWithDisabledAndReadonlyElements) {
  const std::string test_file =
      "advance_focus_in_form_with_disabled_and_readonly_elements.html";
  RegisterMockedHttpURLLoad(test_file);
  WebViewImpl* web_view =
      web_view_helper_.InitializeAndLoad(base_url_ + test_file);
  web_view->MainFrameImpl()->GetFrame()->SetInitialFocus(false);
  Document* document = web_view->MainFrameImpl()->GetFrame()->GetDocument();
  WebInputMethodController* active_input_method_controller =
      web_view->MainFrameImpl()
          ->FrameWidget()
          ->GetActiveWebInputMethodController();

  struct FocusedElement {
    const char* element_id;
    int next_previous_flags;
  } focused_elements[] = {
      {"contenteditable6", kWebTextInputFlagHaveNextFocusableElement},
      {"contenteditable7", kWebTextInputFlagHavePreviousFocusableElement},
  };
  // Forward Navigation in form with NEXT which has has disabled/enabled
  // elements which will gets skipped during navigation.
  Element* content_editable6 =
      document->getElementById(AtomicString("contenteditable6"));
  content_editable6->Focus();
  Element* current_focus = nullptr;
  Element* next_focus = nullptr;
  int next_previous_flags;
  for (size_t i = 0; i < std::size(focused_elements); ++i) {
    current_focus =
        document->getElementById(AtomicString(focused_elements[i].element_id));
    EXPECT_EQ(current_focus, document->FocusedElement());
    next_previous_flags =
        active_input_method_controller->ComputeWebTextInputNextPreviousFlags();
    EXPECT_EQ(focused_elements[i].next_previous_flags, next_previous_flags);
    next_focus = document->GetPage()
                     ->GetFocusController()
                     .NextFocusableElementForImeAndAutofill(
                         current_focus, mojom::blink::FocusType::kForward);
    if (next_focus) {
      EXPECT_EQ(next_focus->GetIdAttribute(),
                focused_elements[i + 1].element_id);
    }
    web_view->MainFrameImpl()->GetFrame()->AdvanceFocusForIME(
        mojom::blink::FocusType::kForward);
  }
  // No next editable element which is focusable, hence staying on previous
  // focus.
  EXPECT_EQ(current_focus, document->FocusedElement());

  // Backward Navigation in form with PREVIOUS which has has
  // disabled/enabled elements which will gets skipped during navigation.
  for (size_t i = std::size(focused_elements); i-- > 0;) {
    current_focus =
        document->getElementById(AtomicString(focused_elements[i].element_id));
    EXPECT_EQ(current_focus, document->FocusedElement());
    next_previous_flags =
        active_input_method_controller->ComputeWebTextInputNextPreviousFlags();
    EXPECT_EQ(focused_elements[i].next_previous_flags, next_previous_flags);
    next_focus = document->GetPage()
                     ->GetFocusController()
                     .NextFocusableElementForImeAndAutofill(
                         current_focus, mojom::blink::FocusType::kBackward);
    if (next_focus) {
      EXPECT_EQ(next_focus->GetIdAttribute(),
                focused_elements[i - 1].element_id);
    }
    web_view->MainFrameImpl()->GetFrame()->AdvanceFocusForIME(
        mojom::blink::FocusType::kBackward);
  }
  // Now focus will stay on previous focus itself, because it has no previous
  // element.
  EXPECT_EQ(current_focus, document->FocusedElement());

  web_view_helper_.Reset();
}

TEST_F(WebViewTest, ExitingDeviceEmulationResetsPageScale) {
  RegisterMockedHttpURLLoad("200-by-300.html");
  WebViewImpl* web_view_impl =
      web_view_helper_.InitializeAndLoad(base_url_ + "200-by-300.html");
  web_view_impl->MainFrameViewWidget()->Resize(gfx::Size(200, 300));

  float page_scale_expected = web_view_impl->PageScaleFactor();

  DeviceEmulationParams params;
  params.screen_type = mojom::EmulatedScreenType::kDesktop;
  params.device_scale_factor = 0;
  params.scale = 1;

  web_view_impl->EnableDeviceEmulation(params);

  web_view_impl->SetPageScaleFactor(2);

  web_view_impl->DisableDeviceEmulation();

  EXPECT_EQ(page_scale_expected, web_view_impl->PageScaleFactor());
}

TEST_F(WebViewTest, HistoryResetScrollAndScaleState) {
  RegisterMockedHttpURLLoad("200-by-300.html");
  WebViewImpl* web_view_impl =
      web_view_helper_.InitializeAndLoad(base_url_ + "200-by-300.html");
  web_view_impl->MainFrameViewWidget()->Resize(gfx::Size(100, 150));
  UpdateAllLifecyclePhases();
  EXPECT_EQ(gfx::PointF(), web_view_impl->MainFrameImpl()->GetScrollOffset());

  // Make the page scale and scroll with the given paremeters.
  web_view_impl->SetPageScaleFactor(2.0f);
  web_view_impl->MainFrameImpl()->SetScrollOffset(gfx::PointF(94, 111));
  EXPECT_EQ(2.0f, web_view_impl->PageScaleFactor());
  EXPECT_EQ(94, web_view_impl->MainFrameImpl()->GetScrollOffset().x());
  EXPECT_EQ(111, web_view_impl->MainFrameImpl()->GetScrollOffset().y());
  auto* main_frame_local =
      To<LocalFrame>(web_view_impl->GetPage()->MainFrame());
  main_frame_local->Loader().SaveScrollState();
  EXPECT_EQ(2.0f, main_frame_local->Loader()
                      .GetDocumentLoader()
                      ->GetHistoryItem()
                      ->GetViewState()
                      ->page_scale_factor_);
  EXPECT_EQ(94, main_frame_local->Loader()
                    .GetDocumentLoader()
                    ->GetHistoryItem()
                    ->GetViewState()
                    ->scroll_offset_.x());
  EXPECT_EQ(111, main_frame_local->Loader()
                     .GetDocumentLoader()
                     ->GetHistoryItem()
                     ->GetViewState()
                     ->scroll_offset_.y());

  // Confirm that resetting the page state resets the saved scroll position.
  web_view_impl->ResetScrollAndScaleState();
  EXPECT_EQ(1.0f, web_view_impl->PageScaleFactor());
  EXPECT_EQ(gfx::PointF(), web_view_impl->MainFrameImpl()->GetScrollOffset());
  EXPECT_FALSE(main_frame_local->Loader()
                   .GetDocumentLoader()
                   ->GetHistoryItem()
                   ->GetViewState()
                   .has_value());
}

TEST_F(WebViewTest, BackForwardRestoreScroll) {
  RegisterMockedHttpURLLoad("back_forward_restore_scroll.html");
  WebViewImpl* web_view_impl = web_view_helper_.InitializeAndLoad(
      base_url_ + "back_forward_restore_scroll.html");
  web_view_impl->MainFrameViewWidget()->Resize(gfx::Size(640, 480));
  web_view_impl->MainFrameWidget()->UpdateAllLifecyclePhases(
      DocumentUpdateReason::kTest);

  // Emulate a user scroll
  web_view_impl->MainFrameImpl()->SetScrollOffset(gfx::PointF(0, 900));
  auto* main_frame_local =
      To<LocalFrame>(web_view_impl->GetPage()->MainFrame());
  Persistent<HistoryItem> item1 =
      main_frame_local->Loader().GetDocumentLoader()->GetHistoryItem();

  // Click an anchor
  FrameLoadRequest request_a(
      main_frame_local->DomWindow(),
      ResourceRequest(main_frame_local->GetDocument()->CompleteURL("#a")));
  main_frame_local->Loader().StartNavigation(request_a);
  Persistent<HistoryItem> item2 =
      main_frame_local->Loader().GetDocumentLoader()->GetHistoryItem();

  // Go back, then forward, then back again.
  main_frame_local->Loader().GetDocumentLoader()->CommitSameDocumentNavigation(
      item1->Url(), WebFrameLoadType::kBackForward, item1.Get(),
      ClientRedirectPolicy::kNotClientRedirect,
      /*has_transient_user_activation=*/false, /*initiator_origin=*/nullptr,
      /*is_synchronously_committed=*/false, /*source_element=*/nullptr,
      mojom::blink::TriggeringEventInfo::kNotFromEvent,
      /*is_browser_initiated=*/true, /*has_ua_visual_transition,=*/false,
      /*soft_navigation_heuristics_task_id=*/std::nullopt);
  main_frame_local->Loader().GetDocumentLoader()->CommitSameDocumentNavigation(
      item2->Url(), WebFrameLoadType::kBackForward, item2.Get(),
      ClientRedirectPolicy::kNotClientRedirect,
      /*has_transient_user_activation=*/false, /*initiator_origin=*/nullptr,
      /*is_synchronously_committed=*/false, /*source_element=*/nullptr,
      mojom::blink::TriggeringEventInfo::kNotFromEvent,
      /*is_browser_initiated=*/true, /*has_ua_visual_transition,=*/false,
      /*soft_navigation_heuristics_task_id=*/std::nullopt);
  main_frame_local->Loader().GetDocumentLoader()->CommitSameDocumentNavigation(
      item1->Url(), WebFrameLoadType::kBackForward, item1.Get(),
      ClientRedirectPolicy::kNotClientRedirect,
      /*has_transient_user_activation=*/false, /*initiator_origin=*/nullptr,
      /*is_synchronously_committed=*/false, /*source_element=*/nullptr,
      mojom::blink::TriggeringEventInfo::kNotFromEvent,
      /*is_browser_initiated=*/true, /*has_ua_visual_transition,=*/false,
      /*soft_navigation_heuristics_task_id=*/std::nullopt);
  web_view_impl->MainFrameWidget()->UpdateAllLifecyclePhases(
      DocumentUpdateReason::kTest);

  // Click a different anchor
  FrameLoadRequest request_b(
      main_frame_local->DomWindow(),
      ResourceRequest(main_frame_local->GetDocument()->CompleteURL("#b")));
  main_frame_local->Loader().StartNavigation(request_b);
  Persistent<HistoryItem> item3 =
      main_frame_local->Loader().GetDocumentLoader()->GetHistoryItem();
  web_view_impl->MainFrameWidget()->UpdateAllLifecyclePhases(
      DocumentUpdateReason::kTest);

  // Go back, then forward. The scroll position should be properly set on the
  // forward navigation.
  main_frame_local->Loader().GetDocumentLoader()->CommitSameDocumentNavigation(
      item1->Url(), WebFrameLoadType::kBackForward, item1.Get(),
      ClientRedirectPolicy::kNotClientRedirect,
      /*has_transient_user_activation=*/false, /*initiator_origin=*/nullptr,
      /*is_synchronously_committed=*/false, /*source_element=*/nullptr,
      mojom::blink::TriggeringEventInfo::kNotFromEvent,
      /*is_browser_initiated=*/true, /*has_ua_visual_transition,=*/false,
      /*soft_navigation_heuristics_task_id=*/std::nullopt);

  main_frame_local->Loader().GetDocumentLoader()->CommitSameDocumentNavigation(
      item3->Url(), WebFrameLoadType::kBackForward, item3.Get(),
      ClientRedirectPolicy::kNotClientRedirect,
      /*has_transient_user_activation=*/false, /*initiator_origin=*/nullptr,
      /*is_synchronously_committed=*/false, /*source_element=*/nullptr,
      mojom::blink::TriggeringEventInfo::kNotFromEvent,
      /*is_browser_initiated=*/true, /*has_ua_visual_transition,=*/false,
      /*soft_navigation_heuristics_task_id=*/std::nullopt);
  // The scroll offset is only applied via invoking the anchor via the main
  // lifecycle, or a forced layout.
  // TODO(chrishtr): At the moment, WebLocalFrameImpl::GetScrollOffset() does
  // not force a layout. Script-exposed scroll offset-reading methods do,
  // however. It seems wrong not to force a layout.
  EXPECT_EQ(0, web_view_impl->MainFrameImpl()->GetScrollOffset().x());
  EXPECT_GT(web_view_impl->MainFrameImpl()->GetScrollOffset().y(), 2000);
}

// Tests that scroll offset modified during fullscreen is preserved when
// exiting fullscreen.
TEST_F(WebViewTest, FullscreenNoResetScroll) {
  RegisterMockedHttpURLLoad("fullscreen_style.html");
  WebViewImpl* web_view_impl =
      web_view_helper_.InitializeAndLoad(base_url_ + "fullscreen_style.html");
  web_view_impl->MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  UpdateAllLifecyclePhases();

  // Scroll the page down.
  web_view_impl->MainFrameImpl()->SetScrollOffset(gfx::PointF(0, 2000));
  ASSERT_EQ(2000, web_view_impl->MainFrameImpl()->GetScrollOffset().y());

  // Enter fullscreen.
  LocalFrame* frame = web_view_impl->MainFrameImpl()->GetFrame();
  Element* element = frame->GetDocument()->documentElement();
  LocalFrame::NotifyUserActivation(
      frame, mojom::UserActivationNotificationType::kTest);
  Fullscreen::RequestFullscreen(*element);
  web_view_impl->DidEnterFullscreen();
  UpdateAllLifecyclePhases();

  // Assert the scroll position on the document element doesn't change.
  ASSERT_EQ(2000, web_view_impl->MainFrameImpl()->GetScrollOffset().y());

  web_view_impl->MainFrameImpl()->SetScrollOffset(gfx::PointF(0, 2100));

  web_view_impl->DidExitFullscreen();
  UpdateAllLifecyclePhases();

  EXPECT_EQ(2100, web_view_impl->MainFrameImpl()->GetScrollOffset().y());
}

// Tests that background color is read from the backdrop on fullscreen.
TEST_F(WebViewTest, FullscreenBackgroundColor) {
  RegisterMockedHttpURLLoad("fullscreen_style.html");
  WebViewImpl* web_view_impl =
      web_view_helper_.InitializeAndLoad(base_url_ + "fullscreen_style.html");
  web_view_impl->MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  UpdateAllLifecyclePhases();
  EXPECT_EQ(SK_ColorWHITE, web_view_impl->BackgroundColor());

  // Enter fullscreen.
  LocalFrame* frame = web_view_impl->MainFrameImpl()->GetFrame();
  Element* element =
      frame->GetDocument()->getElementById(AtomicString("fullscreenElement"));
  ASSERT_TRUE(element);
  LocalFrame::NotifyUserActivation(
      frame, mojom::UserActivationNotificationType::kTest);
  Fullscreen::RequestFullscreen(*element);
  web_view_impl->DidEnterFullscreen();
  UpdateAllLifecyclePhases();

  EXPECT_EQ(SK_ColorYELLOW, web_view_impl->BackgroundColor());
}

static void ExitFullscreen(Document& document) {
  Fullscreen::FullyExitFullscreen(document);
  Fullscreen::DidExitFullscreen(document);
  EXPECT_EQ(Fullscreen::FullscreenElementFrom(document), nullptr);
}

// Tests that the removal from the top layer is scheduled.
TEST_F(WebViewTest, FullscreenRemovalTiming) {
  RegisterMockedHttpURLLoad("fullscreen_style.html");
  WebViewImpl* web_view_impl =
      web_view_helper_.InitializeAndLoad(base_url_ + "fullscreen_style.html");
  web_view_impl->MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  UpdateAllLifecyclePhases();

  // Enter fullscreen.
  LocalFrame* frame = web_view_impl->MainFrameImpl()->GetFrame();
  Document* document = frame->GetDocument();
  ASSERT_TRUE(document);
  Element* element =
      document->getElementById(AtomicString("fullscreenElement"));
  ASSERT_TRUE(element);
  LocalFrame::NotifyUserActivation(
      frame, mojom::UserActivationNotificationType::kTest);
  Fullscreen::RequestFullscreen(*element);
  web_view_impl->DidEnterFullscreen();
  UpdateAllLifecyclePhases();
  EXPECT_TRUE(element->IsInTopLayer());

  ExitFullscreen(*document);
  EXPECT_TRUE(element->IsInTopLayer());
  UpdateAllLifecyclePhases();
  EXPECT_FALSE(element->IsInTopLayer());
}

class PrintWebFrameClient : public frame_test_helpers::TestWebFrameClient {
 public:
  PrintWebFrameClient() = default;

  // WebLocalFrameClient overrides:
  void ScriptedPrint() override { print_called_ = true; }

  bool PrintCalled() const { return print_called_; }

 private:
  bool print_called_ = false;
};

TEST_F(WebViewTest, PrintWithXHRInFlight) {
  PrintWebFrameClient client;
  RegisterMockedHttpURLLoad("print_with_xhr_inflight.html");
  WebViewImpl* web_view_impl = web_view_helper_.InitializeAndLoad(
      base_url_ + "print_with_xhr_inflight.html", &client, nullptr);

  ASSERT_TRUE(To<LocalFrame>(web_view_impl->GetPage()->MainFrame())
                  ->GetDocument()
                  ->LoadEventFinished());
  EXPECT_TRUE(client.PrintCalled());
  web_view_helper_.Reset();
}

static void DragAndDropURL(WebViewImpl* web_view, const std::string& url) {
  WebDragData drag_data;
  WebDragData::StringItem item;
  item.type = "text/uri-list";
  item.data = WebString::FromUTF8(url);
  drag_data.AddItem(item);

  const gfx::PointF client_point;
  const gfx::PointF screen_point;
  WebFrameWidget* widget = web_view->MainFrameImpl()->FrameWidget();
  widget->DragTargetDragEnter(drag_data, client_point, screen_point,
                              kDragOperationCopy, 0, base::DoNothing());
  widget->DragTargetDrop(drag_data, client_point, screen_point, 0,
                         base::DoNothing());
  frame_test_helpers::PumpPendingRequestsForFrameToLoad(
      web_view->MainFrameImpl());
}

TEST_F(WebViewTest, DragDropURL) {
  RegisterMockedHttpURLLoad("foo.html");
  RegisterMockedHttpURLLoad("bar.html");

  const std::string foo_url = base_url_ + "foo.html";
  const std::string bar_url = base_url_ + "bar.html";

  WebViewImpl* web_view = web_view_helper_.InitializeAndLoad(foo_url);

  ASSERT_TRUE(web_view);

  // Drag and drop barUrl and verify that we've navigated to it.
  DragAndDropURL(web_view, bar_url);
  EXPECT_EQ(bar_url,
            web_view->MainFrameImpl()->GetDocument().Url().GetString().Utf8());

  // Drag and drop fooUrl and verify that we've navigated back to it.
  DragAndDropURL(web_view, foo_url);
  EXPECT_EQ(foo_url,
            web_view->MainFrameImpl()->GetDocument().Url().GetString().Utf8());

  // Disable navigation on drag-and-drop.
  auto renderer_preferences = web_view->GetRendererPreferences();
  renderer_preferences.can_accept_load_drops = false;
  web_view->SetRendererPreferences(renderer_preferences);

  // Attempt to drag and drop to barUrl and verify that no navigation has
  // occurred.
  DragAndDropURL(web_view, bar_url);
  EXPECT_EQ(foo_url,
            web_view->MainFrameImpl()->GetDocument().Url().GetString().Utf8());
}

bool WebViewTest::SimulateGestureAtElement(WebInputEvent::Type type,
                                           Element* element) {
  if (!element || !element->GetLayoutObject())
    return false;

  DCHECK(web_view_helper_.GetWebView());
  element->scrollIntoViewIfNeeded();

  gfx::Point center =
      web_view_helper_.GetWebView()
          ->MainFrameImpl()
          ->GetFrameView()
          ->FrameToScreen(element->GetLayoutObject()->AbsoluteBoundingBoxRect())
          .CenterPoint();

  WebGestureEvent event(type, WebInputEvent::kNoModifiers,
                        WebInputEvent::GetStaticTimeStampForTests(),
                        WebGestureDevice::kTouchscreen);
  event.SetPositionInWidget(gfx::PointF(center));

  web_view_helper_.GetWebView()->MainFrameWidget()->HandleInputEvent(
      WebCoalescedInputEvent(event, ui::LatencyInfo()));
  RunPendingTasks();
  return true;
}

bool WebViewTest::SimulateGestureAtElementById(WebInputEvent::Type type,
                                               const WebString& id) {
  DCHECK(web_view_helper_.GetWebView());
  Element* element = static_cast<Element*>(
      web_view_helper_.LocalMainFrame()->GetDocument().GetElementById(id));
  return SimulateGestureAtElement(type, element);
}

WebGestureEvent WebViewTest::BuildTapEvent(
    WebInputEvent::Type type,
    int tap_event_count,
    const gfx::PointF& position_in_widget) {
  WebGestureEvent event(type, WebInputEvent::kNoModifiers,
                        WebInputEvent::GetStaticTimeStampForTests(),
                        WebGestureDevice::kTouchscreen);
  event.SetPositionInWidget(position_in_widget);

  switch (type) {
    case WebInputEvent::Type::kGestureTapDown:
      event.data.tap_down.tap_down_count = tap_event_count;
      break;
    case WebInputEvent::Type::kGestureTap:
      event.data.tap.tap_count = tap_event_count;
      break;
    default:
      break;
  }
  return event;
}

bool WebViewTest::SimulateTapEventAtElement(WebInputEvent::Type type,
                                            int tap_event_count,
                                            Element* element) {
  if (!element || !element->GetLayoutObject()) {
    return false;
  }

  DCHECK(web_view_helper_.GetWebView());
  element->scrollIntoViewIfNeeded();

  const gfx::PointF center = gfx::PointF(
      web_view_helper_.GetWebView()
          ->MainFrameImpl()
          ->GetFrameView()
          ->FrameToScreen(element->GetLayoutObject()->AbsoluteBoundingBoxRect())
          .CenterPoint());

  const WebGestureEvent event = BuildTapEvent(type, tap_event_count, center);
  web_view_helper_.GetWebView()->MainFrameWidget()->HandleInputEvent(
      WebCoalescedInputEvent(event, ui::LatencyInfo()));
  RunPendingTasks();
  return true;
}

bool WebViewTest::SimulateTapEventAtElementById(WebInputEvent::Type type,
                                                int tap_event_count,
                                                const WebString& id) {
  DCHECK(web_view_helper_.GetWebView());
  auto* element = static_cast<Element*>(
      web_view_helper_.LocalMainFrame()->GetDocument().GetElementById(id));
  return SimulateTapEventAtElement(type, tap_event_count, element);
}

ExternalDateTimeChooser* WebViewTest::GetExternalDateTimeChooser(
    WebViewImpl* web_view_impl) {
  return web_view_impl->GetChromeClient()
      .GetExternalDateTimeChooserForTesting();
}

TEST_F(WebViewTest, ClientTapHandlingNullWebViewClient) {
  // Note: this test doesn't use WebViewHelper since WebViewHelper creates an
  // internal WebViewClient on demand if the supplied WebViewClient is null.
  WebViewImpl* web_view = web_view_helper_.CreateWebView(
      /*web_view_client=*/nullptr, /*compositing_enabled=*/false);
  frame_test_helpers::TestWebFrameClient web_frame_client;
  WebLocalFrame* local_frame = WebLocalFrame::CreateMainFrame(
      web_view, &web_frame_client, nullptr, mojo::NullRemote(),
      LocalFrameToken(), DocumentToken(), nullptr);
  web_frame_client.Bind(local_frame);
  WebNonCompositedWidgetClient widget_client;
  frame_test_helpers::TestWebFrameWidget* widget =
      web_view_helper_.CreateFrameWidget(local_frame);
  widget->InitializeNonCompositing(&widget_client);
  web_view->DidAttachLocalMainFrame();

  WebGestureEvent event(WebInputEvent::Type::kGestureTap,
                        WebInputEvent::kNoModifiers,
                        WebInputEvent::GetStaticTimeStampForTests(),
                        WebGestureDevice::kTouchscreen);
  event.SetPositionInWidget(gfx::PointF(3, 8));
  EXPECT_EQ(WebInputEventResult::kNotHandled,
            web_view->MainFrameWidget()->HandleInputEvent(
                WebCoalescedInputEvent(event, ui::LatencyInfo())));
  web_view->Close();
}

TEST_F(WebViewTest, LongPressEmptyDiv) {
  RegisterMockedHttpURLLoad("long_press_empty_div.html");

  WebViewImpl* web_view = web_view_helper_.InitializeAndLoad(
      base_url_ + "long_press_empty_div.html");
  web_view->SettingsImpl()->SetAlwaysShowContextMenuOnTouch(false);
  web_view->MainFrameViewWidget()->Resize(gfx::Size(500, 300));
  UpdateAllLifecyclePhases();
  RunPendingTasks();

  WebGestureEvent event(WebInputEvent::Type::kGestureLongPress,
                        WebInputEvent::kNoModifiers,
                        WebInputEvent::GetStaticTimeStampForTests(),
                        WebGestureDevice::kTouchscreen);
  event.SetPositionInWidget(gfx::PointF(250, 150));

  EXPECT_EQ(WebInputEventResult::kNotHandled,
            web_view->MainFrameWidget()->HandleInputEvent(
                WebCoalescedInputEvent(event, ui::LatencyInfo())));
}

TEST_F(WebViewTest, LongPressEmptyDivAlwaysShow) {
  RegisterMockedHttpURLLoad("long_press_empty_div.html");

  WebViewImpl* web_view = web_view_helper_.InitializeAndLoad(
      base_url_ + "long_press_empty_div.html");
  web_view->SettingsImpl()->SetAlwaysShowContextMenuOnTouch(true);
  web_view->MainFrameViewWidget()->Resize(gfx::Size(500, 300));
  UpdateAllLifecyclePhases();
  RunPendingTasks();

  WebGestureEvent event(WebInputEvent::Type::kGestureLongPress,
                        WebInputEvent::kNoModifiers,
                        WebInputEvent::GetStaticTimeStampForTests(),
                        WebGestureDevice::kTouchscreen);
  event.SetPositionInWidget(gfx::PointF(250, 150));

  EXPECT_EQ(WebInputEventResult::kHandledSystem,
            web_view->MainFrameWidget()->HandleInputEvent(
                WebCoalescedInputEvent(event, ui::LatencyInfo())));
}

TEST_F(WebViewTest, LongPressObject) {
  RegisterMockedHttpURLLoad("long_press_object.html");

  WebViewImpl* web_view =
      web_view_helper_.InitializeAndLoad(base_url_ + "long_press_object.html");
  web_view->SettingsImpl()->SetAlwaysShowContextMenuOnTouch(true);
  web_view->MainFrameViewWidget()->Resize(gfx::Size(500, 300));
  UpdateAllLifecyclePhases();
  RunPendingTasks();

  WebGestureEvent event(WebInputEvent::Type::kGestureLongPress,
                        WebInputEvent::kNoModifiers,
                        WebInputEvent::GetStaticTimeStampForTests(),
                        WebGestureDevice::kTouchscreen);
  event.SetPositionInWidget(gfx::PointF(10, 10));

  EXPECT_NE(WebInputEventResult::kHandledSystem,
            web_view->MainFrameWidget()->HandleInputEvent(
                WebCoalescedInputEvent(event, ui::LatencyInfo())));

  auto* element = To<HTMLElem
```