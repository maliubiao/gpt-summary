Response:
The user wants a summary of the functionality of the provided C++ code snippet from `local_frame_view.cc`. The summary should cover:

1. **Core functions:** What does this code do?
2. **Relationship to web technologies:** How does it interact with JavaScript, HTML, and CSS?  Provide examples.
3. **Logical reasoning:** If there are any conditional code blocks, explain them with example inputs and outputs.
4. **Common user/programming errors:**  Point out potential mistakes related to this code.
5. **Overall summary:**  A concise description of the code's purpose.

Let's break down the code section by section and address each of these points.

**Code Section Analysis:**

* **`performPostLayoutTasks()`:**  This function executes tasks after the layout is calculated. It updates image priorities, draggable regions, sticky elements, selection, and hover states. It also schedules plugin updates and visual viewport resize events.
* **`InputEventsScaleFactor()`:**  Calculates the scaling factor for input events based on page zoom and emulation settings.
* **`NotifyPageThatContentAreaWillPaint()`:**  Notifies the page when the content area is about to be painted, primarily to inform scrollbars.
* **`UpdateDocumentDraggableRegions()`:**  Collects and updates the draggable regions of the document based on layout.
* **`DidAttachDocument()`:**  Handles actions when a document is attached to the frame, including initializing the root scroller for the main frame.
* **`InitializeRootScroller()`:**  Sets up the root scroller, which manages scrolling for the main frame.
* **`DocumentBackgroundColor()`:** Determines the background color of the document, considering fullscreen elements and dark mode.
* **`WillBeRemovedFromFrame()`:**  Handles cleanup when the frame view is being removed.
* **`IsUpdatingLifecycle()`:** Checks if a lifecycle update is currently in progress.
* **`ParentFrameView()`:**  Returns the parent frame view, if any.
* **`GetLayoutEmbeddedContent()`:** Returns the layout object associated with embedded content.
* **`LoadAllLazyLoadedIframes()`:**  Forces the loading of lazy-loaded iframes.
* **`UpdateGeometriesIfNeeded()`:** Updates the geometry of child frame views and plugins.
* **`UpdateAllLifecyclePhases()` and related functions (`UpdateAllLifecyclePhasesForTest`, `UpdateLifecycleToCompositingInputsClean`, `UpdateAllLifecyclePhasesExceptPaint`, `DryRunPaintingForPrerender`, `UpdateLifecyclePhasesForPrinting`, `UpdateLifecycleToLayoutClean`):** These functions manage the different phases of the document lifecycle (style, layout, paint, etc.).
* **`InvalidationDisallowedScope`:** A utility class to temporarily disable layout invalidation.
* **`ScheduleVisualUpdateForVisualOverflowIfNeeded()` and `ScheduleVisualUpdateForPaintInvalidationIfNeeded()`:** Schedule visual updates when needed due to overflow or paint invalidation.
* **`NotifyResizeObservers()`:**  Notifies registered resize observers about element size changes.
* **`LocalFrameTreeAllowsThrottling()` and `LocalFrameTreeForcesThrottling()`:** Check if rendering throttling is allowed or forced for the frame tree.
* **`PrepareForLifecycleUpdateRecursive()`:** Prepares the frame tree for a lifecycle update.
* **`UpdateLifecyclePhases()`:** The central function for managing document lifecycle updates.
* **`UpdateLifecyclePhasesInternal()`:** The internal implementation of `UpdateLifecyclePhases`.
* **`RunScrollSnapshotClientSteps()`:** Handles steps related to scroll snapshot clients for CSS Scroll Timelines.
* **`RunViewTransitionSteps()`:** Executes steps for CSS View Transitions.
* **`RunResizeObserverSteps()`:**  Executes steps related to processing resize observer notifications.
* **`ClearResizeObserverLimit()`:** Resets the limit for resize observer notifications.
* **`ShouldDeferLayoutSnap()`:** Determines if layout snapping should be deferred.
* **`EnqueueScrollSnapChangingFromImplIfNecessary()`:**  Enqueues events related to scroll snap changes initiated by the compositor.
* **`RunStyleAndLayoutLifecyclePhases()`:** Executes the style and layout phases of the document lifecycle.

**Relationship to Web Technologies:**

* **JavaScript:**  Functions like `NotifyResizeObservers` directly interact with JavaScript APIs like the Resize Observer API. The lifecycle updates are triggered by various events, some of which can originate from JavaScript.
* **HTML:**  `UpdateDocumentDraggableRegions` relates to the `draggable` attribute in HTML. `LoadAllLazyLoadedIframes` interacts with the `loading="lazy"` attribute on `<iframe>` elements.
* **CSS:** `DocumentBackgroundColor` resolves CSS background colors. The entire lifecycle management process is heavily influenced by CSS changes and how they affect layout and rendering. `RunScrollSnapshotClientSteps` relates to CSS Scroll Timelines. `RunViewTransitionSteps` is for CSS View Transitions.

**Logical Reasoning (Hypothetical Inputs and Outputs):**

* **`UpdateDocumentDraggableRegions()`:**
    * **Input:** A document with elements having the `draggable="true"` attribute and corresponding CSS styles.
    * **Output:** A vector of `DraggableRegionValue` objects representing the coordinates and properties of the draggable elements.
* **`DocumentBackgroundColor()`:**
    * **Input:** A document with a CSS rule `body { background-color: red; }`.
    * **Output:** A `Color` object representing red.
    * **Input:** A document with a fullscreen element and a backdrop with `background-color: blue;`. The base background color is white.
    * **Output:** A `Color` object representing a blend of white and blue.
* **`ShouldThrottleRendering()` within `UpdateLifecyclePhases()`:**
    * **Input:** A frame is currently off-screen or in a background tab. `allow_throttling_` is true.
    * **Output:** `true`, the lifecycle update might be skipped or deferred.
    * **Input:** A frame is visible and active.
    * **Output:** `false`, the lifecycle update will proceed.

**Common User/Programming Errors:**

* **Incorrectly setting the `draggable` attribute:** Forgetting to add necessary event listeners in JavaScript to handle drag-and-drop operations after making an element draggable.
* **Misunderstanding lifecycle phases:**  Making assumptions about when certain actions will occur during the lifecycle (e.g., trying to access layout information before the layout phase).
* **Infinite resize observer loops:**  Creating resize observer callbacks that modify the size of observed elements, leading to an infinite loop of notifications. The code includes mechanisms to detect and handle such loops.
* **Not accounting for throttling:**  Writing code that assumes immediate rendering updates, while the browser might be throttling rendering for off-screen frames.

**Overall Summary of the Provided Code Section:**

This section of `local_frame_view.cc` focuses on the **post-layout processing and the management of the document lifecycle**. It handles tasks that need to occur after the initial layout calculation, such as updating draggable regions, sticky elements, and the selection. More importantly, it contains the core logic for orchestrating the various phases of the document lifecycle (style, layout, compositing inputs, pre-paint), including mechanisms for throttling rendering and handling interactions with JavaScript APIs like Resize Observer and CSS features like View Transitions and Scroll Timelines. It ensures that the document is in the correct state for rendering and user interaction.

```cpp
void LocalFrameView::performPostLayoutTasks(bool visual_viewport_size_changed) {
  // Prevent reentrant calls.
  DCHECK(!IsInPerformLayout());
  TRACE_EVENT0("blink,benchmark", "LocalFrameView::performPostLayoutTasks");

  TRACE_EVENT_OBJECT_SNAPSHOT_WITH_ID(
      TRACE_DISABLED_BY_DEFAULT("blink.debug.layout.trees"), "LayoutTree", this,
      TracedLayoutObject::Create(*GetLayoutView(), true));
  layout_count_for_testing_++;
  Document* document = GetFrame().GetDocument();
  DCHECK(document);

  document->Fetcher()->UpdateAllImageResourcePriorities();
  UpdateDocumentDraggableRegions();
  ExecutePendingStickyUpdates();

  frame_->Selection().DidLayout();

  FontFaceSetDocument::DidLayout(*document);
  // Fire a fake a mouse move event to update hover state and mouse cursor, and
  // send the right mouse out/over events.
  // TODO(lanwei): we should check whether the mouse is inside the frame before
  // dirtying the hover state.
  frame_->LocalFrameRoot().GetEventHandler().MarkHoverStateDirty();

  UpdateGeometriesIfNeeded();

  // Plugins could have torn down the page inside updateGeometries().
  if (!GetLayoutView())
    return;

  ScheduleUpdatePluginsIfNecessary();
  if (visual_viewport_size_changed && !document->Printing())
    frame_->GetDocument()->EnqueueVisualViewportResizeEvent();
}

float LocalFrameView::InputEventsScaleFactor() const {
  float page_scale = frame_->GetPage()->GetVisualViewport().Scale();
  return page_scale *
         frame_->GetPage()->GetChromeClient().InputEventsScaleForEmulation();
}

void LocalFrameView::NotifyPageThatContentAreaWillPaint() const {
  Page* page = frame_->GetPage();
  if (!page)
    return;

  for (const auto& scrollable_area : scrollable_areas_.Values()) {
    if (!scrollable_area->ScrollbarsCanBeActive())
      continue;

    scrollable_area->ContentAreaWillPaint();
  }
}

void LocalFrameView::UpdateDocumentDraggableRegions() const {
  Document* document = frame_->GetDocument();
  if (!document->HasDraggableRegions() ||
      !frame_->GetPage()->GetChromeClient().SupportsDraggableRegions()) {
    return;
  }

  Vector<DraggableRegionValue> new_regions;
  CollectDraggableRegions(*(document->GetLayoutBox()), new_regions);
  if (new_regions == document->DraggableRegions()) {
    return;
  }

  document->SetDraggableRegions(new_regions);
  frame_->GetPage()->GetChromeClient().DraggableRegionsChanged();
}

void LocalFrameView::DidAttachDocument() {
  Page* page = frame_->GetPage();
  DCHECK(page);

  VisualViewport& visual_viewport = page->GetVisualViewport();

  if (frame_->IsMainFrame() && visual_viewport.IsActiveViewport()) {
    // If this frame is provisional it's not yet the Page's main frame. In that
    // case avoid creating a root scroller as it has Page-global effects; it
    // will be initialized when the frame becomes the Page's main frame.
    if (!frame_->IsProvisional())
      InitializeRootScroller();
  }

  if (frame_->IsMainFrame()) {
    // Allow for commits to be deferred because this is a new document.
    have_deferred_main_frame_commits_ = false;
  }
}

void LocalFrameView::InitializeRootScroller() {
  Page* page = frame_->GetPage();
  DCHECK(page);

  DCHECK_EQ(frame_, page->MainFrame());
  DCHECK(frame_->GetDocument());
  DCHECK(frame_->GetDocument()->IsActive());

  VisualViewport& visual_viewport = frame_->GetPage()->GetVisualViewport();
  DCHECK(visual_viewport.IsActiveViewport());

  ScrollableArea* layout_viewport = LayoutViewport();
  DCHECK(layout_viewport);

  // This method may be called multiple times during loading. If the root
  // scroller is already initialized this call will be a no-op.
  if (viewport_scrollable_area_)
    return;

  auto* root_frame_viewport = MakeGarbageCollected<RootFrameViewport>(
      visual_viewport, *layout_viewport);
  viewport_scrollable_area_ = root_frame_viewport;

  DCHECK(frame_->GetDocument());
  page->GlobalRootScrollerController().Initialize(*root_frame_viewport,
                                                  *frame_->GetDocument());
}

Color LocalFrameView::DocumentBackgroundColor() {
  // The LayoutView's background color is set in
  // StyleResolver::PropagateStyleToViewport(). Blend this with the base
  // background color of the LocalFrameView. This should match the color drawn
  // by ViewPainter::paintBoxDecorationBackground.
  Color result = BaseBackgroundColor();

  bool blend_with_base = true;
  LayoutObject* background_source = GetLayoutView();

  // If we have a fullscreen element grab the fullscreen color from the
  // backdrop.
  if (Document* doc = frame_->GetDocument()) {
    if (Element* element = Fullscreen::FullscreenElementFrom(*doc)) {
      if (LayoutObject* layout_object =
              element->PseudoElementLayoutObject(kPseudoIdBackdrop)) {
        background_source = layout_object;
      }
      if (doc->IsXrOverlay()) {
        // Use the fullscreened element's background directly. Don't bother
        // blending with the backdrop since that's transparent.
        blend_with_base = false;
        if (LayoutObject* layout_object = element->GetLayoutObject())
          background_source = layout_object;
      }
    }
  }

  if (!background_source)
    return result;

  Color doc_bg =
      background_source->ResolveColor(GetCSSPropertyBackgroundColor());
  if (background_source->StyleRef().ColorSchemeForced()) {
    // TODO(https://crbug.com/1351544): The DarkModeFilter operate on SkColor4f,
    // and DocumentBackgroundColor should return an SkColor4f.
    doc_bg = Color::FromSkColor4f(EnsureDarkModeFilter().InvertColorIfNeeded(
        doc_bg.toSkColor4f(), DarkModeFilter::ElementRole::kBackground));
  }
  if (blend_with_base)
    return result.Blend(doc_bg);
  return doc_bg;
}

void LocalFrameView::WillBeRemovedFromFrame() {
  if (paint_artifact_compositor_)
    paint_artifact_compositor_->WillBeRemovedFromFrame();
}

bool LocalFrameView::IsUpdatingLifecycle() const {
  LocalFrameView* root_view = GetFrame().LocalFrameRoot().View();
  DCHECK(root_view);
  return root_view->target_state_ != DocumentLifecycle::kUninitialized;
}

LocalFrameView* LocalFrameView::ParentFrameView() const {
  if (!IsAttached())
    return nullptr;

  Frame* parent_frame = frame_->Tree().Parent();
  if (auto* parent_local_frame = DynamicTo<LocalFrame>(parent_frame))
    return parent_local_frame->View();

  return nullptr;
}

LayoutEmbeddedContent* LocalFrameView::GetLayoutEmbeddedContent() const {
  return frame_->OwnerLayoutObject();
}

bool LocalFrameView::LoadAllLazyLoadedIframes() {
  bool result = false;
  ForAllChildViewsAndPlugins([&](EmbeddedContentView& view) {
    if (auto* embed = view.GetLayoutEmbeddedContent()) {
      if (auto* node = embed->GetNode()) {
        if (auto* frame_owner = DynamicTo<HTMLFrameOwnerElement>(node)) {
          result = result || frame_owner->LoadImmediatelyIfLazy();
        }
      }
    }
  });
  return result;
}

void LocalFrameView::UpdateGeometriesIfNeeded() {
  if (!needs_update_geometries_)
    return;
  needs_update_geometries_ = false;
  HeapVector<Member<EmbeddedContentView>> views;
  ForAllChildViewsAndPlugins(
      [&](EmbeddedContentView& view) { views.push_back(view); });

  for (const auto& view : views) {
    // Script or plugins could detach the frame so abort processing if that
    // happens.
    if (!GetLayoutView())
      break;

    view->UpdateGeometry();
  }
  // Explicitly free the backing store to avoid memory regressions.
  // TODO(bikineev): Revisit after young generation is there.
  views.clear();
}

bool LocalFrameView::UpdateAllLifecyclePhases(DocumentUpdateReason reason) {
  AllowThrottlingScope allow_throttling(*this);
  bool updated = GetFrame().LocalFrameRoot().View()->UpdateLifecyclePhases(
      DocumentLifecycle::kPaintClean, reason);

#if DCHECK_IS_ON()
  if (updated) {
    // This function should return true iff all non-throttled frames are in the
    // kPaintClean lifecycle state.
    ForAllNonThrottledLocalFrameViews([](LocalFrameView& frame_view) {
      DCHECK_EQ(frame_view.Lifecycle().GetState(),
                DocumentLifecycle::kPaintClean);
    });

    // A required intersection observation should run throttled frames to
    // kLayoutClean.
    ForAllThrottledLocalFrameViews([](LocalFrameView& frame_view) {
      DCHECK(frame_view.intersection_observation_state_ != kRequired ||
             frame_view.IsDisplayLocked() ||
             frame_view.Lifecycle().GetState() >=
                 DocumentLifecycle::kLayoutClean);
    });
  }
#endif

  return updated;
}

bool LocalFrameView::UpdateAllLifecyclePhasesForTest() {
  bool result = UpdateAllLifecyclePhases(DocumentUpdateReason::kTest);
  RunPostLifecycleSteps();
  return result;
}

bool LocalFrameView::UpdateLifecycleToCompositingInputsClean(
    DocumentUpdateReason reason) {
  return GetFrame().LocalFrameRoot().View()->UpdateLifecyclePhases(
      DocumentLifecycle::kCompositingInputsClean, reason);
}

bool LocalFrameView::UpdateAllLifecyclePhasesExceptPaint(
    DocumentUpdateReason reason) {
  return GetFrame().LocalFrameRoot().View()->UpdateLifecyclePhases(
      DocumentLifecycle::kPrePaintClean, reason);
}

void LocalFrameView::DryRunPaintingForPrerender() {
  TRACE_EVENT("blink", "DryRunPaintingForPrerender");
  CHECK(GetFrame().GetDocument()->IsPrerendering());
  bool update_result =
      GetFrame().LocalFrameRoot().View()->UpdateLifecyclePhases(
          DocumentLifecycle::kPrePaintClean, DocumentUpdateReason::kPrerender);
  if (!update_result) {
    return;
  }
  if (paint_artifact_compositor_) {
    // If `paint_artifact_compositor_` has been created, PaintArtifact might be
    // referred in its `pending_layers`, and since creating the paint tree again
    // may discard the old PaintArtifact, which breaks the reference
    // relationship down, we should not build the tree again. It is very
    // unlikely to reach here, just to avoid race conditions.
    return;
  }
  std::optional<PaintController> paint_controller;
  PaintTree(PaintBenchmarkMode::kNormal, paint_controller);
  return;
}

void LocalFrameView::UpdateLifecyclePhasesForPrinting() {
  auto* local_frame_view_root = GetFrame().LocalFrameRoot().View();
  local_frame_view_root->UpdateLifecyclePhases(
      DocumentLifecycle::kPrePaintClean, DocumentUpdateReason::kPrinting);

  if (local_frame_view_root != this && !IsAttached()) {
    // We are printing a detached frame which is not reached above. Make sure
    // the frame is ready for painting.
    UpdateLifecyclePhases(DocumentLifecycle::kPrePaintClean,
                          DocumentUpdateReason::kPrinting);
  }
}

bool LocalFrameView::UpdateLifecycleToLayoutClean(DocumentUpdateReason reason) {
  return GetFrame().LocalFrameRoot().View()->UpdateLifecyclePhases(
      DocumentLifecycle::kLayoutClean, reason);
}

LocalFrameView::InvalidationDisallowedScope::InvalidationDisallowedScope(
    const LocalFrameView& frame_view)
    : resetter_(&frame_view.GetFrame()
                     .LocalFrameRoot()
                     .View()
                     ->invalidation_disallowed_,
                true) {
  DCHECK_EQ(instance_count_, 0);
  ++instance_count_;
}

LocalFrameView::InvalidationDisallowedScope::~InvalidationDisallowedScope() {
  --instance_count_;
}

void LocalFrameView::ScheduleVisualUpdateForVisualOverflowIfNeeded() {
  LocalFrame& local_frame_root = GetFrame().LocalFrameRoot();
  // We need a full lifecycle update to recompute visual overflow if we are
  // not already targeting kPaintClean or we have already passed
  // CompositingInputs in the current frame.
  if (local_frame_root.View()->target_state_ < DocumentLifecycle::kPaintClean ||
      Lifecycle().GetState() >= DocumentLifecycle::kCompositingInputsClean) {
    // Schedule visual update to process the paint invalidation in the next
    // cycle.
    local_frame_root.ScheduleVisualUpdateUnlessThrottled();
  }
  // Otherwise the visual overflow will be updated in the compositing inputs
  // phase of this lifecycle.
}

void LocalFrameView::ScheduleVisualUpdateForPaintInvalidationIfNeeded() {
  LocalFrame& local_frame_root = GetFrame().LocalFrameRoot();
  // We need a full lifecycle update to clear pending paint invalidations.
  if (local_frame_root.View()->target_state_ < DocumentLifecycle::kPaintClean ||
      Lifecycle().GetState() >= DocumentLifecycle::kPrePaintClean) {
    // Schedule visual update to process the paint invalidation in the next
    // cycle.
    local_frame_root.ScheduleVisualUpdateUnlessThrottled();
  }
  // Otherwise the paint invalidation will be handled in the pre-paint and paint
  // phase of this full lifecycle update.
}

bool LocalFrameView::NotifyResizeObservers() {
  // Return true if lifecycles need to be re-run
  TRACE_EVENT0("blink,benchmark", "LocalFrameView::NotifyResizeObservers");

  // Controller exists only if ResizeObserver was created.
  ResizeObserverController* resize_controller =
      ResizeObserverController::FromIfExists(*GetFrame().DomWindow());
  if (!resize_controller)
    return false;

  size_t min_depth = resize_controller->GatherObservations();

  if (min_depth != ResizeObserverController::kDepthBottom) {
    resize_controller->DeliverObservations();
  } else {
    // Observation depth limit reached
    if (resize_controller->SkippedObservations() &&
        !resize_controller->IsLoopLimitErrorDispatched()) {
      resize_controller->ClearObservations();

      if (auto* script_state = ToScriptStateForMainWorld(frame_->DomWindow())) {
        ScriptState::Scope scope(script_state);
        const String message =
            "ResizeObserver loop completed with undelivered notifications.";
        ScriptValue value(script_state->GetIsolate(),
                          V8String(script_state->GetIsolate(), message));
        // TODO(pdr): We could report the source location of one of the
        // observers which had skipped observations.
        ErrorEvent* error = ErrorEvent::Create(message, CaptureSourceLocation(),
                                               value, &script_state->World());
        // We're using |SanitizeScriptErrors::kDoNotSanitize| as the error is
        // made by blink itself.
        // TODO(yhirano): Reconsider this.
        frame_->DomWindow()->DispatchErrorEvent(
            error, SanitizeScriptErrors::kDoNotSanitize);
      }

      // Ensure notifications will get delivered in next cycle.
      ScheduleAnimation();
      resize_controller->SetLoopLimitErrorDispatched(true);
    }
    if (Lifecycle().GetState() >= DocumentLifecycle::kPrePaintClean)
      return false;
  }

  // Lifecycle needs to be run again because Resize Observer affected layout
  return true;
}

bool LocalFrameView::LocalFrameTreeAllowsThrottling() const {
  if (LocalFrameView* root_view = GetFrame().LocalFrameRoot().View())
    return root_view->allow_throttling_;
  return false;
}

bool LocalFrameView::LocalFrameTreeForcesThrottling() const {
  if (LocalFrameView* root_view = GetFrame().LocalFrameRoot().View())
    return root_view->force_throttling_;
  return false;
}

void LocalFrameView::PrepareForLifecycleUpdateRecursive() {
  // We will run lifecycle phases for LocalFrameViews that are unthrottled; or
  // are throttled but require IntersectionObserver steps to run.
  if (!ShouldThrottleRendering() ||
      intersection_observation_state_ == kRequired) {
    Lifecycle().EnsureStateAtMost(DocumentLifecycle::kVisualUpdatePending);
    ForAllChildLocalFrameViews([](LocalFrameView& child) {
      child.PrepareForLifecycleUpdateRecursive();
    });
  }
}

// TODO(leviw): We don't assert lifecycle information from documents in child
// WebPluginContainerImpls.
bool LocalFrameView::UpdateLifecyclePhases(
    DocumentLifecycle::LifecycleState target_state,
    DocumentUpdateReason reason) {
  // If the lifecycle is postponed, which can happen if the inspector requests
  // it, then we shouldn't update any lifecycle phases.
  if (frame_->GetDocument() &&
      frame_->GetDocument()->Lifecycle().LifecyclePostponed()) [[unlikely]] {
    return false;
  }

  // Prevent reentrance.
  // TODO(vmpstr): Should we just have a DCHECK instead here?
  if (IsUpdatingLifecycle()) [[unlikely]] {
    DUMP_WILL_BE_NOTREACHED()
        << "LocalFrameView::updateLifecyclePhasesInternal() reentrance";
    return false;
  }

  // This must be called from the root frame, or a detached frame for printing,
  // since it recurses down, not up. Otherwise the lifecycles of the frames
  // might be out of sync.
  DCHECK(frame_->IsLocalRoot() || !IsAttached());

  DCHECK(LocalFrameTreeAllowsThrottling() ||
         (target_state < DocumentLifecycle::kPaintClean));

  // Only the following target states are supported.
  DCHECK(target_state == DocumentLifecycle::kLayoutClean ||
         target_state == DocumentLifecycle::kCompositingInputsClean ||
         target_state == DocumentLifecycle::kPrePaintClean ||
         target_state == DocumentLifecycle::kPaintClean);

  // If the document is not active then it is either not yet initialized, or it
  // is stopping. In either case, we can't reach one of the supported target
  // states.
  if (!frame_->GetDocument()->IsActive())
    return false;

  // If we're throttling and we aren't required to run the IntersectionObserver
  // steps, then we don't need to update lifecycle phases. The throttling status
  // will get updated in RunPostLifecycleSteps().
  if (ShouldThrottleRendering() &&
      intersection_observation_state_ < kRequired) {
    return Lifecycle().GetState() == target_state;
  }

  PrepareForLifecycleUpdateRecursive();

  // This is used to guard against reentrance. It is also used in conjunction
  // with the current lifecycle state to determine which phases are yet to run
  // in this cycle. Note that this may change the return value of
  // ShouldThrottleRendering(), hence it cannot be moved before the preceeding
  // code, which relies on the prior value of ShouldThrottleRendering().
  base::AutoReset<DocumentLifecycle::LifecycleState> target_state_scope(
      &target_state_, target_state);

  lifecycle_data_.start_time = base::TimeTicks::Now();
  ++lifecycle_data_.count;

  if (target_state == DocumentLifecycle::kPaintClean) {
    {
      TRACE_EVENT0("blink", "LocalFrameView::WillStartLifecycleUpdate");

      ForAllNonThrottledLocalFrameViews([](LocalFrameView& frame_view) {
        auto lifecycle_observers = frame_view.lifecycle_observers_;
        for (auto& observer : lifecycle_observers)
          observer->WillStartLifecycleUpdate(frame_view);
      });
    }

    {
      TRACE_EVENT0(
          "blink",
          "LocalFrameView::UpdateLifecyclePhases - start of lifecycle tasks");
      ForAllNonThrottledLocalFrameViews([](LocalFrameView& frame_view) {
        WTF::Vector<base::OnceClosure> tasks;
        frame_view.start_of_lifecycle_tasks_.swap(tasks);
        for (auto& task : tasks)
          std::move(task).Run();
      });
    }
  }

  std::optional<base::AutoReset<bool>> force_debug_info;
  if (reason == DocumentUpdateReason::kTest)
    force_debug_info.emplace(&paint_debug_info_enabled_, true);

  // Run the lifecycle updates.
  UpdateLifecyclePhasesInternal(target_state);

  if (target_state == DocumentLifecycle::kPaintClean) {
    TRACE_EVENT0("blink", "LocalFrameView::DidFinishLifecycleUpdate");

    ForAllNonThrottledLocalFrameViews([](LocalFrameView& frame_view) {
      auto lifecycle_observers = frame_view.lifecycle_observers_;
      for (auto& observer : lifecycle_observers)
        observer->DidFinishLifecycleUpdate(frame_view);
    });
    if (frame_->GetWidgetForLocalRoot() &&
        RuntimeEnabledFeatures::ReportVisibleLineBoundsEnabled()) {
      frame_->GetWidgetForLocalRoot()->UpdateLineBounds();
    }
  }

  // Hit testing metrics include the entire time processing a document update
  // in preparation for a hit test.
  if (reason == DocumentUpdateReason::kHitTest) {
    if (auto* metrics_aggregator = GetUkmAggregator()) {
      metrics_aggregator->RecordTimerSample(
          static_cast<size_t>(LocalFrameUkmAggregator::kHitTestDocumentUpdate),
          lifecycle_data_.start_time, base::TimeTicks::Now());
    }
  }

  return Lifecycle().GetState() == target_state;
}

void LocalFrameView::UpdateLifecyclePhasesInternal(
    DocumentLifecycle::LifecycleState target_state) {
  // TODO(https://crbug.com/1196853): Switch to ScriptForbiddenScope once
  // failures are fixed.
  BlinkLifecycleScopeWillBeScriptForbidden forbid_script;

  // RunScrollSnapshotClientSteps must not run more than once.
  bool should_run_scroll_snapshot_client_steps = true;

  // Run style, layout, compositing and prepaint lifecycle phases and deliver
  // resize observations if required. Resize observer callbacks/delegates have
  // the potential to dirty layout (until loop limit is reached) and therefore
  // the above lifecycle phases need to be re-run until the limit is reached
  // or no layout is pending.
  // Note that after ResizeObserver has settled, we also run intersection
  // observations that need to be delievered in post-layout. This process can
  // also dirty layout, which will run this loop again.

  // A LocalFrameView can be unthrottled at this point, but become throttled as
  // it advances through lifecycle stages. If that happens, it will prevent
  // subsequent passes through the loop from updating the newly-throttled views.
  // To avoid that, we lock in the set of unthrottled views before entering the
  // loop.
  HeapVector<Member<LocalFrameView>> unthrottled_frame_views;
  ForAllNonThrottledLocalFrameViews(
      [&unthrottled_frame_views](LocalFrameView& frame_view) {
        unthrottled_frame_views.push_back(&frame_view);
      });

  while (true) {
    for (LocalFrameView* frame_view : unthrottled_frame_views) {
      // RunResizeObserverSteps may run arbitrary script, which can cause a
      // frame to become detached.
      if (frame_view->GetFrame().IsAttached()) {
        frame_view->Lifecycle().EnsureStateAtMost(
            DocumentLifecycle::kVisualUpdatePending);
      }
    }
    bool run_more_lifecycle_phases =
        RunStyleAndLayoutLifecyclePhases(target_state);
    if (!run_more_lifecycle_phases)
      return;
    DCHECK(Lifecycle().GetState() >= DocumentLifecycle::kLayoutClean);

    // ScrollSnapshotClients may be associated with scrollers that never had a
    // chance to get a layout box at the time style was calculated; when this
    // situation happens, RunScrollTimelineSteps will re-snapshot all affected
    // clients and dirty style for associated effect targets.
    //
    // https://github.com/w3c/csswg-drafts/issues/5261
    if (should_run_scroll_snapshot_client_steps) {
      should_run_scroll_snapshot_client_steps = false;
      bool needs_to_repeat_lifecycle = RunScrollSnapshotClientSteps();
      if (needs_to_repeat_lifecycle)
        continue;
    }

    if (!GetLayoutView())
      return;

    {
      // We need scoping braces here because this
      // DisallowLayoutInvalidationScope is meant to be in effect during
      // pre-paint, but not during ResizeObserver or ViewTransition.
#if DCHECK_IS_ON()
      DisallowLayoutInvalidationScope disallow_layout_invalidation(this);
#endif

      DEVTOOLS_TIMELINE_TRACE_EVENT_INSTANT_WITH_CATEGORIES(
          TRACE_DISABLED_BY_DEFAULT("devtools.timeline"), "SetLayerTreeId",
          inspector_set_layer_tree_id::Data, frame_.Get());
      // The Compositing Inputs lifecycle phase should be integrated into the
      // PrePaint lifecycle phase in the future. The difference between these
      // two stages is not relevant to web developers, so include them both
      // under PrePaint.
      DEVTOOLS_TIMELINE_TRACE_EVENT("PrePaint", inspector_pre_paint_event::Data,
                                    frame_.Get());
      run_more_lifecycle_phases =
          RunCompositingInputsLifecyclePhase(target_state);
      if (!run_more_lifecycle_phases)
        return;

      run_more_lifecycle_phases = RunPrePaintLifecyclePhase(target_state);
    }

    if (!run_more_lifecycle_phases) {
      // If we won't be proceeding to paint, update view transition stylesheet
      // here.
      bool needs_to_repeat_lifecycle = RunViewTransitionSteps(target_state);
      if (needs_to_repeat_lifecycle)
        continue;
    }

      DCHECK(ShouldThrottleRendering() ||
             Lifecycle().GetState() >= DocumentLifecycle::kPrePaintClean);
      if (ShouldThrottleRendering() || !run_more_lifecycle_phases)
        return;

    // Some features may require several passes over style and layout
    // within the same lifecycle update.
    bool needs_to_repeat_lifecycle = false;

    // ResizeObserver and post-layout IntersectionObserver observation
    // deliveries may dirty style and layout. RunResizeObserverSteps will return
    // true if any observer ran that may have dirtied style or layout;
    // RunPostLayoutIntersectionObserverSteps will return true if any
    // observations led to content-visibility intersection changing visibility
    // state synchronously (which happens on the first intersection
    // observeration of a context).
    //
    // Note that we run the content-visibility intersection observation first.
    // The idea is that we want to synchronously determine the initial,
    // first-time-rendered state of on- or off-screen `content-visibility:
    
### 提示词
```
这是目录为blink/renderer/core/frame/local_frame_view.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第3部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
t() call.
  DCHECK(!IsInPerformLayout());
  TRACE_EVENT0("blink,benchmark", "LocalFrameView::performPostLayoutTasks");

  TRACE_EVENT_OBJECT_SNAPSHOT_WITH_ID(
      TRACE_DISABLED_BY_DEFAULT("blink.debug.layout.trees"), "LayoutTree", this,
      TracedLayoutObject::Create(*GetLayoutView(), true));
  layout_count_for_testing_++;
  Document* document = GetFrame().GetDocument();
  DCHECK(document);

  document->Fetcher()->UpdateAllImageResourcePriorities();
  UpdateDocumentDraggableRegions();
  ExecutePendingStickyUpdates();

  frame_->Selection().DidLayout();

  FontFaceSetDocument::DidLayout(*document);
  // Fire a fake a mouse move event to update hover state and mouse cursor, and
  // send the right mouse out/over events.
  // TODO(lanwei): we should check whether the mouse is inside the frame before
  // dirtying the hover state.
  frame_->LocalFrameRoot().GetEventHandler().MarkHoverStateDirty();

  UpdateGeometriesIfNeeded();

  // Plugins could have torn down the page inside updateGeometries().
  if (!GetLayoutView())
    return;

  ScheduleUpdatePluginsIfNecessary();
  if (visual_viewport_size_changed && !document->Printing())
    frame_->GetDocument()->EnqueueVisualViewportResizeEvent();
}

float LocalFrameView::InputEventsScaleFactor() const {
  float page_scale = frame_->GetPage()->GetVisualViewport().Scale();
  return page_scale *
         frame_->GetPage()->GetChromeClient().InputEventsScaleForEmulation();
}

void LocalFrameView::NotifyPageThatContentAreaWillPaint() const {
  Page* page = frame_->GetPage();
  if (!page)
    return;

  for (const auto& scrollable_area : scrollable_areas_.Values()) {
    if (!scrollable_area->ScrollbarsCanBeActive())
      continue;

    scrollable_area->ContentAreaWillPaint();
  }
}

void LocalFrameView::UpdateDocumentDraggableRegions() const {
  Document* document = frame_->GetDocument();
  if (!document->HasDraggableRegions() ||
      !frame_->GetPage()->GetChromeClient().SupportsDraggableRegions()) {
    return;
  }

  Vector<DraggableRegionValue> new_regions;
  CollectDraggableRegions(*(document->GetLayoutBox()), new_regions);
  if (new_regions == document->DraggableRegions()) {
    return;
  }

  document->SetDraggableRegions(new_regions);
  frame_->GetPage()->GetChromeClient().DraggableRegionsChanged();
}

void LocalFrameView::DidAttachDocument() {
  Page* page = frame_->GetPage();
  DCHECK(page);

  VisualViewport& visual_viewport = page->GetVisualViewport();

  if (frame_->IsMainFrame() && visual_viewport.IsActiveViewport()) {
    // If this frame is provisional it's not yet the Page's main frame. In that
    // case avoid creating a root scroller as it has Page-global effects; it
    // will be initialized when the frame becomes the Page's main frame.
    if (!frame_->IsProvisional())
      InitializeRootScroller();
  }

  if (frame_->IsMainFrame()) {
    // Allow for commits to be deferred because this is a new document.
    have_deferred_main_frame_commits_ = false;
  }
}

void LocalFrameView::InitializeRootScroller() {
  Page* page = frame_->GetPage();
  DCHECK(page);

  DCHECK_EQ(frame_, page->MainFrame());
  DCHECK(frame_->GetDocument());
  DCHECK(frame_->GetDocument()->IsActive());

  VisualViewport& visual_viewport = frame_->GetPage()->GetVisualViewport();
  DCHECK(visual_viewport.IsActiveViewport());

  ScrollableArea* layout_viewport = LayoutViewport();
  DCHECK(layout_viewport);

  // This method may be called multiple times during loading. If the root
  // scroller is already initialized this call will be a no-op.
  if (viewport_scrollable_area_)
    return;

  auto* root_frame_viewport = MakeGarbageCollected<RootFrameViewport>(
      visual_viewport, *layout_viewport);
  viewport_scrollable_area_ = root_frame_viewport;

  DCHECK(frame_->GetDocument());
  page->GlobalRootScrollerController().Initialize(*root_frame_viewport,
                                                  *frame_->GetDocument());
}

Color LocalFrameView::DocumentBackgroundColor() {
  // The LayoutView's background color is set in
  // StyleResolver::PropagateStyleToViewport(). Blend this with the base
  // background color of the LocalFrameView. This should match the color drawn
  // by ViewPainter::paintBoxDecorationBackground.
  Color result = BaseBackgroundColor();

  bool blend_with_base = true;
  LayoutObject* background_source = GetLayoutView();

  // If we have a fullscreen element grab the fullscreen color from the
  // backdrop.
  if (Document* doc = frame_->GetDocument()) {
    if (Element* element = Fullscreen::FullscreenElementFrom(*doc)) {
      if (LayoutObject* layout_object =
              element->PseudoElementLayoutObject(kPseudoIdBackdrop)) {
        background_source = layout_object;
      }
      if (doc->IsXrOverlay()) {
        // Use the fullscreened element's background directly. Don't bother
        // blending with the backdrop since that's transparent.
        blend_with_base = false;
        if (LayoutObject* layout_object = element->GetLayoutObject())
          background_source = layout_object;
      }
    }
  }

  if (!background_source)
    return result;

  Color doc_bg =
      background_source->ResolveColor(GetCSSPropertyBackgroundColor());
  if (background_source->StyleRef().ColorSchemeForced()) {
    // TODO(https://crbug.com/1351544): The DarkModeFilter operate on SkColor4f,
    // and DocumentBackgroundColor should return an SkColor4f.
    doc_bg = Color::FromSkColor4f(EnsureDarkModeFilter().InvertColorIfNeeded(
        doc_bg.toSkColor4f(), DarkModeFilter::ElementRole::kBackground));
  }
  if (blend_with_base)
    return result.Blend(doc_bg);
  return doc_bg;
}

void LocalFrameView::WillBeRemovedFromFrame() {
  if (paint_artifact_compositor_)
    paint_artifact_compositor_->WillBeRemovedFromFrame();
}

bool LocalFrameView::IsUpdatingLifecycle() const {
  LocalFrameView* root_view = GetFrame().LocalFrameRoot().View();
  DCHECK(root_view);
  return root_view->target_state_ != DocumentLifecycle::kUninitialized;
}

LocalFrameView* LocalFrameView::ParentFrameView() const {
  if (!IsAttached())
    return nullptr;

  Frame* parent_frame = frame_->Tree().Parent();
  if (auto* parent_local_frame = DynamicTo<LocalFrame>(parent_frame))
    return parent_local_frame->View();

  return nullptr;
}

LayoutEmbeddedContent* LocalFrameView::GetLayoutEmbeddedContent() const {
  return frame_->OwnerLayoutObject();
}

bool LocalFrameView::LoadAllLazyLoadedIframes() {
  bool result = false;
  ForAllChildViewsAndPlugins([&](EmbeddedContentView& view) {
    if (auto* embed = view.GetLayoutEmbeddedContent()) {
      if (auto* node = embed->GetNode()) {
        if (auto* frame_owner = DynamicTo<HTMLFrameOwnerElement>(node)) {
          result = result || frame_owner->LoadImmediatelyIfLazy();
        }
      }
    }
  });
  return result;
}

void LocalFrameView::UpdateGeometriesIfNeeded() {
  if (!needs_update_geometries_)
    return;
  needs_update_geometries_ = false;
  HeapVector<Member<EmbeddedContentView>> views;
  ForAllChildViewsAndPlugins(
      [&](EmbeddedContentView& view) { views.push_back(view); });

  for (const auto& view : views) {
    // Script or plugins could detach the frame so abort processing if that
    // happens.
    if (!GetLayoutView())
      break;

    view->UpdateGeometry();
  }
  // Explicitly free the backing store to avoid memory regressions.
  // TODO(bikineev): Revisit after young generation is there.
  views.clear();
}

bool LocalFrameView::UpdateAllLifecyclePhases(DocumentUpdateReason reason) {
  AllowThrottlingScope allow_throttling(*this);
  bool updated = GetFrame().LocalFrameRoot().View()->UpdateLifecyclePhases(
      DocumentLifecycle::kPaintClean, reason);

#if DCHECK_IS_ON()
  if (updated) {
    // This function should return true iff all non-throttled frames are in the
    // kPaintClean lifecycle state.
    ForAllNonThrottledLocalFrameViews([](LocalFrameView& frame_view) {
      DCHECK_EQ(frame_view.Lifecycle().GetState(),
                DocumentLifecycle::kPaintClean);
    });

    // A required intersection observation should run throttled frames to
    // kLayoutClean.
    ForAllThrottledLocalFrameViews([](LocalFrameView& frame_view) {
      DCHECK(frame_view.intersection_observation_state_ != kRequired ||
             frame_view.IsDisplayLocked() ||
             frame_view.Lifecycle().GetState() >=
                 DocumentLifecycle::kLayoutClean);
    });
  }
#endif

  return updated;
}

bool LocalFrameView::UpdateAllLifecyclePhasesForTest() {
  bool result = UpdateAllLifecyclePhases(DocumentUpdateReason::kTest);
  RunPostLifecycleSteps();
  return result;
}

bool LocalFrameView::UpdateLifecycleToCompositingInputsClean(
    DocumentUpdateReason reason) {
  return GetFrame().LocalFrameRoot().View()->UpdateLifecyclePhases(
      DocumentLifecycle::kCompositingInputsClean, reason);
}

bool LocalFrameView::UpdateAllLifecyclePhasesExceptPaint(
    DocumentUpdateReason reason) {
  return GetFrame().LocalFrameRoot().View()->UpdateLifecyclePhases(
      DocumentLifecycle::kPrePaintClean, reason);
}

void LocalFrameView::DryRunPaintingForPrerender() {
  TRACE_EVENT("blink", "DryRunPaintingForPrerender");
  CHECK(GetFrame().GetDocument()->IsPrerendering());
  bool update_result =
      GetFrame().LocalFrameRoot().View()->UpdateLifecyclePhases(
          DocumentLifecycle::kPrePaintClean, DocumentUpdateReason::kPrerender);
  if (!update_result) {
    return;
  }
  if (paint_artifact_compositor_) {
    // If `paint_artifact_compositor_` has been created, PaintArtifact might be
    // referred in its `pending_layers`, and since creating the paint tree again
    // may discard the old PaintArtifact, which breaks the reference
    // relationship down, we should not build the tree again. It is very
    // unlikely to reach here, just to avoid race conditions.
    return;
  }
  std::optional<PaintController> paint_controller;
  PaintTree(PaintBenchmarkMode::kNormal, paint_controller);
  return;
}

void LocalFrameView::UpdateLifecyclePhasesForPrinting() {
  auto* local_frame_view_root = GetFrame().LocalFrameRoot().View();
  local_frame_view_root->UpdateLifecyclePhases(
      DocumentLifecycle::kPrePaintClean, DocumentUpdateReason::kPrinting);

  if (local_frame_view_root != this && !IsAttached()) {
    // We are printing a detached frame which is not reached above. Make sure
    // the frame is ready for painting.
    UpdateLifecyclePhases(DocumentLifecycle::kPrePaintClean,
                          DocumentUpdateReason::kPrinting);
  }
}

bool LocalFrameView::UpdateLifecycleToLayoutClean(DocumentUpdateReason reason) {
  return GetFrame().LocalFrameRoot().View()->UpdateLifecyclePhases(
      DocumentLifecycle::kLayoutClean, reason);
}

LocalFrameView::InvalidationDisallowedScope::InvalidationDisallowedScope(
    const LocalFrameView& frame_view)
    : resetter_(&frame_view.GetFrame()
                     .LocalFrameRoot()
                     .View()
                     ->invalidation_disallowed_,
                true) {
  DCHECK_EQ(instance_count_, 0);
  ++instance_count_;
}

LocalFrameView::InvalidationDisallowedScope::~InvalidationDisallowedScope() {
  --instance_count_;
}

void LocalFrameView::ScheduleVisualUpdateForVisualOverflowIfNeeded() {
  LocalFrame& local_frame_root = GetFrame().LocalFrameRoot();
  // We need a full lifecycle update to recompute visual overflow if we are
  // not already targeting kPaintClean or we have already passed
  // CompositingInputs in the current frame.
  if (local_frame_root.View()->target_state_ < DocumentLifecycle::kPaintClean ||
      Lifecycle().GetState() >= DocumentLifecycle::kCompositingInputsClean) {
    // Schedule visual update to process the paint invalidation in the next
    // cycle.
    local_frame_root.ScheduleVisualUpdateUnlessThrottled();
  }
  // Otherwise the visual overflow will be updated in the compositing inputs
  // phase of this lifecycle.
}

void LocalFrameView::ScheduleVisualUpdateForPaintInvalidationIfNeeded() {
  LocalFrame& local_frame_root = GetFrame().LocalFrameRoot();
  // We need a full lifecycle update to clear pending paint invalidations.
  if (local_frame_root.View()->target_state_ < DocumentLifecycle::kPaintClean ||
      Lifecycle().GetState() >= DocumentLifecycle::kPrePaintClean) {
    // Schedule visual update to process the paint invalidation in the next
    // cycle.
    local_frame_root.ScheduleVisualUpdateUnlessThrottled();
  }
  // Otherwise the paint invalidation will be handled in the pre-paint and paint
  // phase of this full lifecycle update.
}

bool LocalFrameView::NotifyResizeObservers() {
  // Return true if lifecycles need to be re-run
  TRACE_EVENT0("blink,benchmark", "LocalFrameView::NotifyResizeObservers");

  // Controller exists only if ResizeObserver was created.
  ResizeObserverController* resize_controller =
      ResizeObserverController::FromIfExists(*GetFrame().DomWindow());
  if (!resize_controller)
    return false;

  size_t min_depth = resize_controller->GatherObservations();

  if (min_depth != ResizeObserverController::kDepthBottom) {
    resize_controller->DeliverObservations();
  } else {
    // Observation depth limit reached
    if (resize_controller->SkippedObservations() &&
        !resize_controller->IsLoopLimitErrorDispatched()) {
      resize_controller->ClearObservations();

      if (auto* script_state = ToScriptStateForMainWorld(frame_->DomWindow())) {
        ScriptState::Scope scope(script_state);
        const String message =
            "ResizeObserver loop completed with undelivered notifications.";
        ScriptValue value(script_state->GetIsolate(),
                          V8String(script_state->GetIsolate(), message));
        // TODO(pdr): We could report the source location of one of the
        // observers which had skipped observations.
        ErrorEvent* error = ErrorEvent::Create(message, CaptureSourceLocation(),
                                               value, &script_state->World());
        // We're using |SanitizeScriptErrors::kDoNotSanitize| as the error is
        // made by blink itself.
        // TODO(yhirano): Reconsider this.
        frame_->DomWindow()->DispatchErrorEvent(
            error, SanitizeScriptErrors::kDoNotSanitize);
      }

      // Ensure notifications will get delivered in next cycle.
      ScheduleAnimation();
      resize_controller->SetLoopLimitErrorDispatched(true);
    }
    if (Lifecycle().GetState() >= DocumentLifecycle::kPrePaintClean)
      return false;
  }

  // Lifecycle needs to be run again because Resize Observer affected layout
  return true;
}

bool LocalFrameView::LocalFrameTreeAllowsThrottling() const {
  if (LocalFrameView* root_view = GetFrame().LocalFrameRoot().View())
    return root_view->allow_throttling_;
  return false;
}

bool LocalFrameView::LocalFrameTreeForcesThrottling() const {
  if (LocalFrameView* root_view = GetFrame().LocalFrameRoot().View())
    return root_view->force_throttling_;
  return false;
}

void LocalFrameView::PrepareForLifecycleUpdateRecursive() {
  // We will run lifecycle phases for LocalFrameViews that are unthrottled; or
  // are throttled but require IntersectionObserver steps to run.
  if (!ShouldThrottleRendering() ||
      intersection_observation_state_ == kRequired) {
    Lifecycle().EnsureStateAtMost(DocumentLifecycle::kVisualUpdatePending);
    ForAllChildLocalFrameViews([](LocalFrameView& child) {
      child.PrepareForLifecycleUpdateRecursive();
    });
  }
}

// TODO(leviw): We don't assert lifecycle information from documents in child
// WebPluginContainerImpls.
bool LocalFrameView::UpdateLifecyclePhases(
    DocumentLifecycle::LifecycleState target_state,
    DocumentUpdateReason reason) {
  // If the lifecycle is postponed, which can happen if the inspector requests
  // it, then we shouldn't update any lifecycle phases.
  if (frame_->GetDocument() &&
      frame_->GetDocument()->Lifecycle().LifecyclePostponed()) [[unlikely]] {
    return false;
  }

  // Prevent reentrance.
  // TODO(vmpstr): Should we just have a DCHECK instead here?
  if (IsUpdatingLifecycle()) [[unlikely]] {
    DUMP_WILL_BE_NOTREACHED()
        << "LocalFrameView::updateLifecyclePhasesInternal() reentrance";
    return false;
  }

  // This must be called from the root frame, or a detached frame for printing,
  // since it recurses down, not up. Otherwise the lifecycles of the frames
  // might be out of sync.
  DCHECK(frame_->IsLocalRoot() || !IsAttached());

  DCHECK(LocalFrameTreeAllowsThrottling() ||
         (target_state < DocumentLifecycle::kPaintClean));

  // Only the following target states are supported.
  DCHECK(target_state == DocumentLifecycle::kLayoutClean ||
         target_state == DocumentLifecycle::kCompositingInputsClean ||
         target_state == DocumentLifecycle::kPrePaintClean ||
         target_state == DocumentLifecycle::kPaintClean);

  // If the document is not active then it is either not yet initialized, or it
  // is stopping. In either case, we can't reach one of the supported target
  // states.
  if (!frame_->GetDocument()->IsActive())
    return false;

  // If we're throttling and we aren't required to run the IntersectionObserver
  // steps, then we don't need to update lifecycle phases. The throttling status
  // will get updated in RunPostLifecycleSteps().
  if (ShouldThrottleRendering() &&
      intersection_observation_state_ < kRequired) {
    return Lifecycle().GetState() == target_state;
  }

  PrepareForLifecycleUpdateRecursive();

  // This is used to guard against reentrance. It is also used in conjunction
  // with the current lifecycle state to determine which phases are yet to run
  // in this cycle. Note that this may change the return value of
  // ShouldThrottleRendering(), hence it cannot be moved before the preceeding
  // code, which relies on the prior value of ShouldThrottleRendering().
  base::AutoReset<DocumentLifecycle::LifecycleState> target_state_scope(
      &target_state_, target_state);

  lifecycle_data_.start_time = base::TimeTicks::Now();
  ++lifecycle_data_.count;

  if (target_state == DocumentLifecycle::kPaintClean) {
    {
      TRACE_EVENT0("blink", "LocalFrameView::WillStartLifecycleUpdate");

      ForAllNonThrottledLocalFrameViews([](LocalFrameView& frame_view) {
        auto lifecycle_observers = frame_view.lifecycle_observers_;
        for (auto& observer : lifecycle_observers)
          observer->WillStartLifecycleUpdate(frame_view);
      });
    }

    {
      TRACE_EVENT0(
          "blink",
          "LocalFrameView::UpdateLifecyclePhases - start of lifecycle tasks");
      ForAllNonThrottledLocalFrameViews([](LocalFrameView& frame_view) {
        WTF::Vector<base::OnceClosure> tasks;
        frame_view.start_of_lifecycle_tasks_.swap(tasks);
        for (auto& task : tasks)
          std::move(task).Run();
      });
    }
  }

  std::optional<base::AutoReset<bool>> force_debug_info;
  if (reason == DocumentUpdateReason::kTest)
    force_debug_info.emplace(&paint_debug_info_enabled_, true);

  // Run the lifecycle updates.
  UpdateLifecyclePhasesInternal(target_state);

  if (target_state == DocumentLifecycle::kPaintClean) {
    TRACE_EVENT0("blink", "LocalFrameView::DidFinishLifecycleUpdate");

    ForAllNonThrottledLocalFrameViews([](LocalFrameView& frame_view) {
      auto lifecycle_observers = frame_view.lifecycle_observers_;
      for (auto& observer : lifecycle_observers)
        observer->DidFinishLifecycleUpdate(frame_view);
    });
    if (frame_->GetWidgetForLocalRoot() &&
        RuntimeEnabledFeatures::ReportVisibleLineBoundsEnabled()) {
      frame_->GetWidgetForLocalRoot()->UpdateLineBounds();
    }
  }

  // Hit testing metrics include the entire time processing a document update
  // in preparation for a hit test.
  if (reason == DocumentUpdateReason::kHitTest) {
    if (auto* metrics_aggregator = GetUkmAggregator()) {
      metrics_aggregator->RecordTimerSample(
          static_cast<size_t>(LocalFrameUkmAggregator::kHitTestDocumentUpdate),
          lifecycle_data_.start_time, base::TimeTicks::Now());
    }
  }

  return Lifecycle().GetState() == target_state;
}

void LocalFrameView::UpdateLifecyclePhasesInternal(
    DocumentLifecycle::LifecycleState target_state) {
  // TODO(https://crbug.com/1196853): Switch to ScriptForbiddenScope once
  // failures are fixed.
  BlinkLifecycleScopeWillBeScriptForbidden forbid_script;

  // RunScrollSnapshotClientSteps must not run more than once.
  bool should_run_scroll_snapshot_client_steps = true;

  // Run style, layout, compositing and prepaint lifecycle phases and deliver
  // resize observations if required. Resize observer callbacks/delegates have
  // the potential to dirty layout (until loop limit is reached) and therefore
  // the above lifecycle phases need to be re-run until the limit is reached
  // or no layout is pending.
  // Note that after ResizeObserver has settled, we also run intersection
  // observations that need to be delievered in post-layout. This process can
  // also dirty layout, which will run this loop again.

  // A LocalFrameView can be unthrottled at this point, but become throttled as
  // it advances through lifecycle stages. If that happens, it will prevent
  // subsequent passes through the loop from updating the newly-throttled views.
  // To avoid that, we lock in the set of unthrottled views before entering the
  // loop.
  HeapVector<Member<LocalFrameView>> unthrottled_frame_views;
  ForAllNonThrottledLocalFrameViews(
      [&unthrottled_frame_views](LocalFrameView& frame_view) {
        unthrottled_frame_views.push_back(&frame_view);
      });

  while (true) {
    for (LocalFrameView* frame_view : unthrottled_frame_views) {
      // RunResizeObserverSteps may run arbitrary script, which can cause a
      // frame to become detached.
      if (frame_view->GetFrame().IsAttached()) {
        frame_view->Lifecycle().EnsureStateAtMost(
            DocumentLifecycle::kVisualUpdatePending);
      }
    }
    bool run_more_lifecycle_phases =
        RunStyleAndLayoutLifecyclePhases(target_state);
    if (!run_more_lifecycle_phases)
      return;
    DCHECK(Lifecycle().GetState() >= DocumentLifecycle::kLayoutClean);

    // ScrollSnapshotClients may be associated with scrollers that never had a
    // chance to get a layout box at the time style was calculated; when this
    // situation happens, RunScrollTimelineSteps will re-snapshot all affected
    // clients and dirty style for associated effect targets.
    //
    // https://github.com/w3c/csswg-drafts/issues/5261
    if (should_run_scroll_snapshot_client_steps) {
      should_run_scroll_snapshot_client_steps = false;
      bool needs_to_repeat_lifecycle = RunScrollSnapshotClientSteps();
      if (needs_to_repeat_lifecycle)
        continue;
    }

    if (!GetLayoutView())
      return;

    {
      // We need scoping braces here because this
      // DisallowLayoutInvalidationScope is meant to be in effect during
      // pre-paint, but not during ResizeObserver or ViewTransition.
#if DCHECK_IS_ON()
      DisallowLayoutInvalidationScope disallow_layout_invalidation(this);
#endif

      DEVTOOLS_TIMELINE_TRACE_EVENT_INSTANT_WITH_CATEGORIES(
          TRACE_DISABLED_BY_DEFAULT("devtools.timeline"), "SetLayerTreeId",
          inspector_set_layer_tree_id::Data, frame_.Get());
      // The Compositing Inputs lifecycle phase should be integrated into the
      // PrePaint lifecycle phase in the future. The difference between these
      // two stages is not relevant to web developers, so include them both
      // under PrePaint.
      DEVTOOLS_TIMELINE_TRACE_EVENT("PrePaint", inspector_pre_paint_event::Data,
                                    frame_.Get());
      run_more_lifecycle_phases =
          RunCompositingInputsLifecyclePhase(target_state);
      if (!run_more_lifecycle_phases)
        return;

      run_more_lifecycle_phases = RunPrePaintLifecyclePhase(target_state);
    }

    if (!run_more_lifecycle_phases) {
      // If we won't be proceeding to paint, update view transition stylesheet
      // here.
      bool needs_to_repeat_lifecycle = RunViewTransitionSteps(target_state);
      if (needs_to_repeat_lifecycle)
        continue;
    }

      DCHECK(ShouldThrottleRendering() ||
             Lifecycle().GetState() >= DocumentLifecycle::kPrePaintClean);
      if (ShouldThrottleRendering() || !run_more_lifecycle_phases)
        return;

    // Some features may require several passes over style and layout
    // within the same lifecycle update.
    bool needs_to_repeat_lifecycle = false;

    // ResizeObserver and post-layout IntersectionObserver observation
    // deliveries may dirty style and layout. RunResizeObserverSteps will return
    // true if any observer ran that may have dirtied style or layout;
    // RunPostLayoutIntersectionObserverSteps will return true if any
    // observations led to content-visibility intersection changing visibility
    // state synchronously (which happens on the first intersection
    // observeration of a context).
    //
    // Note that we run the content-visibility intersection observation first.
    // The idea is that we want to synchronously determine the initial,
    // first-time-rendered state of on- or off-screen `content-visibility:
    // auto` subtrees before dispatching any kind of resize observations,
    // including the contain-intrinsic-size resize observer. If we repeat the
    // lifecycle here or in the resize observer, the second observation will be
    // asynchronous and will always defer posting observations. This is
    // contrasted with the alternative in which both resize observer and
    // intersection observer can repeat the lifecycle causing another resize
    // observer call to now see different sizes and in the worst case issue a
    // console error and schedule an additional frame of work.
    needs_to_repeat_lifecycle = RunPostLayoutIntersectionObserverSteps();
    if (needs_to_repeat_lifecycle)
      continue;

    {
      ScriptForbiddenScope::AllowUserAgentScript allow_script;
      base::AutoReset<DocumentLifecycle::LifecycleState> saved_target_state(
          &target_state_, DocumentLifecycle::kUninitialized);
      needs_to_repeat_lifecycle = RunResizeObserverSteps(target_state);
    }
    // Only run the rest of the steps here if resize observer is done.
    if (needs_to_repeat_lifecycle)
      continue;

    // ViewTransition mutates the tree and mirrors post layout transform for
    // transitioning elements to UA created elements. This may dirty
    // style/layout requiring another lifecycle update.
    needs_to_repeat_lifecycle = RunViewTransitionSteps(target_state);
    if (!needs_to_repeat_lifecycle)
      break;
  }

  // This must be after all other updates for position-visibility.
  ForAllNonThrottledLocalFrameViews([](LocalFrameView& frame_view) {
    frame_view.frame_->CheckPositionAnchorsForChainedVisibilityChanges();
  });

  // Once we exit the ResizeObserver / IntersectionObserver loop above, we need
  // to clear the resize observer limits so that next time we run this, we can
  // deliver more observations.
  ClearResizeObserverLimit();

  // Layout invalidation scope was disabled for resize observer
  // re-enable it for subsequent steps
#if DCHECK_IS_ON()
  DisallowLayoutInvalidationScope disallow_layout_invalidation(this);
#endif

  // This needs to be done prior to paint: it will update the cc::Layer bounds
  // for the remote frame views, which will be wrapped during paint in
  // ForeignLayerDisplayItem's whose visual rect is set at construction based
  // on cc::Layer bounds.
  ForAllRemoteFrameViews(
      [](RemoteFrameView& frame_view) { frame_view.UpdateCompositingRect(); });

  DCHECK_EQ(target_state, DocumentLifecycle::kPaintClean);
  RunPaintLifecyclePhase(PaintBenchmarkMode::kNormal);
  DCHECK(ShouldThrottleRendering() || AnyFrameIsPrintingOrPaintingPreview() ||
         Lifecycle().GetState() == DocumentLifecycle::kPaintClean);
}

bool LocalFrameView::RunScrollSnapshotClientSteps() {
  // TODO(crbug.com/1329159): Determine if the source for a view timeline has
  // changed, which may in turn require a fresh style/layout cycle.

  DCHECK_GE(Lifecycle().GetState(), DocumentLifecycle::kLayoutClean);
  bool re_run_lifecycles = false;
  ForAllNonThrottledLocalFrameViews(
      [&re_run_lifecycles](LocalFrameView& frame_view) {
        bool valid = frame_view.GetFrame().ValidateScrollSnapshotClients();
        re_run_lifecycles |= !valid;
      });
  return re_run_lifecycles;
}

bool LocalFrameView::RunViewTransitionSteps(
    DocumentLifecycle::LifecycleState target_state) {
  DCHECK(frame_ && frame_->GetDocument());
  DCHECK(frame_->IsLocalRoot() || !IsAttached());

  if (target_state < DocumentLifecycle::kPrePaintClean)
    return false;

  bool re_run_lifecycle = false;
  ForAllNonThrottledLocalFrameViews(
      [&re_run_lifecycle, target_state](LocalFrameView& frame_view) {
        const auto* document = frame_view.GetFrame().GetDocument();
        if (!document)
          return;

        DCHECK_GE(document->Lifecycle().GetState(),
                  DocumentLifecycle::kPrePaintClean);
        auto* transition = ViewTransitionUtils::GetTransition(*document);
        if (!transition)
          return;

        if (target_state == DocumentLifecycle::kPaintClean)
          transition->RunViewTransitionStepsDuringMainFrame();
        else
          transition->RunViewTransitionStepsOutsideMainFrame();

        re_run_lifecycle |= document->Lifecycle().GetState() <
                                DocumentLifecycle::kPrePaintClean ||
                            frame_view.NeedsLayout();
      });

  return re_run_lifecycle;
}

bool LocalFrameView::RunResizeObserverSteps(
    DocumentLifecycle::LifecycleState target_state) {
  if (target_state != DocumentLifecycle::kPaintClean)
    return false;

  for (auto& element : disconnected_elements_with_remembered_size_) {
    if (!element->isConnected()) {
      element->SetLastRememberedBlockSize(std::nullopt);
      element->SetLastRememberedInlineSize(std::nullopt);
    }
  }
  disconnected_elements_with_remembered_size_.clear();

  // https://drafts.csswg.org/css-anchor-position-1/#last-successful-position-option
  bool re_run_lifecycles = UpdateLastSuccessfulPositionFallbacks();

  ForAllNonThrottledLocalFrameViews(
      [&re_run_lifecycles](LocalFrameView& frame_view) {
        bool result = frame_view.NotifyResizeObservers();
        re_run_lifecycles = re_run_lifecycles || result;
      });
  return re_run_lifecycles;
}

void LocalFrameView::ClearResizeObserverLimit() {
  ForAllNonThrottledLocalFrameViews([](LocalFrameView& frame_view) {
    ResizeObserverController* resize_controller =
        ResizeObserverController::From(*frame_view.frame_->DomWindow());
    resize_controller->ClearMinDepth();
    resize_controller->SetLoopLimitErrorDispatched(false);
  });
}

bool LocalFrameView::ShouldDeferLayoutSnap() const {
  // Scrollers that are snap containers normally need to re-snap after layout
  // changes, but we defer the snap until the user is done scrolling to avoid
  // fighting with snap animations on the compositor thread.
  if (auto* web_frame = WebLocalFrameImpl::FromFrame(frame_)) {
    if (auto* widget = web_frame->LocalRootFrameWidget()) {
      return widget->IsScrollGestureActive();
    }
  }
  return false;
}

void LocalFrameView::EnqueueScrollSnapChangingFromImplIfNecessary() {
  ForAllNonThrottledLocalFrameViews([](LocalFrameView& frame_view) {
    for (const auto& area : frame_view.scrollable_areas_.Values()) {
      if (area->ScrollsOverflow()) {
        area->EnqueueScrollSnapChangingEventFromImplIfNeeded();
      }
    }
  });
}

bool LocalFrameView::RunStyleAndLayoutLifecyclePhases(
    DocumentLifecycle::LifecycleState target_state) {
  TRACE_EVENT0("blink,benchmark",
               "LocalFrameView::RunStyleAndLayoutLifecyclePhases");
  UpdateStyleAndLayoutIfNeededRecursive();
  DCHECK(ShouldThrottleRendering() ||
         Lifecycle().GetState() >= DocumentLifecycle::kLayoutClean);
  if (Lifecycle().GetState() < DocumentLifecycle::kLayoutClean)
    return false;

  // PerformRootScrollerSelection can dirty layout if an effective root
  // scroller is changed so make sure we get back to LayoutClean.
  if (frame_->GetDocument()
          ->GetRootScrollerController()
          .PerformRootScrollerSelection() &&
      RuntimeEnabledFeatures::ImplicitRootScrollerEnabled()) {
    UpdateStyleAndLayoutIfNeededRecursive();
  }

  if (target_state == DocumentLifecycle::kLayoutClean)
    return false;

  // Now we can run post layout steps in preparation for further phases.
  ForAllNonThrottledLocalFrameViews([](LocalFrameVie
```