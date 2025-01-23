Response:
The user is asking for a summary of the provided C++ code file `web_local_frame_impl.cc`.
The request includes specific points to address:
- List the functionalities of the file.
- Explain its relation to JavaScript, HTML, and CSS with examples.
- Provide examples of logical reasoning with input and output.
- Illustrate common user or programming errors.
- Summarize the overall function of the code (for this first part).

**Thinking Process:**

1. **High-Level Understanding:** The file name `web_local_frame_impl.cc` suggests it's the implementation of `WebLocalFrame`, a core concept in the Blink rendering engine. The comments at the beginning confirm this, outlining the ownership structure of frames and related objects.

2. **Deconstructing the Comments:** The initial comments about ownership (`WebView`, `Page`, `LocalFrame`, `FrameLoader`, `LocalFrameView`) are crucial. They establish the context and the relationships between these key components. The discussion about Oilpan (Blink's garbage collector) clarifies memory management aspects. The section on how frames are destroyed highlights the lifecycle and detachment mechanisms.

3. **Analyzing Includes:** The `#include` directives provide a wealth of information about the file's dependencies and therefore its functionalities. Look for categories:
    - **Core Blink:** `core/frame/*`, `core/dom/*`, `core/loader/*`, `core/editing/*`, `core/page/*`, etc. These indicate core rendering engine functionalities.
    - **Platform Abstraction:** `public/platform/*`. These suggest interactions with the underlying operating system or browser environment.
    - **Public Web APIs:** `public/web/*`. These are the interfaces exposed to the embedder (like Chromium).
    - **Mojo:** `mojo/public/cpp/*`. This signifies inter-process communication within Chromium.
    - **Third-Party:** Libraries like `base`, `cc`.

4. **Examining Class Definitions and Functions:** Scan through the class definitions (e.g., `ChromePrintContext`, `ChromePluginPrintContext`, `PaintPreviewContext`, `TouchStartEventListener`) and the functions (`InitializeFrameWidget`, `InstanceCount`, `FromFrameToken`). These provide concrete clues about specific tasks the file handles.

5. **Identifying Key Functionality Areas:** Based on the includes and class definitions, group the functionalities:
    - **Frame Management:** Creation, destruction, relationships between frames.
    - **Printing:**  Handling print requests, interacting with plugins for printing.
    - **Hit Testing:**  Determining what element is at a specific point (especially for touch events).
    - **Event Handling:**  Processing touch events.
    - **Widget Management:**  Interacting with the `WebFrameWidget`.

6. **Relating to Web Technologies (JavaScript, HTML, CSS):**
    - **JavaScript:**  The file interacts with the JavaScript engine (V8) through `ScriptController`, `ScriptValue`, and related classes. It handles script evaluation and execution within the frame.
    - **HTML:** The file deals with HTML elements (`HTMLInputElement`, `HTMLFormElement`, etc.) and the DOM structure. It's responsible for managing the representation of HTML content within the frame.
    - **CSS:** While not directly manipulating CSS properties, the rendering process managed by this file is heavily influenced by CSS. The layout and painting sections are where CSS effects come into play.

7. **Logical Reasoning (Hypothetical Input/Output):**  Consider specific functions and imagine their behavior:
    - **`FromFrameToken`:** Input: A `FrameToken`. Output: A `WebLocalFrame` pointer if the token is valid, otherwise `nullptr`.
    - **Print Contexts:** Input: A request to print. Output: A series of drawing commands sent to the printing system.

8. **Common Errors:** Think about potential issues developers might encounter when working with frames:
    - Incorrectly managing frame lifecycles (e.g., dangling pointers if `close()` is not called).
    - Making assumptions about frame hierarchy that might be incorrect.

9. **Drafting the Summary:**  Combine all the gathered information into a concise summary, addressing each part of the user's request. Emphasize the core role of `WebLocalFrameImpl` in managing the lifecycle and functionalities of a local frame within the Blink rendering engine.

**Self-Correction/Refinement:**

- Initially, I might focus too much on the low-level details. It's important to step back and provide a high-level overview first.
- Ensure the examples for JavaScript, HTML, and CSS are concrete and relevant to the code's purpose.
- When discussing logical reasoning, choose functions that are easy to understand and illustrate the input-output concept clearly.
- Make sure the common errors are practical and reflect potential issues in web development or embedding scenarios.
```cpp
/*
 * Copyright (C) 2009 Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *     * Neither the name of Google Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

// How ownership works
// -------------------
//
// Big oh represents a refcounted relationship: owner O--- ownee
//
// WebView (for the toplevel frame only)
//    O
//    |           WebFrame
//    |              O
//    |              |
//   Page O------- LocalFrame (main_frame_) O-------O LocalFrameView
//                   ||
//                   ||
//               FrameLoader
//
// FrameLoader and LocalFrame are formerly one object that was split apart
// because it got too big. They basically have the same lifetime, hence the
// double line.
//
// From the perspective of the embedder, WebFrame is simply an object that it
// allocates by calling WebFrame::create() and must be freed by calling close().
// Internally, WebFrame is actually refcounted and it holds a reference to its
// corresponding LocalFrame in blink.
//
// Oilpan: the middle objects + Page in the above diagram are Oilpan heap
// allocated, WebView and LocalFrameView are currently not. In terms of
// ownership and control, the relationships stays the same, but the references
// from the off-heap WebView to the on-heap Page is handled by a Persistent<>,
// not a scoped_refptr<>. Similarly, the mutual strong references between the
// on-heap LocalFrame and the off-heap LocalFrameView is through a RefPtr (from
// LocalFrame to LocalFrameView), and a Persistent refers to the LocalFrame in
// the other direction.
//
// From the embedder's point of view, the use of Oilpan brings no changes.
// close() must still be used to signal that the embedder is through with the
// WebFrame. Calling it will bring about the release and finalization of the
// frame object, and everything underneath.
//
// How frames are destroyed
// ------------------------
//
// The main frame is never destroyed and is re-used. The FrameLoader is re-used
// and a reference to the main frame is kept by the Page.
//
// When frame content is replaced, all subframes are destroyed. This happens
// in Frame::detachChildren for each subframe in a pre-order depth-first
// traversal. Note that child node order may not match DOM node order!
// detachChildren() (virtually) calls Frame::detach(), which again calls
// LocalFrameClient::detached(). This triggers WebFrame to clear its reference
// to LocalFrame. LocalFrameClient::detached() also notifies the embedder via
// WebLocalFrameClient that the frame is detached. Most embedders will invoke
// close() on the WebFrame at this point, triggering its deletion unless
// something else is still retaining a reference.
//
// The client is expected to be set whenever the WebLocalFrameImpl is attached
// to the DOM.

#include "third_party/blink/renderer/core/frame/web_local_frame_impl.h"

#include <algorithm>
#include <cmath>
#include <memory>
#include <numeric>
#include <utility>

#include "base/compiler_specific.h"
#include "base/notreached.h"
#include "base/numerics/safe_conversions.h"
#include "base/task/single_thread_task_runner.h"
#include "build/build_config.h"
#include "cc/base/features.h"
#include "mojo/public/cpp/bindings/pending_associated_receiver.h"
#include "mojo/public/cpp/bindings/pending_associated_remote.h"
#include "services/metrics/public/cpp/ukm_source_id.h"
#include "services/network/public/cpp/web_sandbox_flags.h"
#include "services/network/public/mojom/web_sandbox_flags.mojom-blink.h"
#include "third_party/blink/public/common/context_menu_data/context_menu_params_builder.h"
#include "third_party/blink/public/common/frame/fenced_frame_sandbox_flags.h"
#include "third_party/blink/public/common/page_state/page_state.h"
#include "third_party/blink/public/common/storage_key/storage_key.h"
#include "third_party/blink/public/mojom/browser_interface_broker.mojom-blink.h"
#include "third_party/blink/public/mojom/devtools/inspector_issue.mojom-blink.h"
#include "third_party/blink/public/mojom/fenced_frame/fenced_frame.mojom-blink.h"
#include "third_party/blink/public/mojom/frame/frame_replication_state.mojom-blink.h"
#include "third_party/blink/public/mojom/frame/media_player_action.mojom-blink.h"
#include "third_party/blink/public/mojom/frame/tree_scope_type.mojom-blink.h"
#include "third_party/blink/public/mojom/lcp_critical_path_predictor/lcp_critical_path_predictor.mojom.h"
#include "third_party/blink/public/mojom/permissions_policy/permissions_policy.mojom-blink.h"
#include "third_party/blink/public/platform/interface_registry.h"
#include "third_party/blink/public/platform/task_type.h"
#include "third_party/blink/public/platform/web_isolated_world_info.h"
#include "third_party/blink/public/platform/web_security_origin.h"
#include "third_party/blink/public/platform/web_url_error.h"
#include "third_party/blink/public/platform/web_vector.h"
#include "third_party/blink/public/web/blink.h"
#include "third_party/blink/public/web/web_associated_url_loader_options.h"
#include "third_party/blink/public/web/web_autofill_client.h"
#include "third_party/blink/public/web/web_console_message.h"
#include "third_party/blink/public/web/web_content_capture_client.h"
#include "third_party/blink/public/web/web_document.h"
#include "third_party/blink/public/web/web_form_element.h"
#include "third_party/blink/public/web/web_frame_owner_properties.h"
#include "third_party/blink/public/web/web_history_item.h"
#include "third_party/blink/public/web/web_input_element.h"
#include "third_party/blink/public/web/web_local_frame_client.h"
#include "third_party/blink/public/web/web_manifest_manager.h"
#include "third_party/blink/public/web/web_navigation_params.h"
#include "third_party/blink/public/web/web_node.h"
#include "third_party/blink/public/web/web_performance_metrics_for_nested_contexts.h"
#include "third_party/blink/public/web/web_performance_metrics_for_reporting.h"
#include "third_party/blink/public/web/web_plugin.h"
#include "third_party/blink/public/web/web_print_client.h"
#include "third_party/blink/public/web/web_print_page_description.h"
#include "third_party/blink/public/web/web_print_params.h"
#include "third_party/blink/public/web/web_print_preset_options.h"
#include "third_party/blink/public/web/web_range.h"
#include "third_party/blink/public/web/web_script_source.h"
#include "third_party/blink/public/web/web_serialized_script_value.h"
#include "third_party/blink/renderer/bindings/core/v8/binding_security.h"
#include "third_party/blink/renderer/bindings/core/v8/isolated_world_csp.h"
#include "third_party/blink/renderer/bindings/core/v8/sanitize_script_errors.h"
#include "third_party/blink/renderer/bindings/core/v8/script_controller.h"
#include "third_party/blink/renderer/bindings/core/v8/script_evaluation_result.h"
#include "third_party/blink/renderer/bindings/core/v8/script_value.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_gc_controller.h"
#include "third_party/blink/renderer/core/clipboard/clipboard_utilities.h"
#include "third_party/blink/renderer/core/clipboard/system_clipboard.h"
#include "third_party/blink/renderer/core/core_initializer.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/events/add_event_listener_options_resolved.h"
#include "third_party/blink/renderer/core/dom/icon_url.h"
#include "third_party/blink/renderer/core/dom/node.h"
#include "third_party/blink/renderer/core/dom/node_traversal.h"
#include "third_party/blink/renderer/core/dom/shadow_root.h"
#include "third_party/blink/renderer/core/editing/editing_utilities.h"
#include "third_party/blink/renderer/core/editing/editor.h"
#include "third_party/blink/renderer/core/editing/ephemeral_range.h"
#include "third_party/blink/renderer/core/editing/finder/find_in_page_coordinates.h"
#include "third_party/blink/renderer/core/editing/finder/text_finder.h"
#include "third_party/blink/renderer/core/editing/frame_selection.h"
#include "third_party/blink/renderer/core/editing/ime/edit_context.h"
#include "third_party/blink/renderer/core/editing/ime/ime_text_span_vector_builder.h"
#include "third_party/blink/renderer/core/editing/ime/input_method_controller.h"
#include "third_party/blink/renderer/core/editing/iterators/text_iterator.h"
#include "third_party/blink/renderer/core/editing/markers/document_marker_controller.h"
#include "third_party/blink/renderer/core/editing/plain_text_range.h"
#include "third_party/blink/renderer/core/editing/selection_template.h"
#include "third_party/blink/renderer/core/editing/serializers/serialization.h"
#include "third_party/blink/renderer/core/editing/set_selection_options.h"
#include "third_party/blink/renderer/core/editing/spellcheck/spell_checker.h"
#include "third_party/blink/renderer/core/editing/text_affinity.h"
#include "third_party/blink/renderer/core/editing/visible_position.h"
#include "third_party/blink/renderer/core/events/after_print_event.h"
#include "third_party/blink/renderer/core/events/before_print_event.h"
#include "third_party/blink/renderer/core/events/touch_event.h"
#include "third_party/blink/renderer/core/execution_context/window_agent.h"
#include "third_party/blink/renderer/core/exported/web_dev_tools_agent_impl.h"
#include "third_party/blink/renderer/core/exported/web_plugin_container_impl.h"
#include "third_party/blink/renderer/core/exported/web_view_impl.h"
#include "third_party/blink/renderer/core/frame/csp/content_security_policy.h"
#include "third_party/blink/renderer/core/frame/deprecation/deprecation.h"
#include "third_party/blink/renderer/core/frame/find_in_page.h"
#include "third_party/blink/renderer/core/frame/frame_console.h"
#include "third_party/blink/renderer/core/frame/intervention.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame_client_impl.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/page_scale_constraints_set.h"
#include "third_party/blink/renderer/core/frame/pausable_script_executor.h"
#include "third_party/blink/renderer/core/frame/remote_frame.h"
#include "third_party/blink/renderer/core/frame/remote_frame_owner.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/frame/smart_clip.h"
#include "third_party/blink/renderer/core/frame/visual_viewport.h"
#include "third_party/blink/renderer/core/frame/web_frame_widget_impl.h"
#include "third_party/blink/renderer/core/frame/web_remote_frame_impl.h"
#include "third_party/blink/renderer/core/html/fenced_frame/html_fenced_frame_element.h"
#include "third_party/blink/renderer/core/html/forms/html_form_control_element.h"
#include "third_party/blink/renderer/core/html/forms/html_form_element.h"
#include "third_party/blink/renderer/core/html/forms/html_input_element.h"
#include "third_party/blink/renderer/core/html/html_anchor_element.h"
#include "third_party/blink/renderer/core/html/html_collection.h"
#include "third_party/blink/renderer/core/html/html_frame_element_base.h"
#include "third_party/blink/renderer/core/html/html_frame_owner_element.h"
#include "third_party/blink/renderer/core/html/html_head_element.h"
#include "third_party/blink/renderer/core/html/html_iframe_element.h"
#include "third_party/blink/renderer/core/html/html_image_element.h"
#include "third_party/blink/renderer/core/html/html_link_element.h"
#include "third_party/blink/renderer/core/html/plugin_document.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/input/context_menu_allowed_scope.h"
#include "third_party/blink/renderer/core/input/event_handler.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/core/inspector/inspector_audits_issue.h"
#include "third_party/blink/renderer/core/inspector/inspector_issue.h"
#include "third_party/blink/renderer/core/inspector/inspector_issue_conversion.h"
#include "third_party/blink/renderer/core/layout/hit_test_result.h"
#include "third_party/blink/renderer/core/layout/layout_embedded_content.h"
#include "third_party/blink/renderer/core/layout/layout_object.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/lcp_critical_path_predictor/lcp_critical_path_predictor.h"
#include "third_party/blink/renderer/core/loader/document_loader.h"
#include "third_party/blink/renderer/core/loader/frame_load_request.h"
#include "third_party/blink/renderer/core/loader/frame_loader.h"
#include "third_party/blink/renderer/core/loader/history_item.h"
#include "third_party/blink/renderer/core/loader/web_associated_url_loader_impl.h"
#include "third_party/blink/renderer/core/page/context_menu_controller.h"
#include "third_party/blink/renderer/core/page/focus_controller.h"
#include "third_party/blink/renderer/core/page/frame_tree.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/page/print_context.h"
#include "third_party/blink/renderer/core/paint/paint_layer.h"
#include "third_party/blink/renderer/core/paint/paint_layer_scrollable_area.h"
#include "third_party/blink/renderer/core/paint/timing/paint_timing.h"
#include "third_party/blink/renderer/core/script/classic_script.h"
#include "third_party/blink/renderer/core/scroll/scroll_types.h"
#include "third_party/blink/renderer/core/scroll/scrollbar_theme.h"
#include "third_party/blink/renderer/core/timing/dom_window_performance.h"
#include "third_party/blink/renderer/core/timing/window_performance.h"
#include "third_party/blink/renderer/platform/bindings/dom_wrapper_world.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/script_forbidden_scope.h"
#include "third_party/blink/renderer/platform/bindings/source_location.h"
#include "third_party/blink/renderer/platform/fonts/font_cache.h"
#include "third_party/blink/renderer/platform/graphics/color.h"
#include "third_party/blink/renderer/platform/graphics/graphics_context.h"
#include "third_party/blink/renderer/platform/graphics/paint/drawing_recorder.h"
#include "third_party/blink/renderer/platform/graphics/paint/ignore_paint_timing_scope.h"
#include "third_party/blink/renderer/platform/graphics/paint/paint_record_builder.h"
#include "third_party/blink/renderer/platform/graphics/paint/scoped_paint_chunk_properties.h"
#include "third_party/blink/renderer/platform/graphics/skia/skia_utils.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/heap/thread_state.h"
#include "third_party/blink/renderer/platform/instrumentation/tracing/trace_event.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/loader/fetch/fetch_context.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_fetcher.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_request.h"
#include "third_party/blink/renderer/platform/loader/fetch/url_loader/url_loader_factory.h"
#include "third_party/blink/renderer/platform/scheduler/public/frame_scheduler.h"
#include "third_party/blink/renderer/platform/scheduler/public/scheduling_policy.h"
#include "third_party/blink/renderer/platform/text/text_direction.h"
#include "third_party/blink/renderer/platform/weborigin/kurl.h"
#include "third_party/blink/renderer/platform/weborigin/scheme_registry.h"
#include "third_party/blink/renderer/platform/weborigin/security_policy.h"
#include "third_party/blink/renderer/platform/wtf/casting.h"
#include "third_party/blink/renderer/platform/wtf/hash_map.h"
#include "ui/gfx/geometry/size_conversions.h"

#if BUILDFLAG(IS_WIN)
#include "third_party/blink/public/web/win/web_font_family_names.h"
#include "third_party/blink/renderer/core/layout/layout_font_accessor_win.h"
#endif

namespace blink {

namespace {

int g_frame_count = 0;

class DummyFrameOwner final : public GarbageCollected<DummyFrameOwner>,
                              public FrameOwner {
 public:
  void Trace(Visitor* visitor) const override { FrameOwner::Trace(visitor); }

  // FrameOwner overrides:
  Frame* ContentFrame() const override { return nullptr; }
  void SetContentFrame(Frame&) override {}
  void ClearContentFrame() override {}
  const FramePolicy& GetFramePolicy() const override {
    DEFINE_STATIC_LOCAL(FramePolicy, frame_policy, ());
    return frame_policy;
  }
  void AddResourceTiming(mojom::blink::ResourceTimingInfoPtr) override {}
  void DispatchLoad() override {}
  void IntrinsicSizingInfoChanged() override {}
  void SetNeedsOcclusionTracking(bool) override {}
  AtomicString BrowsingContextContainerName() const override {
    return AtomicString();
  }
  mojom::blink::ScrollbarMode ScrollbarMode() const override {
    return mojom::blink::ScrollbarMode::kAuto;
  }
  int MarginWidth() const override { return -1; }
  int MarginHeight() const override { return -1; }
  bool AllowFullscreen() const override { return false; }
  bool AllowPaymentRequest() const override { return false; }
  bool IsDisplayNone() const override { return false; }
  mojom::blink::ColorScheme GetColorScheme() const override {
    return mojom::blink::ColorScheme::kLight;
  }
  mojom::blink::PreferredColorScheme GetPreferredColorScheme() const override {
    return mojom::blink::PreferredColorScheme::kLight;
  }
  bool ShouldLazyLoadChildren() const override { return false; }

 private:
  // Intentionally private to prevent redundant checks when the type is
  // already DummyFrameOwner.
  bool IsLocal() const override { return false; }
  bool IsRemote() const override { return false; }
};

}  // namespace

// Simple class to override some of PrintContext behavior. Some of the methods
// made virtual so that they can be overridden by ChromePluginPrintContext.
class ChromePrintContext : public PrintContext {
 public:
  explicit ChromePrintContext(LocalFrame* frame) : PrintContext(frame) {}
  ChromePrintContext(const ChromePrintContext&) = delete;
  ChromePrintContext& operator=(const ChromePrintContext&) = delete;

  ~ChromePrintContext() override = default;

  virtual WebPrintPageDescription GetPageDescription(uint32_t page_index) {
    return GetFrame()->GetDocument()->GetPageDescription(page_index);
  }

  void SpoolSinglePage(cc::PaintCanvas* canvas, wtf_size_t page_index) {
    // The page rect gets scaled and translated, so specify the entire
    // print content area here as the recording rect.
    PaintRecordBuilder builder;
    GraphicsContext& context = builder.Context();
    context.SetPrintingMetafile(canvas->GetPrintingMetafile());
    context.SetPrinting(true);
    context.BeginRecording();
    SpoolPage(context, page_index);
    canvas->drawPicture(context.EndRecording());
  }

  void SpoolPagesWithBoundariesForTesting(cc::PaintCanvas* canvas,
                                          const gfx::Size& spool_size_in_pixels,
                                          const WebVector<uint32_t>* pages) {
    gfx::Rect all_pages_rect(spool_size_in_pixels);

    PaintRecordBuilder builder;
    GraphicsContext& context = builder.Context();
    context.SetPrintingMetafile(canvas->GetPrintingMetafile());
    context.SetPrinting(true);
    context.BeginRecording();

    // Fill the whole background by white.
    context.FillRect(all_pages_rect, Color::kWhite, AutoDarkMode::Disabled());

    WebVector<uint32_t> all_pages;
    if (!pages) {
      all_pages.reserve(PageCount());
      all_pages.resize(PageCount());
      std::iota(all_pages.begin(), all_pages.end(), 0);
      pages = &all_pages;
    }

    int current_height = 0;
    for (uint32_t page_index : *pages) {
      if (page_index >= PageCount()) {
        break;
      }

      // Draw a line for a page boundary if this isn't the first page.
      if (page_index != pages->front()) {
        const gfx::Rect boundary_line_rect(0, current_height - 1,
                                           spool_size_in_pixels.width(), 1);
        context.FillRect(boundary_line_rect, Color(0, 0, 255),
                         AutoDarkMode::Disabled());
      }

      WebPrintPageDescription description =
          GetFrame()->GetDocument()->GetPageDescription(page_index);

      AffineTransform transform;
      transform.Translate(0, current_height);

      if (description.orientation == PageOrientation::kUpright) {
        current_height += description.size.height() + 1;
      } else {
        if (description.orientation == PageOrientation::kRotateRight) {
          transform.Translate(description.size.height(), 0);
          transform.Rotate(90);
        } else {
          DCHECK_EQ(description.orientation, PageOrientation::kRotateLeft);
          transform.Translate(0, description.size.width());
          transform.Rotate(-90);
        }
        current_height += description.size.width() + 1;
      }

      context.Save();
      context.ConcatCTM(transform);

      SpoolPage(context, page_index);

      context.Restore();
    }

    canvas->drawPicture(context.EndRecording());
  }

 protected:
  virtual void SpoolPage(GraphicsContext& context, wtf_size_t page_index) {
    DispatchEventsForPrintingOnAllFrames();
    if (!IsFrameValid()) {
      return;
    }

    auto* frame_view = GetFrame()->View();
    DCHECK(frame_view);
    frame_view->UpdateLifecyclePhasesForPrinting();

    if (!IsFrameValid() || page_index >= PageCount()) {
      // TODO(crbug.com/452672): The number of pages may change after layout for
      // pagination.
      return;
    }
    gfx::Rect page_rect = PageRect(page_index);

    // Cancel out the scroll offset used in screen mode.
    gfx::Vector2d offset = frame_view->LayoutViewport()->ScrollOffsetInt();
    context.Save();
    context.Translate(static_cast<float>(offset.x()),
                      static_cast<float>(offset.y()));

    const LayoutView* layout_view = frame_view->GetLayoutView();

    PaintRecordBuilder builder(context);

    frame_view->PrintPage(builder.Context(), page_index, CullRect(page_rect));

    auto property_tree_state =
        layout_view->FirstFragment().LocalBorderBoxProperties();
    OutputLinkedDestinations(builder.Context(), property_tree_state, page_rect);
    context.DrawRecord(builder.EndRecording(property_tree_state.Unalias()));
    context.Restore();
  }

 private:
  void DispatchEventsForPrintingOnAllFrames() {
    Heap
### 提示词
```
这是目录为blink/renderer/core/frame/web_local_frame_impl.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
/*
 * Copyright (C) 2009 Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *     * Neither the name of Google Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

// How ownership works
// -------------------
//
// Big oh represents a refcounted relationship: owner O--- ownee
//
// WebView (for the toplevel frame only)
//    O
//    |           WebFrame
//    |              O
//    |              |
//   Page O------- LocalFrame (main_frame_) O-------O LocalFrameView
//                   ||
//                   ||
//               FrameLoader
//
// FrameLoader and LocalFrame are formerly one object that was split apart
// because it got too big. They basically have the same lifetime, hence the
// double line.
//
// From the perspective of the embedder, WebFrame is simply an object that it
// allocates by calling WebFrame::create() and must be freed by calling close().
// Internally, WebFrame is actually refcounted and it holds a reference to its
// corresponding LocalFrame in blink.
//
// Oilpan: the middle objects + Page in the above diagram are Oilpan heap
// allocated, WebView and LocalFrameView are currently not. In terms of
// ownership and control, the relationships stays the same, but the references
// from the off-heap WebView to the on-heap Page is handled by a Persistent<>,
// not a scoped_refptr<>. Similarly, the mutual strong references between the
// on-heap LocalFrame and the off-heap LocalFrameView is through a RefPtr (from
// LocalFrame to LocalFrameView), and a Persistent refers to the LocalFrame in
// the other direction.
//
// From the embedder's point of view, the use of Oilpan brings no changes.
// close() must still be used to signal that the embedder is through with the
// WebFrame.  Calling it will bring about the release and finalization of the
// frame object, and everything underneath.
//
// How frames are destroyed
// ------------------------
//
// The main frame is never destroyed and is re-used. The FrameLoader is re-used
// and a reference to the main frame is kept by the Page.
//
// When frame content is replaced, all subframes are destroyed. This happens
// in Frame::detachChildren for each subframe in a pre-order depth-first
// traversal. Note that child node order may not match DOM node order!
// detachChildren() (virtually) calls Frame::detach(), which again calls
// LocalFrameClient::detached(). This triggers WebFrame to clear its reference
// to LocalFrame. LocalFrameClient::detached() also notifies the embedder via
// WebLocalFrameClient that the frame is detached. Most embedders will invoke
// close() on the WebFrame at this point, triggering its deletion unless
// something else is still retaining a reference.
//
// The client is expected to be set whenever the WebLocalFrameImpl is attached
// to the DOM.

#include "third_party/blink/renderer/core/frame/web_local_frame_impl.h"

#include <algorithm>
#include <cmath>
#include <memory>
#include <numeric>
#include <utility>

#include "base/compiler_specific.h"
#include "base/notreached.h"
#include "base/numerics/safe_conversions.h"
#include "base/task/single_thread_task_runner.h"
#include "build/build_config.h"
#include "cc/base/features.h"
#include "mojo/public/cpp/bindings/pending_associated_receiver.h"
#include "mojo/public/cpp/bindings/pending_associated_remote.h"
#include "services/metrics/public/cpp/ukm_source_id.h"
#include "services/network/public/cpp/web_sandbox_flags.h"
#include "services/network/public/mojom/web_sandbox_flags.mojom-blink.h"
#include "third_party/blink/public/common/context_menu_data/context_menu_params_builder.h"
#include "third_party/blink/public/common/frame/fenced_frame_sandbox_flags.h"
#include "third_party/blink/public/common/page_state/page_state.h"
#include "third_party/blink/public/common/storage_key/storage_key.h"
#include "third_party/blink/public/mojom/browser_interface_broker.mojom-blink.h"
#include "third_party/blink/public/mojom/devtools/inspector_issue.mojom-blink.h"
#include "third_party/blink/public/mojom/fenced_frame/fenced_frame.mojom-blink.h"
#include "third_party/blink/public/mojom/frame/frame_replication_state.mojom-blink.h"
#include "third_party/blink/public/mojom/frame/media_player_action.mojom-blink.h"
#include "third_party/blink/public/mojom/frame/tree_scope_type.mojom-blink.h"
#include "third_party/blink/public/mojom/lcp_critical_path_predictor/lcp_critical_path_predictor.mojom.h"
#include "third_party/blink/public/mojom/permissions_policy/permissions_policy.mojom-blink.h"
#include "third_party/blink/public/platform/interface_registry.h"
#include "third_party/blink/public/platform/task_type.h"
#include "third_party/blink/public/platform/web_isolated_world_info.h"
#include "third_party/blink/public/platform/web_security_origin.h"
#include "third_party/blink/public/platform/web_url_error.h"
#include "third_party/blink/public/platform/web_vector.h"
#include "third_party/blink/public/web/blink.h"
#include "third_party/blink/public/web/web_associated_url_loader_options.h"
#include "third_party/blink/public/web/web_autofill_client.h"
#include "third_party/blink/public/web/web_console_message.h"
#include "third_party/blink/public/web/web_content_capture_client.h"
#include "third_party/blink/public/web/web_document.h"
#include "third_party/blink/public/web/web_form_element.h"
#include "third_party/blink/public/web/web_frame_owner_properties.h"
#include "third_party/blink/public/web/web_history_item.h"
#include "third_party/blink/public/web/web_input_element.h"
#include "third_party/blink/public/web/web_local_frame_client.h"
#include "third_party/blink/public/web/web_manifest_manager.h"
#include "third_party/blink/public/web/web_navigation_params.h"
#include "third_party/blink/public/web/web_node.h"
#include "third_party/blink/public/web/web_performance_metrics_for_nested_contexts.h"
#include "third_party/blink/public/web/web_performance_metrics_for_reporting.h"
#include "third_party/blink/public/web/web_plugin.h"
#include "third_party/blink/public/web/web_print_client.h"
#include "third_party/blink/public/web/web_print_page_description.h"
#include "third_party/blink/public/web/web_print_params.h"
#include "third_party/blink/public/web/web_print_preset_options.h"
#include "third_party/blink/public/web/web_range.h"
#include "third_party/blink/public/web/web_script_source.h"
#include "third_party/blink/public/web/web_serialized_script_value.h"
#include "third_party/blink/renderer/bindings/core/v8/binding_security.h"
#include "third_party/blink/renderer/bindings/core/v8/isolated_world_csp.h"
#include "third_party/blink/renderer/bindings/core/v8/sanitize_script_errors.h"
#include "third_party/blink/renderer/bindings/core/v8/script_controller.h"
#include "third_party/blink/renderer/bindings/core/v8/script_evaluation_result.h"
#include "third_party/blink/renderer/bindings/core/v8/script_value.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_gc_controller.h"
#include "third_party/blink/renderer/core/clipboard/clipboard_utilities.h"
#include "third_party/blink/renderer/core/clipboard/system_clipboard.h"
#include "third_party/blink/renderer/core/core_initializer.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/events/add_event_listener_options_resolved.h"
#include "third_party/blink/renderer/core/dom/icon_url.h"
#include "third_party/blink/renderer/core/dom/node.h"
#include "third_party/blink/renderer/core/dom/node_traversal.h"
#include "third_party/blink/renderer/core/dom/shadow_root.h"
#include "third_party/blink/renderer/core/editing/editing_utilities.h"
#include "third_party/blink/renderer/core/editing/editor.h"
#include "third_party/blink/renderer/core/editing/ephemeral_range.h"
#include "third_party/blink/renderer/core/editing/finder/find_in_page_coordinates.h"
#include "third_party/blink/renderer/core/editing/finder/text_finder.h"
#include "third_party/blink/renderer/core/editing/frame_selection.h"
#include "third_party/blink/renderer/core/editing/ime/edit_context.h"
#include "third_party/blink/renderer/core/editing/ime/ime_text_span_vector_builder.h"
#include "third_party/blink/renderer/core/editing/ime/input_method_controller.h"
#include "third_party/blink/renderer/core/editing/iterators/text_iterator.h"
#include "third_party/blink/renderer/core/editing/markers/document_marker_controller.h"
#include "third_party/blink/renderer/core/editing/plain_text_range.h"
#include "third_party/blink/renderer/core/editing/selection_template.h"
#include "third_party/blink/renderer/core/editing/serializers/serialization.h"
#include "third_party/blink/renderer/core/editing/set_selection_options.h"
#include "third_party/blink/renderer/core/editing/spellcheck/spell_checker.h"
#include "third_party/blink/renderer/core/editing/text_affinity.h"
#include "third_party/blink/renderer/core/editing/visible_position.h"
#include "third_party/blink/renderer/core/events/after_print_event.h"
#include "third_party/blink/renderer/core/events/before_print_event.h"
#include "third_party/blink/renderer/core/events/touch_event.h"
#include "third_party/blink/renderer/core/execution_context/window_agent.h"
#include "third_party/blink/renderer/core/exported/web_dev_tools_agent_impl.h"
#include "third_party/blink/renderer/core/exported/web_plugin_container_impl.h"
#include "third_party/blink/renderer/core/exported/web_view_impl.h"
#include "third_party/blink/renderer/core/frame/csp/content_security_policy.h"
#include "third_party/blink/renderer/core/frame/deprecation/deprecation.h"
#include "third_party/blink/renderer/core/frame/find_in_page.h"
#include "third_party/blink/renderer/core/frame/frame_console.h"
#include "third_party/blink/renderer/core/frame/intervention.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame_client_impl.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/page_scale_constraints_set.h"
#include "third_party/blink/renderer/core/frame/pausable_script_executor.h"
#include "third_party/blink/renderer/core/frame/remote_frame.h"
#include "third_party/blink/renderer/core/frame/remote_frame_owner.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/frame/smart_clip.h"
#include "third_party/blink/renderer/core/frame/visual_viewport.h"
#include "third_party/blink/renderer/core/frame/web_frame_widget_impl.h"
#include "third_party/blink/renderer/core/frame/web_remote_frame_impl.h"
#include "third_party/blink/renderer/core/html/fenced_frame/html_fenced_frame_element.h"
#include "third_party/blink/renderer/core/html/forms/html_form_control_element.h"
#include "third_party/blink/renderer/core/html/forms/html_form_element.h"
#include "third_party/blink/renderer/core/html/forms/html_input_element.h"
#include "third_party/blink/renderer/core/html/html_anchor_element.h"
#include "third_party/blink/renderer/core/html/html_collection.h"
#include "third_party/blink/renderer/core/html/html_frame_element_base.h"
#include "third_party/blink/renderer/core/html/html_frame_owner_element.h"
#include "third_party/blink/renderer/core/html/html_head_element.h"
#include "third_party/blink/renderer/core/html/html_iframe_element.h"
#include "third_party/blink/renderer/core/html/html_image_element.h"
#include "third_party/blink/renderer/core/html/html_link_element.h"
#include "third_party/blink/renderer/core/html/plugin_document.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/input/context_menu_allowed_scope.h"
#include "third_party/blink/renderer/core/input/event_handler.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/core/inspector/inspector_audits_issue.h"
#include "third_party/blink/renderer/core/inspector/inspector_issue.h"
#include "third_party/blink/renderer/core/inspector/inspector_issue_conversion.h"
#include "third_party/blink/renderer/core/layout/hit_test_result.h"
#include "third_party/blink/renderer/core/layout/layout_embedded_content.h"
#include "third_party/blink/renderer/core/layout/layout_object.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/lcp_critical_path_predictor/lcp_critical_path_predictor.h"
#include "third_party/blink/renderer/core/loader/document_loader.h"
#include "third_party/blink/renderer/core/loader/frame_load_request.h"
#include "third_party/blink/renderer/core/loader/frame_loader.h"
#include "third_party/blink/renderer/core/loader/history_item.h"
#include "third_party/blink/renderer/core/loader/web_associated_url_loader_impl.h"
#include "third_party/blink/renderer/core/page/context_menu_controller.h"
#include "third_party/blink/renderer/core/page/focus_controller.h"
#include "third_party/blink/renderer/core/page/frame_tree.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/page/print_context.h"
#include "third_party/blink/renderer/core/paint/paint_layer.h"
#include "third_party/blink/renderer/core/paint/paint_layer_scrollable_area.h"
#include "third_party/blink/renderer/core/paint/timing/paint_timing.h"
#include "third_party/blink/renderer/core/script/classic_script.h"
#include "third_party/blink/renderer/core/scroll/scroll_types.h"
#include "third_party/blink/renderer/core/scroll/scrollbar_theme.h"
#include "third_party/blink/renderer/core/timing/dom_window_performance.h"
#include "third_party/blink/renderer/core/timing/window_performance.h"
#include "third_party/blink/renderer/platform/bindings/dom_wrapper_world.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/script_forbidden_scope.h"
#include "third_party/blink/renderer/platform/bindings/source_location.h"
#include "third_party/blink/renderer/platform/fonts/font_cache.h"
#include "third_party/blink/renderer/platform/graphics/color.h"
#include "third_party/blink/renderer/platform/graphics/graphics_context.h"
#include "third_party/blink/renderer/platform/graphics/paint/drawing_recorder.h"
#include "third_party/blink/renderer/platform/graphics/paint/ignore_paint_timing_scope.h"
#include "third_party/blink/renderer/platform/graphics/paint/paint_record_builder.h"
#include "third_party/blink/renderer/platform/graphics/paint/scoped_paint_chunk_properties.h"
#include "third_party/blink/renderer/platform/graphics/skia/skia_utils.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/heap/thread_state.h"
#include "third_party/blink/renderer/platform/instrumentation/tracing/trace_event.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/loader/fetch/fetch_context.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_fetcher.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_request.h"
#include "third_party/blink/renderer/platform/loader/fetch/url_loader/url_loader_factory.h"
#include "third_party/blink/renderer/platform/scheduler/public/frame_scheduler.h"
#include "third_party/blink/renderer/platform/scheduler/public/scheduling_policy.h"
#include "third_party/blink/renderer/platform/text/text_direction.h"
#include "third_party/blink/renderer/platform/weborigin/kurl.h"
#include "third_party/blink/renderer/platform/weborigin/scheme_registry.h"
#include "third_party/blink/renderer/platform/weborigin/security_policy.h"
#include "third_party/blink/renderer/platform/wtf/casting.h"
#include "third_party/blink/renderer/platform/wtf/hash_map.h"
#include "ui/gfx/geometry/size_conversions.h"

#if BUILDFLAG(IS_WIN)
#include "third_party/blink/public/web/win/web_font_family_names.h"
#include "third_party/blink/renderer/core/layout/layout_font_accessor_win.h"
#endif

namespace blink {

namespace {

int g_frame_count = 0;

class DummyFrameOwner final : public GarbageCollected<DummyFrameOwner>,
                              public FrameOwner {
 public:
  void Trace(Visitor* visitor) const override { FrameOwner::Trace(visitor); }

  // FrameOwner overrides:
  Frame* ContentFrame() const override { return nullptr; }
  void SetContentFrame(Frame&) override {}
  void ClearContentFrame() override {}
  const FramePolicy& GetFramePolicy() const override {
    DEFINE_STATIC_LOCAL(FramePolicy, frame_policy, ());
    return frame_policy;
  }
  void AddResourceTiming(mojom::blink::ResourceTimingInfoPtr) override {}
  void DispatchLoad() override {}
  void IntrinsicSizingInfoChanged() override {}
  void SetNeedsOcclusionTracking(bool) override {}
  AtomicString BrowsingContextContainerName() const override {
    return AtomicString();
  }
  mojom::blink::ScrollbarMode ScrollbarMode() const override {
    return mojom::blink::ScrollbarMode::kAuto;
  }
  int MarginWidth() const override { return -1; }
  int MarginHeight() const override { return -1; }
  bool AllowFullscreen() const override { return false; }
  bool AllowPaymentRequest() const override { return false; }
  bool IsDisplayNone() const override { return false; }
  mojom::blink::ColorScheme GetColorScheme() const override {
    return mojom::blink::ColorScheme::kLight;
  }
  mojom::blink::PreferredColorScheme GetPreferredColorScheme() const override {
    return mojom::blink::PreferredColorScheme::kLight;
  }
  bool ShouldLazyLoadChildren() const override { return false; }

 private:
  // Intentionally private to prevent redundant checks when the type is
  // already DummyFrameOwner.
  bool IsLocal() const override { return false; }
  bool IsRemote() const override { return false; }
};

}  // namespace

// Simple class to override some of PrintContext behavior. Some of the methods
// made virtual so that they can be overridden by ChromePluginPrintContext.
class ChromePrintContext : public PrintContext {
 public:
  explicit ChromePrintContext(LocalFrame* frame) : PrintContext(frame) {}
  ChromePrintContext(const ChromePrintContext&) = delete;
  ChromePrintContext& operator=(const ChromePrintContext&) = delete;

  ~ChromePrintContext() override = default;

  virtual WebPrintPageDescription GetPageDescription(uint32_t page_index) {
    return GetFrame()->GetDocument()->GetPageDescription(page_index);
  }

  void SpoolSinglePage(cc::PaintCanvas* canvas, wtf_size_t page_index) {
    // The page rect gets scaled and translated, so specify the entire
    // print content area here as the recording rect.
    PaintRecordBuilder builder;
    GraphicsContext& context = builder.Context();
    context.SetPrintingMetafile(canvas->GetPrintingMetafile());
    context.SetPrinting(true);
    context.BeginRecording();
    SpoolPage(context, page_index);
    canvas->drawPicture(context.EndRecording());
  }

  void SpoolPagesWithBoundariesForTesting(cc::PaintCanvas* canvas,
                                          const gfx::Size& spool_size_in_pixels,
                                          const WebVector<uint32_t>* pages) {
    gfx::Rect all_pages_rect(spool_size_in_pixels);

    PaintRecordBuilder builder;
    GraphicsContext& context = builder.Context();
    context.SetPrintingMetafile(canvas->GetPrintingMetafile());
    context.SetPrinting(true);
    context.BeginRecording();

    // Fill the whole background by white.
    context.FillRect(all_pages_rect, Color::kWhite, AutoDarkMode::Disabled());

    WebVector<uint32_t> all_pages;
    if (!pages) {
      all_pages.reserve(PageCount());
      all_pages.resize(PageCount());
      std::iota(all_pages.begin(), all_pages.end(), 0);
      pages = &all_pages;
    }

    int current_height = 0;
    for (uint32_t page_index : *pages) {
      if (page_index >= PageCount()) {
        break;
      }

      // Draw a line for a page boundary if this isn't the first page.
      if (page_index != pages->front()) {
        const gfx::Rect boundary_line_rect(0, current_height - 1,
                                           spool_size_in_pixels.width(), 1);
        context.FillRect(boundary_line_rect, Color(0, 0, 255),
                         AutoDarkMode::Disabled());
      }

      WebPrintPageDescription description =
          GetFrame()->GetDocument()->GetPageDescription(page_index);

      AffineTransform transform;
      transform.Translate(0, current_height);

      if (description.orientation == PageOrientation::kUpright) {
        current_height += description.size.height() + 1;
      } else {
        if (description.orientation == PageOrientation::kRotateRight) {
          transform.Translate(description.size.height(), 0);
          transform.Rotate(90);
        } else {
          DCHECK_EQ(description.orientation, PageOrientation::kRotateLeft);
          transform.Translate(0, description.size.width());
          transform.Rotate(-90);
        }
        current_height += description.size.width() + 1;
      }

      context.Save();
      context.ConcatCTM(transform);

      SpoolPage(context, page_index);

      context.Restore();
    }

    canvas->drawPicture(context.EndRecording());
  }

 protected:
  virtual void SpoolPage(GraphicsContext& context, wtf_size_t page_index) {
    DispatchEventsForPrintingOnAllFrames();
    if (!IsFrameValid()) {
      return;
    }

    auto* frame_view = GetFrame()->View();
    DCHECK(frame_view);
    frame_view->UpdateLifecyclePhasesForPrinting();

    if (!IsFrameValid() || page_index >= PageCount()) {
      // TODO(crbug.com/452672): The number of pages may change after layout for
      // pagination.
      return;
    }
    gfx::Rect page_rect = PageRect(page_index);

    // Cancel out the scroll offset used in screen mode.
    gfx::Vector2d offset = frame_view->LayoutViewport()->ScrollOffsetInt();
    context.Save();
    context.Translate(static_cast<float>(offset.x()),
                      static_cast<float>(offset.y()));

    const LayoutView* layout_view = frame_view->GetLayoutView();

    PaintRecordBuilder builder(context);

    frame_view->PrintPage(builder.Context(), page_index, CullRect(page_rect));

    auto property_tree_state =
        layout_view->FirstFragment().LocalBorderBoxProperties();
    OutputLinkedDestinations(builder.Context(), property_tree_state, page_rect);
    context.DrawRecord(builder.EndRecording(property_tree_state.Unalias()));
    context.Restore();
  }

 private:
  void DispatchEventsForPrintingOnAllFrames() {
    HeapVector<Member<Document>> documents;
    for (Frame* current_frame = GetFrame(); current_frame;
         current_frame = current_frame->Tree().TraverseNext(GetFrame())) {
      if (auto* current_local_frame = DynamicTo<LocalFrame>(current_frame))
        documents.push_back(current_local_frame->GetDocument());
    }

    for (auto& doc : documents)
      doc->DispatchEventsForPrinting();
  }
};

// Simple class to override some of PrintContext behavior. This is used when
// the frame hosts a plugin that supports custom printing. In this case, we
// want to delegate all printing related calls to the plugin.
class ChromePluginPrintContext final : public ChromePrintContext {
 public:
  ChromePluginPrintContext(LocalFrame* frame, WebPluginContainerImpl* plugin)
      : ChromePrintContext(frame), plugin_(plugin) {}

  ~ChromePluginPrintContext() override = default;

  void Trace(Visitor* visitor) const override {
    visitor->Trace(plugin_);
    ChromePrintContext::Trace(visitor);
  }

  const gfx::Rect& PageRect(wtf_size_t) const = delete;

  WebPrintPageDescription GetPageDescription(uint32_t page_index) override {
    // Plug-ins aren't really able to provide any page description apart from
    // the "default" one. Yet, the printing code calls this function for
    // plug-ins, which isn't ideal, but something we have to cope with for now.
    return default_page_description_;
  }

  wtf_size_t PageCount() const override { return page_count_; }

  void BeginPrintMode(const WebPrintParams& print_params) override {
    default_page_description_ = print_params.default_page_description;
    page_count_ = plugin_->PrintBegin(print_params);
  }

  void EndPrintMode() override {
    plugin_->PrintEnd();
    // TODO(junov): The following should not be necessary because
    // the document's printing state does not need to be set when printing
    // via a plugin. The problem is that WebLocalFrameImpl::DispatchBeforePrint
    // modifies this state regardless of whether a plug-in is being used.
    // This code should be refactored so that the print_context_ is in scope
    // when  beforeprint/afterprint events are dispatched So that plug-in
    // behavior can be differentiated. Also, should beforeprint/afterprint
    // events even be dispatched when using a plug-in?
    if (IsFrameValid())
      GetFrame()->GetDocument()->SetPrinting(Document::kNotPrinting);
  }

 protected:
  void SpoolPage(GraphicsContext& context, wtf_size_t page_index) override {
    PaintRecordBuilder builder(context);
    plugin_->PrintPage(page_index, builder.Context());
    context.DrawRecord(builder.EndRecording());
  }

 private:
  // Set when printing.
  Member<WebPluginContainerImpl> plugin_;

  WebPrintPageDescription default_page_description_;

  wtf_size_t page_count_ = 0;
};

class PaintPreviewContext : public PrintContext {
 public:
  explicit PaintPreviewContext(LocalFrame* frame) : PrintContext(frame) {
    use_paginated_layout_ = false;
  }
  PaintPreviewContext(const PaintPreviewContext&) = delete;
  PaintPreviewContext& operator=(const PaintPreviewContext&) = delete;
  ~PaintPreviewContext() override = default;

  bool Capture(cc::PaintCanvas* canvas,
               const gfx::Rect& bounds,
               bool include_linked_destinations) {
    // This code is based on ChromePrintContext::SpoolSinglePage()/SpoolPage().
    // It differs in that it:
    //   1. Uses a different set of flags for painting and the graphics context.
    //   2. Paints a single "page" of `bounds` size without applying print
    //   modifications to the page.
    //   3. Does no scaling.
    if (!GetFrame()->GetDocument() ||
        !GetFrame()->GetDocument()->GetLayoutView())
      return false;
    GetFrame()->View()->UpdateLifecyclePhasesForPrinting();
    if (!GetFrame()->GetDocument() ||
        !GetFrame()->GetDocument()->GetLayoutView())
      return false;
    PaintRecordBuilder builder;
    builder.Context().SetPaintPreviewTracker(canvas->GetPaintPreviewTracker());

    LocalFrameView* frame_view = GetFrame()->View();
    DCHECK(frame_view);

    // This calls BeginRecording on |builder| with dimensions specified by the
    // CullRect.
    PaintFlags flags = PaintFlag::kOmitCompositingInfo;
    if (include_linked_destinations)
      flags |= PaintFlag::kAddUrlMetadata;

    frame_view->PaintOutsideOfLifecycle(builder.Context(), flags,
                                        CullRect(bounds));
    PropertyTreeStateOrAlias property_tree_state =
        frame_view->GetLayoutView()->FirstFragment().ContentsProperties();
    if (include_linked_destinations) {
      OutputLinkedDestinations(builder.Context(), property_tree_state, bounds);
    }
    canvas->drawPicture(builder.EndRecording(property_tree_state.Unalias()));
    return true;
  }
};

// Android WebView requires hit testing results on every touch event. This
// pushes the hit test result to the callback that is registered.
class TouchStartEventListener : public NativeEventListener {
 public:
  explicit TouchStartEventListener(
      base::RepeatingCallback<void(const blink::WebHitTestResult&)> callback)
      : callback_(std::move(callback)) {}

  void Invoke(ExecutionContext*, Event* event) override {
    auto* touch_event = DynamicTo<TouchEvent>(event);
    if (!touch_event)
      return;
    const auto* native_event = touch_event->NativeEvent();
    if (!native_event)
      return;

    DCHECK_EQ(WebInputEvent::Type::kTouchStart,
              native_event->Event().GetType());
    const auto& web_touch_event =
        static_cast<const WebTouchEvent&>(native_event->Event());

    if (web_touch_event.touches_length != 1u)
      return;

    LocalDOMWindow* dom_window = event->currentTarget()->ToLocalDOMWindow();
    CHECK(dom_window);

    WebGestureEvent tap_event(
        WebInputEvent::Type::kGestureTap, WebInputEvent::kNoModifiers,
        base::TimeTicks::Now(), WebGestureDevice::kTouchscreen);
    // GestureTap is only ever from a touchscreen.
    tap_event.SetPositionInWidget(
        web_touch_event.touches[0].PositionInWidget());
    tap_event.SetPositionInScreen(
        web_touch_event.touches[0].PositionInScreen());
    tap_event.SetFrameScale(web_touch_event.FrameScale());
    tap_event.SetFrameTranslate(web_touch_event.FrameTranslate());
    tap_event.data.tap.tap_count = 1;
    tap_event.data.tap.height = tap_event.data.tap.width =
        std::max(web_touch_event.touches[0].radius_x,
                 web_touch_event.touches[0].radius_y);

    HitTestResult result =
        dom_window->GetFrame()
            ->GetEventHandler()
            .HitTestResultForGestureEvent(
                tap_event, HitTestRequest::kReadOnly | HitTestRequest::kActive)
            .GetHitTestResult();

    result.SetToShadowHostIfInUAShadowRoot();

    callback_.Run(result);
  }

 private:
  base::RepeatingCallback<void(const blink::WebHitTestResult&)> callback_;
};

// WebFrame -------------------------------------------------------------------

static CreateWebFrameWidgetCallback* g_create_web_frame_widget = nullptr;

void InstallCreateWebFrameWidgetHook(
    CreateWebFrameWidgetCallback* create_widget) {
  // This DCHECK's aims to avoid unexpected replacement of the hook.
  DCHECK(!g_create_web_frame_widget || !create_widget);
  g_create_web_frame_widget = create_widget;
}

WebFrameWidget* WebLocalFrame::InitializeFrameWidget(
    CrossVariantMojoAssociatedRemote<mojom::blink::FrameWidgetHostInterfaceBase>
        mojo_frame_widget_host,
    CrossVariantMojoAssociatedReceiver<mojom::blink::FrameWidgetInterfaceBase>
        mojo_frame_widget,
    CrossVariantMojoAssociatedRemote<mojom::blink::WidgetHostInterfaceBase>
        mojo_widget_host,
    CrossVariantMojoAssociatedReceiver<mojom::blink::WidgetInterfaceBase>
        mojo_widget,
    const viz::FrameSinkId& frame_sink_id,
    bool is_for_nested_main_frame,
    bool is_for_scalable_page,
    bool hidden) {
  CreateFrameWidgetInternal(
      base::PassKey<WebLocalFrame>(), std::move(mojo_frame_widget_host),
      std::move(mojo_frame_widget), std::move(mojo_widget_host),
      std::move(mojo_widget), frame_sink_id, is_for_nested_main_frame,
      is_for_scalable_page, hidden);
  return FrameWidget();
}

int WebFrame::InstanceCount() {
  return g_frame_count;
}

// static
WebFrame* WebFrame::FromFrameToken(const FrameToken& frame_token) {
  auto* frame = Frame::ResolveFrame(frame_token);
  return WebFrame::FromCoreFrame(frame);
}

// static
WebLocalFrame* WebLocalFrame::FromFrameToken(
    const LocalFrameToken& frame_token) {
  auto* frame = LocalFrame::FromFrameToken(frame_token);
  return WebLocalFrameImpl::FromFrame(frame);
}

WebLocalFrame* WebLocalFrame::FrameForCurrentContext() {
  v8::Isolate* isolate = v8::Isolate::TryGetCurrent();
  if (!isolate) [[un
```