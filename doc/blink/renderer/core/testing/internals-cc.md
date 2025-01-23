Response:
My thinking process to analyze the provided code snippet and generate the summary goes like this:

1. **Understand the Goal:** The request is to analyze the first part of a Chromium Blink engine source file (`internals.cc`) and summarize its functionality. Key areas to focus on are its relationship to web technologies (JavaScript, HTML, CSS), examples of logical inference (if any), common usage errors, and debugging context.

2. **Initial Scan and Keyword Recognition:** I quickly scanned the code looking for high-level patterns and keywords. I noticed:
    * Copyright and license information (standard boilerplate, but good to acknowledge).
    * `#include` directives, indicating dependencies on other Blink components and standard C++ libraries. These headers give clues about the file's purpose. For example, headers related to `dom`, `css`, `html`, `editing`, `frame`, `page`, `layout`, `script`, `testing` strongly suggest this file is involved in internal testing and manipulation of core web page structures and behaviors.
    * Namespaces (`blink`).
    * Class definition `Internals`.
    * Numerous method declarations within the `Internals` class.

3. **Focus on the `Internals` Class:** The class name itself is a strong indicator of its function. "Internals" suggests that this class provides access to internal aspects of the Blink rendering engine, likely for testing and debugging purposes.

4. **Analyze Included Headers for Functionality Clues:** I started going through the `#include` directives more carefully, mentally categorizing them:
    * **Core Web Technologies:** Headers like `core/dom/*.h`, `core/css/*.h`, `core/html/*.h` directly link to the fundamental building blocks of web pages. This confirms the file's involvement with HTML elements, CSS styling, and the Document Object Model.
    * **Rendering and Layout:** Headers like `cc/layers/*.h`, `core/layout/*.h`, `core/paint/*.h` indicate functionality related to how the page is visually rendered and how elements are positioned.
    * **Scripting and Binding:** Headers like `bindings/core/v8/*.h` suggest interaction with JavaScript through the V8 engine.
    * **Testing:** The directory name `core/testing` and headers like `core/testing/*.h` confirm this file's primary purpose is testing.
    * **Editing:** Headers like `core/editing/*.h` point to functionality for manipulating text and selections within web pages.
    * **Frame and Page Management:** Headers like `core/frame/*.h`, `core/page/*.h` indicate control over the structure and lifecycle of web page frames and the overall page.
    * **Streams:** Headers like `core/streams/*.h` indicate involvement with the Streams API.
    * **Other Utilities:** Headers like `base/`, `third_party/absl/`, `wtf/` suggest basic utility functions and data structures are used.

5. **Examine the `Internals` Class Methods:**  Even without seeing the full method implementations, the method names provide valuable information:
    * `ResetToConsistentState`:  Indicates the ability to reset the browser to a clean state for testing.
    * `GetFrame`, `settings`, `runtimeFlags`: Provide access to internal objects.
    * `workerThreadCount`:  Reveals information about worker threads.
    * `observeGC`:  Suggests a mechanism to monitor garbage collection.
    * `updateStyleAndReturnAffectedElementCount`, `styleForElementCount`: Relate to CSS styling and its impact.

6. **Infer Relationships to Web Technologies:** Based on the included headers and method names, I started drawing connections to JavaScript, HTML, and CSS:
    * **JavaScript:** The presence of `ScriptPromise`, `ScriptValue`, and V8-related headers clearly indicates that the `Internals` class exposes functionality that can be called from JavaScript within the testing environment.
    * **HTML:**  The inclusion of numerous HTML element headers (e.g., `HTMLCanvasElement`, `HTMLInputElement`) suggests that the `Internals` class allows for inspection and manipulation of HTML elements.
    * **CSS:**  Headers related to CSS properties, parsing, and style engines show that the `Internals` class can interact with CSS styling rules.

7. **Consider Logical Inference (Hypothetical Examples):** While the provided snippet doesn't contain complex logic, I considered how the provided methods *could* be used for inference in tests. For example, `updateStyleAndReturnAffectedElementCount` implicitly performs a style update and returns a count. A test could assume that changing a certain CSS property will affect a specific number of elements.

8. **Think About User/Programming Errors:** I considered common mistakes when interacting with web pages or writing tests:
    * Incorrectly accessing or manipulating DOM elements.
    * Expecting style changes to happen immediately without triggering a layout update.
    * Issues with asynchronous operations (like promises).

9. **Imagine Debugging Scenarios:**  I thought about how a developer might end up looking at this code:
    * Investigating unexpected test failures.
    * Trying to understand how internal Blink functions work.
    * Debugging rendering or layout issues.

10. **Synthesize the Summary:** Finally, I organized my observations into a coherent summary, addressing the specific points requested: functionality, relationship to web technologies with examples, logical inference examples, user/programming errors, and debugging context. I focused on conveying the core idea that `internals.cc` provides a back door for testing and manipulating the inner workings of the Blink rendering engine.

By following these steps, I could analyze the code snippet effectively and generate a comprehensive summary that addressed all the requirements of the prompt. The key was to combine a high-level overview with a more detailed examination of the code structure and included headers to infer the file's purpose and capabilities.
这是 `blink/renderer/core/testing/internals.cc` 文件的第一部分，它是一个 Chromium Blink 引擎的源代码文件，主要功能是**提供一系列用于测试 Blink 渲染引擎内部行为的接口和工具函数**。它允许测试代码绕过正常的 Web API，直接访问和操作 Blink 的内部状态，以便进行更深入、更精细的测试。

**功能归纳:**

* **提供访问内部状态的入口:** `Internals` 类提供了一系列方法，允许测试代码访问和修改 Blink 引擎的内部状态，例如获取帧（frame）、设置（settings）、运行时标志（runtime flags）、worker 线程数量等。
* **辅助 DOM 操作和检查:**  提供了诸如更新样式并返回受影响元素数量、获取元素样式数量等方法，方便测试 CSS 样式计算和应用。
* **支持异步操作测试:** 包含对 `ScriptPromise` 的处理，例如在 `UseCounterImplObserverImpl` 中用于等待某个特定功能被计数。
* **模拟和控制浏览器行为:**  例如 `ResetToConsistentState` 方法用于将页面重置到一个一致的状态，方便进行不同的测试用例。还包含对设备模拟、页面缩放等的控制。
* **提供测试专用的 Stream API 工具:**  定义了 `TestReadableStreamSource` 和 `TestWritableStreamSink` 类，用于创建可控的 ReadableStream 和 WritableStream，方便测试 Stream API 的内部逻辑和优化。
* **暴露内部调试和监控功能:**  例如 `observeGC` 用于观察 JavaScript 对象的垃圾回收情况。
* **提供用于测试标记 (Marker) 的功能:** 包含 `MarkerTypeFrom` 和 `MarkerTypesFrom` 函数，用于将字符串转换为 `DocumentMarker` 的类型，方便测试文本标记功能。

**与 Javascript, HTML, CSS 的关系及举例说明:**

这个文件虽然是 C++ 代码，但它提供的功能与 JavaScript, HTML, CSS 密切相关，因为它允许测试代码从底层验证这些 Web 技术在 Blink 引擎中的实现是否正确。

* **JavaScript:**
    * **功能关系:** `Internals` 类的方法可以直接影响 JavaScript 的行为。例如，修改运行时标志可以启用或禁用某些 JavaScript 特性。`observeGC` 可以用于测试 JavaScript 对象的生命周期管理。
    * **举例说明:**  一个 JavaScript 测试可以调用 `internals.runtimeFlags().setFooFeatureEnabled(true)` 来启用一个实验性的 JavaScript 功能，然后验证该功能在页面中的表现。另一个测试可以使用 `internals.observeGC(myObject)` 来观察一个 JavaScript 对象 `myObject` 是否被正确地垃圾回收。
* **HTML:**
    * **功能关系:** `Internals` 类提供了访问和操作 DOM 树的接口。例如，可以获取特定的元素，检查其属性，甚至修改 DOM 结构。
    * **举例说明:** 一个测试可以使用 `internals.updateStyleAndReturnAffectedElementCount()` 来验证在添加一个新的 HTML 元素后，有多少元素需要重新计算样式。另一个测试可以使用 `internals.getFrame()` 获取 iframe 的 frame 对象，然后访问 iframe 中的 DOM 元素。
* **CSS:**
    * **功能关系:** `Internals` 类允许测试 CSS 样式的应用和计算过程。例如，可以获取元素的计算样式，检查特定的 CSS 属性值。
    * **举例说明:**  一个测试可以使用 `internals.styleForElementCount()` 来检查在修改某个 CSS 规则后，有多少元素的样式被重新计算。另一个测试可以创建一个元素，应用一些 CSS 样式，然后使用 `internals` 提供的方法来验证该元素的特定 CSS 属性值是否符合预期。

**逻辑推理及假设输入与输出:**

虽然大部分代码是提供接口，但其中一些辅助函数包含简单的逻辑推理。

* **例子：`MarkerTypeFrom(const String& marker_type)`**
    * **假设输入:** 字符串 `"Spelling"`
    * **逻辑推理:** 函数会比较输入字符串与预定义的标记类型字符串（例如 "Spelling", "Grammar"）。如果匹配，则返回对应的 `DocumentMarker::MarkerType` 枚举值。
    * **输出:** `std::optional<DocumentMarker::MarkerType>(DocumentMarker::kSpelling)`

* **例子：`ResetToConsistentState(Page* page)`**
    * **假设输入:** 一个指向 `Page` 对象的指针。
    * **逻辑推理:** 函数会执行一系列操作，将 `Page` 对象及其相关的状态重置为默认值，例如设置光标可见、重置页面缩放、清除事件监听器等。
    * **输出:**  `Page` 对象及其内部状态被修改为一致的初始状态。

**涉及用户或编程常见的使用错误:**

由于 `internals.cc` 主要用于测试，其使用者主要是 Blink 的开发者。常见的错误可能包括：

* **错误地假设内部状态:**  开发者可能会错误地假设某个内部状态的值或行为，导致测试用例失败。例如，错误地认为在某个操作后，元素的样式会立即更新，而实际上可能需要等待异步操作完成。
* **不正确地使用 `Internals` 接口:** `Internals` 提供的接口可能比较底层，不当的使用可能导致程序崩溃或产生未定义的行为。例如，在错误的时刻调用某个方法，或者传递了错误的参数。
* **测试泄漏:**  在测试用例中使用了 `Internals` 修改了某些全局状态，但没有在测试结束后恢复，可能影响后续的测试用例。`ResetToConsistentState` 的目的就是为了避免这类问题。
* **与正常 Web API 行为不一致的假设:**  开发者可能基于 `Internals` 提供的能力编写测试，但这些能力绕过了正常的 Web API 流程，导致测试结果与实际浏览器行为不一致。

**用户操作如何一步步的到达这里，作为调试线索:**

普通用户操作不会直接到达 `internals.cc`。这个文件是 Blink 引擎的内部测试代码。开发者通常会在以下场景接触到它：

1. **编写或修改 Blink 引擎的测试用例:** 当开发者需要测试 Blink 引擎的某个特定功能时，可能会编写使用 `Internals` 接口的 C++ 测试用例。
2. **调试测试用例失败的原因:** 如果一个使用了 `Internals` 的测试用例失败，开发者可能会查看 `internals.cc` 的代码，以了解 `Internals` 提供的功能是如何实现的，从而找到测试用例的错误或 Blink 引擎的 bug。
3. **理解 Blink 内部实现:**  开发者可能会为了更深入地理解 Blink 引擎的内部工作原理，而研究 `internals.cc` 中提供的接口和实现。
4. **代码审查:** 在代码审查过程中，开发者会审查 `internals.cc` 的修改，确保测试代码的正确性和质量。

**总结第一部分的功能:**

总而言之，`blink/renderer/core/testing/internals.cc` 文件的第一部分定义了 `Internals` 类，它是一个**测试工具集**，允许 Blink 开发者通过 C++ 代码直接访问和操纵 Blink 引擎的内部状态，以便编写更强大、更精细的单元测试和集成测试。它提供了访问 DOM、CSS 样式、帧结构、运行时设置等内部信息的接口，并包含一些用于辅助测试的工具函数，例如重置页面状态和创建测试用的 Stream 对象。这个文件是 Blink 引擎开发和质量保证的关键组成部分。

### 提示词
```
这是目录为blink/renderer/core/testing/internals.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
/*
 * Copyright (C) 2012 Google Inc. All rights reserved.
 * Copyright (C) 2013 Apple Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1.  Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 * 2.  Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE AND ITS CONTRIBUTORS "AS IS" AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL APPLE OR ITS CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/core/testing/internals.h"

#include <atomic>
#include <memory>
#include <optional>
#include <utility>

#include "base/functional/function_ref.h"
#include "base/numerics/safe_conversions.h"
#include "base/process/process_handle.h"
#include "base/task/single_thread_task_runner.h"
#include "cc/layers/picture_layer.h"
#include "cc/trees/layer_tree_host.h"
#include "gpu/command_buffer/client/gles2_interface.h"
#include "third_party/abseil-cpp/absl/utility/utility.h"
#include "third_party/blink/public/common/widget/device_emulation_params.h"
#include "third_party/blink/public/mojom/devtools/inspector_issue.mojom-blink.h"
#include "third_party/blink/public/mojom/favicon/favicon_url.mojom-blink.h"
#include "third_party/blink/public/mojom/input/focus_type.mojom-blink.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/platform/web_graphics_context_3d_provider.h"
#include "third_party/blink/renderer/bindings/core/v8/script_function.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/core/animation/document_timeline.h"
#include "third_party/blink/renderer/core/css/css_property_names.h"
#include "third_party/blink/renderer/core/css/parser/css_property_parser.h"
#include "third_party/blink/renderer/core/css/properties/css_unresolved_property.h"
#include "third_party/blink/renderer/core/css/style_engine.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/dom_node_ids.h"
#include "third_party/blink/renderer/core/dom/dom_string_list.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/dom/flat_tree_traversal.h"
#include "third_party/blink/renderer/core/dom/pseudo_element.h"
#include "third_party/blink/renderer/core/dom/range.h"
#include "third_party/blink/renderer/core/dom/shadow_root.h"
#include "third_party/blink/renderer/core/dom/static_node_list.h"
#include "third_party/blink/renderer/core/dom/tree_scope.h"
#include "third_party/blink/renderer/core/editing/drag_caret.h"
#include "third_party/blink/renderer/core/editing/editor.h"
#include "third_party/blink/renderer/core/editing/ephemeral_range.h"
#include "third_party/blink/renderer/core/editing/frame_selection.h"
#include "third_party/blink/renderer/core/editing/iterators/text_iterator.h"
#include "third_party/blink/renderer/core/editing/markers/document_marker.h"
#include "third_party/blink/renderer/core/editing/markers/document_marker_controller.h"
#include "third_party/blink/renderer/core/editing/markers/spell_check_marker.h"
#include "third_party/blink/renderer/core/editing/markers/suggestion_marker_properties.h"
#include "third_party/blink/renderer/core/editing/markers/text_match_marker.h"
#include "third_party/blink/renderer/core/editing/plain_text_range.h"
#include "third_party/blink/renderer/core/editing/selection_template.h"
#include "third_party/blink/renderer/core/editing/serializers/serialization.h"
#include "third_party/blink/renderer/core/editing/spellcheck/idle_spell_check_controller.h"
#include "third_party/blink/renderer/core/editing/spellcheck/spell_check_requester.h"
#include "third_party/blink/renderer/core/editing/spellcheck/spell_checker.h"
#include "third_party/blink/renderer/core/exported/web_view_impl.h"
#include "third_party/blink/renderer/core/frame/event_handler_registry.h"
#include "third_party/blink/renderer/core/frame/frame_console.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_client.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/performance_monitor.h"
#include "third_party/blink/renderer/core/frame/remote_dom_window.h"
#include "third_party/blink/renderer/core/frame/report.h"
#include "third_party/blink/renderer/core/frame/reporting_context.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/frame/test_report_body.h"
#include "third_party/blink/renderer/core/frame/visual_viewport.h"
#include "third_party/blink/renderer/core/geometry/dom_point.h"
#include "third_party/blink/renderer/core/geometry/dom_rect.h"
#include "third_party/blink/renderer/core/geometry/dom_rect_list.h"
#include "third_party/blink/renderer/core/html/canvas/canvas_context_creation_attributes_core.h"
#include "third_party/blink/renderer/core/html/canvas/canvas_font_cache.h"
#include "third_party/blink/renderer/core/html/canvas/canvas_rendering_context.h"
#include "third_party/blink/renderer/core/html/canvas/html_canvas_element.h"
#include "third_party/blink/renderer/core/html/custom/custom_element.h"
#include "third_party/blink/renderer/core/html/forms/form_controller.h"
#include "third_party/blink/renderer/core/html/forms/html_input_element.h"
#include "third_party/blink/renderer/core/html/forms/html_select_element.h"
#include "third_party/blink/renderer/core/html/forms/html_text_area_element.h"
#include "third_party/blink/renderer/core/html/forms/text_control_inner_elements.h"
#include "third_party/blink/renderer/core/html/html_iframe_element.h"
#include "third_party/blink/renderer/core/html/html_image_element.h"
#include "third_party/blink/renderer/core/html/media/html_media_element.h"
#include "third_party/blink/renderer/core/html/media/html_video_element.h"
#include "third_party/blink/renderer/core/html/media/remote_playback_controller.h"
#include "third_party/blink/renderer/core/html/shadow/shadow_element_names.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/input/event_handler.h"
#include "third_party/blink/renderer/core/input/keyboard_event_manager.h"
#include "third_party/blink/renderer/core/inspector/inspector_audits_issue.h"
#include "third_party/blink/renderer/core/inspector/inspector_issue.h"
#include "third_party/blink/renderer/core/inspector/inspector_issue_conversion.h"
#include "third_party/blink/renderer/core/inspector/main_thread_debugger.h"
#include "third_party/blink/renderer/core/intersection_observer/intersection_observer.h"
#include "third_party/blink/renderer/core/layout/layout_object.h"
#include "third_party/blink/renderer/core/layout/layout_tree_as_text.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/lcp_critical_path_predictor/element_locator.h"
#include "third_party/blink/renderer/core/lcp_critical_path_predictor/lcp_critical_path_predictor.h"
#include "third_party/blink/renderer/core/loader/document_loader.h"
#include "third_party/blink/renderer/core/loader/frame_loader.h"
#include "third_party/blink/renderer/core/loader/history_item.h"
#include "third_party/blink/renderer/core/page/chrome_client.h"
#include "third_party/blink/renderer/core/page/focus_controller.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/page/print_context.h"
#include "third_party/blink/renderer/core/page/scrolling/root_scroller_controller.h"
#include "third_party/blink/renderer/core/page/spatial_navigation_controller.h"
#include "third_party/blink/renderer/core/page/touch_adjustment.h"
#include "third_party/blink/renderer/core/page/validation_message_client.h"
#include "third_party/blink/renderer/core/page/viewport_description.h"
#include "third_party/blink/renderer/core/paint/paint_layer.h"
#include "third_party/blink/renderer/core/paint/paint_layer_scrollable_area.h"
#include "third_party/blink/renderer/core/probe/core_probes.h"
#include "third_party/blink/renderer/core/script/import_map.h"
#include "third_party/blink/renderer/core/script/modulator.h"
#include "third_party/blink/renderer/core/scroll/mac_scrollbar_animator.h"
#include "third_party/blink/renderer/core/scroll/programmatic_scroll_animator.h"
#include "third_party/blink/renderer/core/scroll/scroll_animator_base.h"
#include "third_party/blink/renderer/core/scroll/scrollbar_theme.h"
#include "third_party/blink/renderer/core/streams/readable_stream.h"
#include "third_party/blink/renderer/core/streams/readable_stream_default_controller_with_script_scope.h"
#include "third_party/blink/renderer/core/streams/readable_stream_transferring_optimizer.h"
#include "third_party/blink/renderer/core/streams/underlying_sink_base.h"
#include "third_party/blink/renderer/core/streams/underlying_source_base.h"
#include "third_party/blink/renderer/core/streams/writable_stream.h"
#include "third_party/blink/renderer/core/streams/writable_stream_transferring_optimizer.h"
#include "third_party/blink/renderer/core/style_property_shorthand.h"
#include "third_party/blink/renderer/core/svg/svg_image_element.h"
#include "third_party/blink/renderer/core/svg_names.h"
#include "third_party/blink/renderer/core/testing/callback_function_test.h"
#include "third_party/blink/renderer/core/testing/dictionary_test.h"
#include "third_party/blink/renderer/core/testing/gc_observation.h"
#include "third_party/blink/renderer/core/testing/hit_test_layer_rect.h"
#include "third_party/blink/renderer/core/testing/hit_test_layer_rect_list.h"
#include "third_party/blink/renderer/core/testing/internal_runtime_flags.h"
#include "third_party/blink/renderer/core/testing/internal_settings.h"
#include "third_party/blink/renderer/core/testing/internals_ukm_recorder.h"
#include "third_party/blink/renderer/core/testing/mock_hyphenation.h"
#include "third_party/blink/renderer/core/testing/origin_trials_test.h"
#include "third_party/blink/renderer/core/testing/record_test.h"
#include "third_party/blink/renderer/core/testing/scoped_mock_overlay_scrollbars.h"
#include "third_party/blink/renderer/core/testing/sequence_test.h"
#include "third_party/blink/renderer/core/testing/static_selection.h"
#include "third_party/blink/renderer/core/testing/type_conversions.h"
#include "third_party/blink/renderer/core/testing/union_types_test.h"
#include "third_party/blink/renderer/core/timezone/timezone_controller.h"
#include "third_party/blink/renderer/core/timing/dom_window_performance.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_array_buffer.h"
#include "third_party/blink/renderer/core/workers/worker_thread.h"
#include "third_party/blink/renderer/platform/bindings/exception_messages.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/bindings/v8_throw_exception.h"
#include "third_party/blink/renderer/platform/graphics/compositing/paint_artifact_compositor.h"
#include "third_party/blink/renderer/platform/graphics/paint/raster_invalidation_tracking.h"
#include "third_party/blink/renderer/platform/heap/cross_thread_handle.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/instrumentation/instance_counters.h"
#include "third_party/blink/renderer/platform/instrumentation/tracing/trace_event.h"
#include "third_party/blink/renderer/platform/language.h"
#include "third_party/blink/renderer/platform/loader/fetch/memory_cache.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_fetcher.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_load_priority.h"
#include "third_party/blink/renderer/platform/network/network_state_notifier.h"
#include "third_party/blink/renderer/platform/scheduler/public/thread.h"
#include "third_party/blink/renderer/platform/testing/url_test_helpers.h"
#include "third_party/blink/renderer/platform/text/layout_locale.h"
#include "third_party/blink/renderer/platform/weborigin/scheme_registry.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_copier_base.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_copier_std.h"
#include "third_party/blink/renderer/platform/wtf/dtoa.h"
#include "third_party/blink/renderer/platform/wtf/text/string_buffer.h"
#include "third_party/blink/renderer/platform/wtf/text/text_encoding_registry.h"
#include "third_party/blink/renderer/platform/wtf/threading.h"
#include "ui/base/cursor/cursor.h"
#include "ui/base/cursor/mojom/cursor_type.mojom-blink.h"
#include "ui/base/ui_base_features.h"
#include "ui/gfx/geometry/point_conversions.h"
#include "ui/gfx/geometry/rect.h"
#include "v8/include/v8.h"

namespace blink {

using ui::mojom::ImeTextSpanThickness;
using ui::mojom::ImeTextSpanUnderlineStyle;

namespace {

ScopedMockOverlayScrollbars* g_mock_overlay_scrollbars = nullptr;

void ResetMockOverlayScrollbars() {
  if (g_mock_overlay_scrollbars)
    delete g_mock_overlay_scrollbars;
  g_mock_overlay_scrollbars = nullptr;
}

class UseCounterImplObserverImpl final : public UseCounterImpl::Observer {
 public:
  UseCounterImplObserverImpl(ScriptPromiseResolver<IDLUndefined>* resolver,
                             WebFeature feature)
      : resolver_(resolver), feature_(feature) {}
  UseCounterImplObserverImpl(const UseCounterImplObserverImpl&) = delete;
  UseCounterImplObserverImpl& operator=(const UseCounterImplObserverImpl&) =
      delete;

  bool OnCountFeature(WebFeature feature) final {
    if (feature_ != feature)
      return false;
    resolver_->Resolve();
    return true;
  }

  void Trace(Visitor* visitor) const override {
    UseCounterImpl::Observer::Trace(visitor);
    visitor->Trace(resolver_);
  }

 private:
  Member<ScriptPromiseResolver<IDLUndefined>> resolver_;
  WebFeature feature_;
};

class TestReadableStreamSource : public UnderlyingSourceBase {
 public:
  class Generator;

  using Reply = CrossThreadOnceFunction<void(std::unique_ptr<Generator>)>;
  using OptimizerCallback =
      CrossThreadOnceFunction<void(scoped_refptr<base::SingleThreadTaskRunner>,
                                   Reply)>;

  enum class Type {
    kWithNullOptimizer,
    kWithPerformNullOptimizer,
    kWithObservableOptimizer,
    kWithPerfectOptimizer,
  };

  class Generator final {
    USING_FAST_MALLOC(Generator);

   public:
    explicit Generator(int max_count) : max_count_(max_count) {}

    std::optional<int> Generate() {
      if (count_ >= max_count_) {
        return std::nullopt;
      }
      ++count_;
      return current_++;
    }

    void Add(int n) { current_ += n; }

   private:
    friend class Optimizer;

    int current_ = 0;
    int count_ = 0;
    const int max_count_;
  };

  class Optimizer final : public ReadableStreamTransferringOptimizer {
    USING_FAST_MALLOC(Optimizer);

   public:
    Optimizer(scoped_refptr<base::SingleThreadTaskRunner> task_runner,
              OptimizerCallback callback,
              Type type)
        : task_runner_(std::move(task_runner)),
          callback_(std::move(callback)),
          type_(type) {}

    UnderlyingSourceBase* PerformInProcessOptimization(
        ScriptState* script_state) override;

   private:
    scoped_refptr<base::SingleThreadTaskRunner> task_runner_;
    OptimizerCallback callback_;
    const Type type_;
  };

  TestReadableStreamSource(ScriptState* script_state, Type type)
      : UnderlyingSourceBase(script_state), type_(type) {}

  ScriptPromise<IDLUndefined> Start(ScriptState* script_state) override {
    if (generator_) {
      return ToResolvedUndefinedPromise(script_state);
    }
    resolver_ =
        MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(script_state);
    return resolver_->Promise();
  }

  ScriptPromise<IDLUndefined> Pull(ScriptState* script_state,
                                   ExceptionState&) override {
    if (!generator_) {
      return ToResolvedUndefinedPromise(script_state);
    }

    const auto result = generator_->Generate();
    if (!result) {
      Controller()->Close();
      return ToResolvedUndefinedPromise(script_state);
    }
    Controller()->Enqueue(
        v8::Integer::New(script_state->GetIsolate(), *result));
    return ToResolvedUndefinedPromise(script_state);
  }

  std::unique_ptr<ReadableStreamTransferringOptimizer>
  CreateTransferringOptimizer(ScriptState* script_state) {
    switch (type_) {
      case Type::kWithNullOptimizer:
        return nullptr;
      case Type::kWithPerformNullOptimizer:
        return std::make_unique<ReadableStreamTransferringOptimizer>();
      case Type::kWithObservableOptimizer:
      case Type::kWithPerfectOptimizer:
        ExecutionContext* context = ExecutionContext::From(script_state);
        return std::make_unique<Optimizer>(
            context->GetTaskRunner(TaskType::kInternalDefault),
            CrossThreadBindOnce(&TestReadableStreamSource::Detach,
                                MakeUnwrappingCrossThreadWeakHandle(this)),
            type_);
    }
  }

  void Attach(std::unique_ptr<Generator> generator) {
    if (type_ == Type::kWithObservableOptimizer) {
      generator->Add(100);
    }
    generator_ = std::move(generator);
    if (resolver_) {
      resolver_->Resolve();
    }
  }

  void Detach(scoped_refptr<base::SingleThreadTaskRunner> task_runner,
              Reply reply) {
    Controller()->Close();
    PostCrossThreadTask(
        *task_runner, FROM_HERE,
        CrossThreadBindOnce(std::move(reply), std::move(generator_)));
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(resolver_);
    UnderlyingSourceBase::Trace(visitor);
  }

 private:
  const Type type_;
  std::unique_ptr<Generator> generator_;
  Member<ScriptPromiseResolver<IDLUndefined>> resolver_;
};

UnderlyingSourceBase*
TestReadableStreamSource::Optimizer::PerformInProcessOptimization(
    ScriptState* script_state) {
  TestReadableStreamSource* source =
      MakeGarbageCollected<TestReadableStreamSource>(script_state, type_);
  ExecutionContext* context = ExecutionContext::From(script_state);

  Reply reply = CrossThreadBindOnce(&TestReadableStreamSource::Attach,
                                    MakeUnwrappingCrossThreadHandle(source));

  PostCrossThreadTask(
      *task_runner_, FROM_HERE,
      CrossThreadBindOnce(std::move(callback_),
                          context->GetTaskRunner(TaskType::kInternalDefault),
                          std::move(reply)));
  return source;
}

class TestWritableStreamSink final : public UnderlyingSinkBase {
 public:
  class InternalSink;

  using Reply = CrossThreadOnceFunction<void(std::unique_ptr<InternalSink>)>;
  using OptimizerCallback =
      CrossThreadOnceFunction<void(scoped_refptr<base::SingleThreadTaskRunner>,
                                   Reply)>;
  enum class Type {
    kWithNullOptimizer,
    kWithPerformNullOptimizer,
    kWithObservableOptimizer,
    kWithPerfectOptimizer,
  };

  class InternalSink final {
    USING_FAST_MALLOC(InternalSink);

   public:
    InternalSink(scoped_refptr<base::SingleThreadTaskRunner> task_runner,
                 CrossThreadOnceFunction<void(std::string)> success_callback,
                 CrossThreadOnceFunction<void()> error_callback)
        : task_runner_(std::move(task_runner)),
          success_callback_(std::move(success_callback)),
          error_callback_(std::move(error_callback)) {}

    void Append(const std::string& s) { result_.append(s); }
    void Close() {
      PostCrossThreadTask(
          *task_runner_, FROM_HERE,
          CrossThreadBindOnce(std::move(success_callback_), result_));
    }
    void Abort() {
      PostCrossThreadTask(*task_runner_, FROM_HERE, std::move(error_callback_));
    }

    // We don't use WTF::String because this object can be accessed from
    // multiple threads.
    std::string result_;

    scoped_refptr<base::SingleThreadTaskRunner> task_runner_;
    CrossThreadOnceFunction<void(std::string)> success_callback_;
    CrossThreadOnceFunction<void()> error_callback_;
  };

  class Optimizer final : public WritableStreamTransferringOptimizer {
    USING_FAST_MALLOC(Optimizer);

   public:
    Optimizer(
        scoped_refptr<base::SingleThreadTaskRunner> task_runner,
        OptimizerCallback callback,
        scoped_refptr<base::RefCountedData<std::atomic_bool>> optimizer_flag,
        Type type)
        : task_runner_(std::move(task_runner)),
          callback_(std::move(callback)),
          optimizer_flag_(std::move(optimizer_flag)),
          type_(type) {}

    UnderlyingSinkBase* PerformInProcessOptimization(
        ScriptState* script_state) override;

   private:
    scoped_refptr<base::SingleThreadTaskRunner> task_runner_;
    OptimizerCallback callback_;
    scoped_refptr<base::RefCountedData<std::atomic_bool>> optimizer_flag_;
    const Type type_;
  };

  explicit TestWritableStreamSink(ScriptState* script_state, Type type)
      : type_(type),
        optimizer_flag_(
            base::MakeRefCounted<base::RefCountedData<std::atomic_bool>>(
                std::in_place,
                false)) {}

  ScriptPromise<IDLUndefined> start(ScriptState* script_state,
                                    WritableStreamDefaultController*,
                                    ExceptionState&) override {
    if (internal_sink_) {
      return ToResolvedUndefinedPromise(script_state);
    }
    start_resolver_ =
        MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(script_state);
    return start_resolver_->Promise();
  }
  ScriptPromise<IDLUndefined> write(ScriptState* script_state,
                                    ScriptValue chunk,
                                    WritableStreamDefaultController*,
                                    ExceptionState&) override {
    DCHECK(internal_sink_);
    internal_sink_->Append(
        ToCoreString(script_state->GetIsolate(),
                     chunk.V8Value()
                         ->ToString(script_state->GetContext())
                         .ToLocalChecked())
            .Utf8());
    return ToResolvedUndefinedPromise(script_state);
  }
  ScriptPromise<IDLUndefined> close(ScriptState* script_state,
                                    ExceptionState&) override {
    DCHECK(internal_sink_);
    closed_ = true;
    if (!optimizer_flag_->data.load()) {
      // The normal closure case.
      internal_sink_->Close();
      return ToResolvedUndefinedPromise(script_state);
    }

    // When the optimizer is active, we need to detach `internal_sink_` and
    // pass it to the optimizer (i.e., the sink in the destination realm).
    if (detached_) {
      PostCrossThreadTask(
          *reply_task_runner_, FROM_HERE,
          CrossThreadBindOnce(std::move(reply_), std::move(internal_sink_)));
    }
    return ToResolvedUndefinedPromise(script_state);
  }
  ScriptPromise<IDLUndefined> abort(ScriptState* script_state,
                                    ScriptValue reason,
                                    ExceptionState&) override {
    return ToResolvedUndefinedPromise(script_state);
  }

  void Attach(std::unique_ptr<InternalSink> internal_sink) {
    DCHECK(!internal_sink_);

    if (type_ == Type::kWithObservableOptimizer) {
      internal_sink->Append("A");
    }

    internal_sink_ = std::move(internal_sink);
    if (start_resolver_) {
      start_resolver_->Resolve();
    }
  }

  void Detach(scoped_refptr<base::SingleThreadTaskRunner> task_runner,
              Reply reply) {
    detached_ = true;

    // We need to wait for the close signal before actually detaching
    // `internal_sink_`.
    if (closed_) {
      PostCrossThreadTask(
          *task_runner, FROM_HERE,
          CrossThreadBindOnce(std::move(reply), std::move(internal_sink_)));
    } else {
      reply_ = std::move(reply);
      reply_task_runner_ = std::move(task_runner);
    }
  }

  std::unique_ptr<WritableStreamTransferringOptimizer>
  CreateTransferringOptimizer(ScriptState* script_state) {
    DCHECK(internal_sink_);

    if (type_ == Type::kWithNullOptimizer) {
      return nullptr;
    }

    ExecutionContext* context = ExecutionContext::From(script_state);
    return std::make_unique<Optimizer>(
        context->GetTaskRunner(TaskType::kInternalDefault),
        CrossThreadBindOnce(&TestWritableStreamSink::Detach,
                            MakeUnwrappingCrossThreadWeakHandle(this)),
        optimizer_flag_, type_);
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(start_resolver_);
    UnderlyingSinkBase::Trace(visitor);
  }

  static void Resolve(ScriptPromiseResolver<IDLString>* resolver,
                      std::string result) {
    resolver->Resolve(String::FromUTF8(result));
  }
  static void Reject(ScriptPromiseResolverBase* resolver) {
    ScriptState* script_state = resolver->GetScriptState();
    ScriptState::Scope scope(script_state);
    resolver->Reject(
        V8ThrowException::CreateTypeError(script_state->GetIsolate(), "error"));
  }

 private:
  const Type type_;
  // `optimizer_flag_` is always non_null. The flag referenced is false
  // initially, and set atomically when the associated optimizer is activated.
  scoped_refptr<base::RefCountedData<std::atomic_bool>> optimizer_flag_;
  std::unique_ptr<InternalSink> internal_sink_;
  Member<ScriptPromiseResolver<IDLUndefined>> start_resolver_;
  bool closed_ = false;
  bool detached_ = false;
  Reply reply_;
  scoped_refptr<base::SingleThreadTaskRunner> reply_task_runner_;
};

UnderlyingSinkBase*
TestWritableStreamSink::Optimizer::PerformInProcessOptimization(
    ScriptState* script_state) {
  if (type_ == Type::kWithPerformNullOptimizer) {
    return nullptr;
  }
  TestWritableStreamSink* sink =
      MakeGarbageCollected<TestWritableStreamSink>(script_state, type_);

  // Set the flag atomically, to notify that this optimizer is active.
  optimizer_flag_->data.store(true);

  ExecutionContext* context = ExecutionContext::From(script_state);
  Reply reply = CrossThreadBindOnce(&TestWritableStreamSink::Attach,
                                    MakeUnwrappingCrossThreadHandle(sink));
  PostCrossThreadTask(
      *task_runner_, FROM_HERE,
      CrossThreadBindOnce(std::move(callback_),
                          context->GetTaskRunner(TaskType::kInternalDefault),
                          std::move(reply)));
  return sink;
}

void OnLCPPredicted(ScriptPromiseResolver<IDLString>* resolver,
                    const Element* lcp_element) {
  const ElementLocator locator =
      lcp_element ? element_locator::OfElement(*lcp_element) : ElementLocator();
  resolver->Resolve(element_locator::ToStringForTesting(locator));
}

}  // namespace

static std::optional<DocumentMarker::MarkerType> MarkerTypeFrom(
    const String& marker_type) {
  if (EqualIgnoringASCIICase(marker_type, "Spelling"))
    return DocumentMarker::kSpelling;
  if (EqualIgnoringASCIICase(marker_type, "Grammar"))
    return DocumentMarker::kGrammar;
  if (EqualIgnoringASCIICase(marker_type, "TextMatch"))
    return DocumentMarker::kTextMatch;
  if (EqualIgnoringASCIICase(marker_type, "Composition"))
    return DocumentMarker::kComposition;
  if (EqualIgnoringASCIICase(marker_type, "ActiveSuggestion"))
    return DocumentMarker::kActiveSuggestion;
  if (EqualIgnoringASCIICase(marker_type, "Suggestion"))
    return DocumentMarker::kSuggestion;
  return std::nullopt;
}

static std::optional<DocumentMarker::MarkerTypes> MarkerTypesFrom(
    const String& marker_type) {
  if (marker_type.empty() || EqualIgnoringASCIICase(marker_type, "all"))
    return DocumentMarker::MarkerTypes::All();
  std::optional<DocumentMarker::MarkerType> type = MarkerTypeFrom(marker_type);
  if (!type)
    return std::nullopt;
  return DocumentMarker::MarkerTypes(type.value());
}

static SpellCheckRequester* GetSpellCheckRequester(Document* document) {
  if (!document || !document->GetFrame())
    return nullptr;
  return &document->GetFrame()->GetSpellChecker().GetSpellCheckRequester();
}

static ScrollableArea* ScrollableAreaForNode(Node* node) {
  if (!node)
    return nullptr;

  if (auto* box = DynamicTo<LayoutBox>(node->GetLayoutObject()))
    return box->GetScrollableArea();
  return nullptr;
}

void Internals::ResetToConsistentState(Page* page) {
  DCHECK(page);

  page->SetIsCursorVisible(true);
  // Ensure the PageScaleFactor always stays within limits, if the test changed
  // the limits.
  page->SetDefaultPageScaleLimits(1, 4);
  page->SetPageScaleFactor(1);
  page->GetChromeClient().GetWebView()->DisableDeviceEmulation();

  // Ensure timers are reset so timers such as EventHandler's |hover_timer_| do
  // not cause additional lifecycle updates.
  for (Frame* frame = page->MainFrame(); frame;
       frame = frame->Tree().TraverseNext()) {
    if (auto* local_frame = DynamicTo<LocalFrame>(frame))
      local_frame->GetEventHandler().Clear();
  }

  LocalFrame* frame = page->DeprecatedLocalMainFrame();
  frame->View()->LayoutViewport()->SetScrollOffset(
      ScrollOffset(), mojom::blink::ScrollType::kProgrammatic);
  OverrideUserPreferredLanguagesForTesting(Vector<AtomicString>());

  KeyboardEventManager::SetCurrentCapsLockState(
      OverrideCapsLockState::kDefault);

  IntersectionObserver::SetThrottleDelayEnabledForTesting(true);
  ResetMockOverlayScrollbars();

  Page::SetMaxNumberOfFramesToTenForTesting(false);
}

Internals::Internals(ExecutionContext* context)
    : runtime_flags_(InternalRuntimeFlags::create()),
      document_(To<LocalDOMWindow>(context)->document()) {
  document_->Fetcher()->EnableIsPreloadedForTest();
}

LocalFrame* Internals::GetFrame() const {
  if (!document_)
    return nullptr;
  return document_->GetFrame();
}

InternalSettings* Internals::settings() const {
  if (!document_)
    return nullptr;
  Page* page = document_->GetPage();
  if (!page)
    return nullptr;
  return InternalSettings::From(*page);
}

InternalRuntimeFlags* Internals::runtimeFlags() const {
  return runtime_flags_.Get();
}

unsigned Internals::workerThreadCount() const {
  return WorkerThread::WorkerThreadCount();
}

GCObservation* Internals::observeGC(ScriptValue script_value,
                                    ExceptionState& exception_state) {
  v8::Local<v8::Value> observed_value = script_value.V8Value();
  DCHECK(!observed_value.IsEmpty());
  if (observed_value->IsNull() || observed_value->IsUndefined()) {
    exception_state.ThrowTypeError("value to observe is null or undefined");
    return nullptr;
  }

  return MakeGarbageCollected<GCObservation>(script_value.GetIsolate(),
                                             observed_value);
}

unsigned Internals::updateStyleAndReturnAffectedElementCount(
    ExceptionState& exception_state) const {
  if (!document_) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidAccessError,
                                      "No context document is available.");
    return 0;
  }

  unsigned before_count = document_->GetStyleEngine().StyleForElementCount();
  document_->UpdateStyleAndLayoutTree();
  return document_->GetStyleEngine().StyleForElementCount() - before_count;
}

unsigned Internals::styleForElementCount(
    ExceptionState& exception_state) const {
  if (!document_) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidAccessError,
```