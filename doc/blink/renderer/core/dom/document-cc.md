Response:
The user wants a summary of the functionalities of the `blink/renderer/core/dom/document.cc` file in the Chromium Blink engine, based on the provided code snippet. I need to analyze the included headers and the code within the provided snippet to infer the responsibilities of the `Document` class and its related functionalities implemented in this file.

Here's a breakdown of the thought process:

1. **Identify the Core Class:** The filename `document.cc` and the `#include "third_party/blink/renderer/core/dom/document.h"` clearly indicate that this file implements the `Document` class. This class represents the root of the HTML or XML document tree.

2. **Analyze Included Headers:**  The numerous `#include` statements reveal the dependencies and thus the functionalities of the `Document` class. I will categorize these includes to understand different aspects of the `Document`'s role.

    * **Core DOM:** Headers like `Attr.h`, `Element.h`, `Node.h`, `Comment.h`, `Text.h`, `DocumentFragment.h`, `DocumentType.h` point to the fundamental DOM manipulation capabilities. The `Document` class is responsible for creating, managing, and querying these DOM nodes.

    * **HTML Specific:** Includes like `HTMLBodyElement.h`, `HTMLDivElement.h`, `HTMLAnchorElement.h`, etc., indicate that `Document` handles HTML-specific elements and their behavior.

    * **CSS Integration:** Headers like `CSSStyleSheet.h`, `CSSStyleDeclaration.h`, `StyleResolver.h`, `MediaQueryList.h` suggest that the `Document` is deeply involved in managing and applying CSS styles.

    * **JavaScript Interaction:**  Headers such as `ScriptController.h`, `ScriptPromiseResolver.h`, `ScriptValue.h` highlight the `Document`'s role as a bridge between the DOM and JavaScript.

    * **Events:** Includes like `Event.h`, `EventListener.h`, and various specific event types (e.g., `ClickEvent.h`, `LoadEvent.h`) indicate that the `Document` is a central point for event handling and dispatching.

    * **Loading and Parsing:** Headers like `DocumentLoader.h`, `HTMLDocumentParser.h` suggest the `Document` is involved in the process of loading and parsing HTML content.

    * **Rendering and Layout:**  Headers like `LayoutView.h`, `PaintLayer.h` imply the `Document` is connected to the rendering and layout of the web page.

    * **Accessibility:** `AXObjectCache.h` signifies the `Document`'s role in providing accessibility information.

    * **Frame Management:** Headers like `LocalFrame.h`, `FrameView.h` indicate the relationship between a `Document` and its containing frame.

    * **Navigation and History:** `History.h` suggests the `Document`'s involvement in browser history management.

    * **Security:** `ContentSecurityPolicy.h` shows that the `Document` enforces security policies.

    * **Metrics and Performance:** Includes related to `ukm` and tracing suggest the `Document` collects and reports performance data.

3. **Analyze Code Snippet Details:** The provided code snippet contains:

    * **Copyright Information:** Standard copyright notices.
    * **Includes:** A long list of header files.
    * **Forward Declarations:**  `namespace blink { class Document; }` and similar patterns.
    * **Internal Helper Functions:**  Functions like `IsInIndeterminateObjectAncestor`, `NotifyPriorityScrollAnchorStatusChanged`, `DefaultFaviconAllowedByCSP`. These give specific insights into certain functionalities.
    * **Constants:**  `kUkmSamplingRate`, `kCMaxWriteRecursionDepth`, `kCLayoutScheduleThreshold` hint at internal mechanisms and limitations.
    * **Static Inline Functions:** `IsValidNameStart` and `IsValidNamePart` relate to XML/HTML name validation, likely used during parsing or element creation.

4. **Synthesize Functionalities:** Based on the header analysis and code snippets, I can group the functionalities of `blink/renderer/core/dom/document.cc`:

    * **Core DOM Management:**  Representing the document root, creating and managing DOM nodes (elements, text nodes, comments, etc.), providing methods for querying the DOM (e.g., `getElementById`, `querySelector`).
    * **HTML Document Representation:**  Specifically handling HTML documents and their structure, including elements like `<body>`, `<head>`, etc.
    * **CSS Style Application:**  Managing associated stylesheets, resolving and applying styles to elements, handling media queries.
    * **JavaScript Integration:** Providing the interface through which JavaScript can interact with the DOM, executing scripts, managing event listeners.
    * **Event Handling:**  Dispatching and handling events within the document.
    * **Document Loading and Parsing:**  Orchestrating the process of fetching and parsing HTML content.
    * **Rendering and Layout Integration:**  Being a key component in the rendering pipeline, triggering layout calculations.
    * **Accessibility Support:**  Providing data for accessibility tools.
    * **Frame Integration:**  Being associated with a specific frame in the browser window.
    * **Navigation and History Management:**  Interacting with the browser's history mechanism.
    * **Security Enforcement:**  Applying Content Security Policy.
    * **Performance Monitoring:**  Collecting and reporting performance metrics.
    * **Custom Element Support:** Handling custom elements.
    * **Focus Management:** Tracking the currently focused element.
    * **Scroll Management:**  Managing scrolling within the document.

5. **Relate to JavaScript, HTML, and CSS:** Provide concrete examples of how the `Document` class interacts with these web technologies.

    * **JavaScript:**  `document.getElementById('myElement')`, `document.createElement('div')`, `element.addEventListener('click', function() { ... })`.
    * **HTML:** Representing the entire HTML structure, including tags like `<html>`, `<head>`, `<body>`, and all other HTML elements.
    * **CSS:**  Managing `<style>` tags and linked stylesheets, applying styles based on selectors, triggering layout and rendering changes based on CSS.

6. **Hypothesize Input/Output for Logic:** For functions like `IsValidNameStart` and `IsValidNamePart`, I can provide examples of valid and invalid inputs and their corresponding boolean outputs.

7. **Identify Common User/Programming Errors:** Think about common mistakes developers make when working with the DOM, such as accessing elements before they are loaded, incorrect use of selectors, or memory leaks with event listeners.

8. **Trace User Actions:** Describe a typical user interaction flow that would lead to the execution of code within `document.cc`, starting from opening a web page.

9. **Structure the Output:** Organize the information logically with clear headings and bullet points, as requested by the user. Specifically address the request to summarize the functionality for this *first* part of the file. Since this is the beginning of the file, the focus is on the fundamental responsibilities and setup of the `Document` class, as evidenced by the includes and initial definitions.

By following these steps, I can generate a comprehensive and accurate summary of the functionalities of the `blink/renderer/core/dom/document.cc` file based on the provided code.
Based on the provided code snippet, which represents the beginning of the `blink/renderer/core/dom/document.cc` file, here's a summary of its functionalities:

**Core Functionality: Foundation of the Document Object Model (DOM)**

This part of the `document.cc` file lays the groundwork for the `Document` class, a fundamental component in the Blink rendering engine. The `Document` class represents the root of the HTML or XML document tree and is responsible for:

* **Representing the Document:** It's the in-memory representation of a web page or XML document. This includes its structure, content, and associated resources.
* **DOM Tree Management:**  It acts as the container and manager for all the nodes (elements, text, comments, etc.) that make up the document tree. This involves mechanisms for creating, inserting, deleting, and traversing these nodes.
* **Connecting to the Frame:** The `Document` is associated with a specific `LocalFrame` within the browser. This connection allows the document to interact with the browsing context, including navigation and resource loading.
* **Style and Layout Integration:** It's a central point for connecting the document's structure with its visual presentation. This involves managing stylesheets, triggering style calculations, and initiating layout processes.
* **JavaScript Interaction:** It provides the primary interface through which JavaScript code interacts with the web page. This includes methods for accessing elements, manipulating the DOM, and handling events.
* **Event Handling:** The `Document` is a key participant in the browser's event system, responsible for dispatching and handling events that occur within the document.
* **Resource Management:** It plays a role in managing resources associated with the document, such as stylesheets, scripts, and images.
* **Security:** The `Document` is involved in enforcing security policies, such as Content Security Policy (CSP).
* **Lifecycle Management:**  It tracks the different stages of the document's lifecycle (e.g., loading, parsing, interactive, complete).
* **Metrics and Performance Monitoring:**  The code includes references to UKM (User Keyed Metrics) and tracing, suggesting the `Document` contributes to collecting and reporting performance data.

**Relationship with JavaScript, HTML, and CSS:**

* **JavaScript:** The `Document` object is the primary entry point for JavaScript to interact with the web page. For example:
    * **JavaScript can access elements:**  `document.getElementById('myElement')` - The `getElementById` method is implemented within the `Document` class (or its associated components).
    * **JavaScript can create new elements:** `document.createElement('div')` - The `createElement` method is a function of the `Document`.
    * **JavaScript can add event listeners:** `document.addEventListener('click', function() { ... })` - The `addEventListener` method is part of the `Document`'s event handling mechanism.
* **HTML:** The `Document` represents the parsed structure of the HTML. The HTML tags and their attributes are converted into a tree of `Node` and `Element` objects managed by the `Document`. For example:
    * When the browser parses an `<html>` tag, a corresponding `HTMLHtmlElement` object is created and becomes a child of the `Document`.
    * Similarly, `<body>`, `<head>`, `<div>`, etc., are represented by specific element objects within the `Document` tree.
* **CSS:** The `Document` is responsible for managing the CSS styles that apply to the page. For example:
    * When a `<link>` tag referencing a CSS file is encountered, the `Document` (or its associated loader) fetches and parses the CSS, creating `CSSStyleSheet` objects.
    * The `Document` uses the CSS information to calculate the final styles applied to each element, which influences how the page is rendered.

**Logic Inference (Based on Initial Snippet):**

* **Assumption:** The browser is in the process of loading and parsing an HTML page.
* **Input:** The HTML parser encounters the `<html>` tag.
* **Output:** The `Document` object (if not already created) is initialized. An `HTMLHtmlElement` is created and becomes the root element of the `Document`. The parsing process continues, and more nodes are added to the `Document` tree.

* **Assumption:** JavaScript code executes `document.getElementById('myDiv')`.
* **Input:** The string `"myDiv"` is passed to the `getElementById` method.
* **Output:** The `Document` searches its internal tree structure for an element with the ID "myDiv". If found, a pointer to that `Element` object is returned; otherwise, `nullptr` or a null object is returned.

**Common User or Programming Errors:**

* **Accessing DOM elements before they are loaded:**  JavaScript might try to access an element using `document.getElementById` before the HTML parser has processed that part of the document. This will result in the method returning `null`.
    * **Example:** A script placed in the `<head>` might try to access elements in the `<body>` before the `<body>` has been parsed.
* **Incorrect use of selectors:** When using methods like `document.querySelector` or `document.querySelectorAll`, incorrect CSS selectors will result in no elements being found.
    * **Example:**  Using `#myDiv.active` when the element only has the ID `myDiv`.
* **Memory leaks with event listeners:**  If event listeners are attached to `Document` or its elements and not properly removed when they are no longer needed, it can lead to memory leaks.

**User Operation and Debugging Clues:**

1. **User opens a web page:** The user enters a URL in the browser's address bar or clicks a link.
2. **Browser initiates request:** The browser sends a request to the server for the HTML content.
3. **HTML content received:** The server responds with the HTML markup.
4. **Parsing begins:** The Blink rendering engine's HTML parser starts to process the received HTML.
5. **`Document` object creation:** As the parser encounters the `<html>` tag, an instance of the `Document` class is created to represent the document.
6. **DOM tree construction:** The parser iterates through the HTML, creating corresponding `Node` and `Element` objects and adding them to the `Document`'s tree structure.
7. **JavaScript execution:** If the HTML includes `<script>` tags, the JavaScript code is executed. This code can then interact with the `Document` object to manipulate the DOM.
8. **CSS processing:**  The browser fetches and parses CSS, and the `Document` integrates these styles.
9. **Layout and rendering:** Based on the DOM and applied styles, the browser calculates the layout of the page and paints it on the screen.

**Debugging Clues to Reach `document.cc`:**

* **JavaScript errors related to DOM manipulation:** If JavaScript code throws errors because it cannot find an element (e.g., `TypeError: Cannot read property 'innerHTML' of null`), it indicates a problem with accessing the DOM, and the investigation might lead to the `Document`'s element lookup mechanisms.
* **Style not being applied correctly:** If elements are not styled as expected, it could point to issues in how the `Document` is managing or applying CSS styles, potentially leading a developer to examine the style resolution logic within `document.cc` or related files.
* **Unexpected behavior during page load:** If the page doesn't load or render correctly, debugging the parsing and initial setup of the `Document` might be necessary.
* **Memory leaks related to DOM nodes:** Tools that detect memory leaks might point to issues with how the `Document` is managing the lifecycle of DOM nodes.
* **Performance issues during DOM manipulation:**  If the page becomes slow when JavaScript interacts with the DOM, profiling and tracing could reveal bottlenecks within the `Document`'s methods for adding, removing, or querying nodes.

In summary, this initial part of `blink/renderer/core/dom/document.cc` is crucial for setting up the fundamental representation of a web document within the Blink engine, making it a cornerstone for all subsequent DOM manipulation, styling, and scripting interactions.

### 提示词
```
这是目录为blink/renderer/core/dom/document.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共11部分，请归纳一下它的功能
```

### 源代码
```cpp
/*
 * Copyright (C) 1999 Lars Knoll (knoll@kde.org)
 *           (C) 1999 Antti Koivisto (koivisto@kde.org)
 *           (C) 2001 Dirk Mueller (mueller@kde.org)
 *           (C) 2006 Alexey Proskuryakov (ap@webkit.org)
 * Copyright (C) 2004, 2005, 2006, 2007, 2008, 2009, 2011, 2012 Apple Inc. All
 * rights reserved.
 * Copyright (C) 2008, 2009 Torch Mobile Inc. All rights reserved.
 * (http://www.torchmobile.com/)
 * Copyright (C) 2008, 2009, 2011, 2012 Google Inc. All rights reserved.
 * Copyright (C) 2010 Nokia Corporation and/or its subsidiary(-ies)
 * Copyright (C) Research In Motion Limited 2010-2011. All rights reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public License
 * along with this library; see the file COPYING.LIB.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 */

#include "third_party/blink/renderer/core/dom/document.h"

#include <memory>
#include <optional>
#include <utility>

#include "base/auto_reset.h"
#include "base/containers/adapters.h"
#include "base/containers/contains.h"
#include "base/debug/dump_without_crashing.h"
#include "base/i18n/time_formatting.h"
#include "base/metrics/histogram_functions.h"
#include "base/not_fatal_until.h"
#include "base/notreached.h"
#include "base/ranges/algorithm.h"
#include "base/task/single_thread_task_runner.h"
#include "base/time/time.h"
#include "base/trace_event/trace_event.h"
#include "cc/animation/animation_host.h"
#include "cc/animation/animation_timeline.h"
#include "cc/input/overscroll_behavior.h"
#include "cc/input/scroll_snap_data.h"
#include "mojo/public/cpp/bindings/pending_remote.h"
#include "mojo/public/cpp/bindings/remote.h"
#include "mojo/public/mojom/base/text_direction.mojom-blink.h"
#include "net/base/schemeful_site.h"
#include "services/metrics/public/cpp/delegating_ukm_recorder.h"
#include "services/metrics/public/cpp/metrics_utils.h"
#include "services/metrics/public/cpp/mojo_ukm_recorder.h"
#include "services/metrics/public/cpp/ukm_builders.h"
#include "services/metrics/public/cpp/ukm_recorder.h"
#include "services/metrics/public/cpp/ukm_source_id.h"
#include "services/network/public/cpp/web_sandbox_flags.h"
#include "services/network/public/mojom/trust_tokens.mojom-blink.h"
#include "services/network/public/mojom/web_sandbox_flags.mojom-blink.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/common/permissions_policy/document_policy_features.h"
#include "third_party/blink/public/common/privacy_budget/identifiability_sample_collector.h"
#include "third_party/blink/public/common/privacy_budget/identifiability_study_settings.h"
#include "third_party/blink/public/common/thread_safe_browser_interface_broker_proxy.h"
#include "third_party/blink/public/mojom/css/preferred_color_scheme.mojom-blink-forward.h"
#include "third_party/blink/public/mojom/frame/frame.mojom-blink.h"
#include "third_party/blink/public/mojom/input/focus_type.mojom-blink.h"
#include "third_party/blink/public/mojom/manifest/display_mode.mojom-blink-forward.h"
#include "third_party/blink/public/mojom/page_state/page_state.mojom-blink.h"
#include "third_party/blink/public/mojom/permissions/permission_status.mojom-blink-forward.h"
#include "third_party/blink/public/mojom/permissions_policy/permissions_policy_feature.mojom-blink-forward.h"
#include "third_party/blink/public/platform/browser_interface_broker_proxy.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/platform/task_type.h"
#include "third_party/blink/public/platform/web_content_settings_client.h"
#include "third_party/blink/public/web/web_link_preview_triggerer.h"
#include "third_party/blink/public/web/web_print_page_description.h"
#include "third_party/blink/renderer/bindings/core/v8/frozen_array.h"
#include "third_party/blink/renderer/bindings/core/v8/isolated_world_csp.h"
#include "third_party/blink/renderer/bindings/core/v8/script_controller.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/core/v8/script_value.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_aria_notification_options.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_caret_position_from_point_options.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_document_ready_state.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_element_creation_options.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_element_registration_options.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_observable_array_css_style_sheet.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_throw_dom_exception.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_elementcreationoptions_string.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_htmlscriptelement_svgscriptelement.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_visibility_state.h"
#include "third_party/blink/renderer/bindings/core/v8/window_proxy.h"
#include "third_party/blink/renderer/core/accessibility/ax_context.h"
#include "third_party/blink/renderer/core/accessibility/ax_object_cache.h"
#include "third_party/blink/renderer/core/animation/document_animations.h"
#include "third_party/blink/renderer/core/animation/document_timeline.h"
#include "third_party/blink/renderer/core/animation/pending_animations.h"
#include "third_party/blink/renderer/core/animation/worklet_animation_controller.h"
#include "third_party/blink/renderer/core/annotation/annotation_agent_container_impl.h"
#include "third_party/blink/renderer/core/core_export.h"
#include "third_party/blink/renderer/core/css/css_font_selector.h"
#include "third_party/blink/renderer/core/css/css_property_value_set.h"
#include "third_party/blink/renderer/core/css/css_style_declaration.h"
#include "third_party/blink/renderer/core/css/css_style_sheet.h"
#include "third_party/blink/renderer/core/css/cssom/caret_position.h"
#include "third_party/blink/renderer/core/css/cssom/computed_style_property_map.h"
#include "third_party/blink/renderer/core/css/element_rule_collector.h"
#include "third_party/blink/renderer/core/css/font_face_set_document.h"
#include "third_party/blink/renderer/core/css/invalidation/style_invalidator.h"
#include "third_party/blink/renderer/core/css/layout_upgrade.h"
#include "third_party/blink/renderer/core/css/media_query_list.h"
#include "third_party/blink/renderer/core/css/media_query_matcher.h"
#include "third_party/blink/renderer/core/css/media_values.h"
#include "third_party/blink/renderer/core/css/parser/css_parser.h"
#include "third_party/blink/renderer/core/css/post_style_update_scope.h"
#include "third_party/blink/renderer/core/css/properties/css_property.h"
#include "third_party/blink/renderer/core/css/property_registry.h"
#include "third_party/blink/renderer/core/css/resolver/font_builder.h"
#include "third_party/blink/renderer/core/css/resolver/style_resolver.h"
#include "third_party/blink/renderer/core/css/resolver/style_resolver_stats.h"
#include "third_party/blink/renderer/core/css/selector_query.h"
#include "third_party/blink/renderer/core/css/style_change_reason.h"
#include "third_party/blink/renderer/core/css/style_engine.h"
#include "third_party/blink/renderer/core/css/style_sheet_contents.h"
#include "third_party/blink/renderer/core/css/style_sheet_list.h"
#include "third_party/blink/renderer/core/display_lock/display_lock_context.h"
#include "third_party/blink/renderer/core/display_lock/display_lock_document_state.h"
#include "third_party/blink/renderer/core/display_lock/display_lock_utilities.h"
#include "third_party/blink/renderer/core/dom/attr.h"
#include "third_party/blink/renderer/core/dom/beforeunload_event_listener.h"
#include "third_party/blink/renderer/core/dom/cdata_section.h"
#include "third_party/blink/renderer/core/dom/comment.h"
#include "third_party/blink/renderer/core/dom/document_data.h"
#include "third_party/blink/renderer/core/dom/document_fragment.h"
#include "third_party/blink/renderer/core/dom/document_init.h"
#include "third_party/blink/renderer/core/dom/document_lifecycle.h"
#include "third_party/blink/renderer/core/dom/document_parser_timing.h"
#include "third_party/blink/renderer/core/dom/document_part_root.h"
#include "third_party/blink/renderer/core/dom/document_type.h"
#include "third_party/blink/renderer/core/dom/dom_implementation.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/dom/element_data_cache.h"
#include "third_party/blink/renderer/core/dom/element_traversal.h"
#include "third_party/blink/renderer/core/dom/events/event.h"
#include "third_party/blink/renderer/core/dom/events/event_dispatch_forbidden_scope.h"
#include "third_party/blink/renderer/core/dom/events/event_listener.h"
#include "third_party/blink/renderer/core/dom/events/native_event_listener.h"
#include "third_party/blink/renderer/core/dom/events/scoped_event_queue.h"
#include "third_party/blink/renderer/core/dom/flat_tree_traversal.h"
#include "third_party/blink/renderer/core/dom/focus_params.h"
#include "third_party/blink/renderer/core/dom/focused_element_change_observer.h"
#include "third_party/blink/renderer/core/dom/layout_tree_builder_traversal.h"
#include "third_party/blink/renderer/core/dom/live_node_list.h"
#include "third_party/blink/renderer/core/dom/mutation_observer.h"
#include "third_party/blink/renderer/core/dom/node_child_removal_tracker.h"
#include "third_party/blink/renderer/core/dom/node_cloning_data.h"
#include "third_party/blink/renderer/core/dom/node_iterator.h"
#include "third_party/blink/renderer/core/dom/node_lists_node_data.h"
#include "third_party/blink/renderer/core/dom/node_rare_data.h"
#include "third_party/blink/renderer/core/dom/node_traversal.h"
#include "third_party/blink/renderer/core/dom/node_with_index.h"
#include "third_party/blink/renderer/core/dom/part_root.h"
#include "third_party/blink/renderer/core/dom/processing_instruction.h"
#include "third_party/blink/renderer/core/dom/scripted_animation_controller.h"
#include "third_party/blink/renderer/core/dom/shadow_including_tree_order_traversal.h"
#include "third_party/blink/renderer/core/dom/shadow_root.h"
#include "third_party/blink/renderer/core/dom/slot_assignment.h"
#include "third_party/blink/renderer/core/dom/slot_assignment_engine.h"
#include "third_party/blink/renderer/core/dom/slot_assignment_recalc_forbidden_scope.h"
#include "third_party/blink/renderer/core/dom/static_node_list.h"
#include "third_party/blink/renderer/core/dom/text_diff_range.h"
#include "third_party/blink/renderer/core/dom/transform_source.h"
#include "third_party/blink/renderer/core/dom/tree_walker.h"
#include "third_party/blink/renderer/core/dom/visited_link_state.h"
#include "third_party/blink/renderer/core/dom/whitespace_attacher.h"
#include "third_party/blink/renderer/core/dom/xml_document.h"
#include "third_party/blink/renderer/core/editing/editing_utilities.h"
#include "third_party/blink/renderer/core/editing/frame_selection.h"
#include "third_party/blink/renderer/core/editing/ime/edit_context.h"
#include "third_party/blink/renderer/core/editing/markers/document_marker_controller.h"
#include "third_party/blink/renderer/core/editing/position_with_affinity.h"
#include "third_party/blink/renderer/core/editing/serializers/serialization.h"
#include "third_party/blink/renderer/core/event_type_names.h"
#include "third_party/blink/renderer/core/events/before_unload_event.h"
#include "third_party/blink/renderer/core/events/event_factory.h"
#include "third_party/blink/renderer/core/events/event_util.h"
#include "third_party/blink/renderer/core/events/hash_change_event.h"
#include "third_party/blink/renderer/core/events/overscroll_event.h"
#include "third_party/blink/renderer/core/events/page_transition_event.h"
#include "third_party/blink/renderer/core/events/visual_viewport_resize_event.h"
#include "third_party/blink/renderer/core/events/visual_viewport_scroll_event.h"
#include "third_party/blink/renderer/core/events/visual_viewport_scrollend_event.h"
#include "third_party/blink/renderer/core/execution_context/window_agent.h"
#include "third_party/blink/renderer/core/fragment_directive/fragment_directive.h"
#include "third_party/blink/renderer/core/fragment_directive/text_fragment_handler.h"
#include "third_party/blink/renderer/core/frame/csp/content_security_policy.h"
#include "third_party/blink/renderer/core/frame/dom_visual_viewport.h"
#include "third_party/blink/renderer/core/frame/event_handler_registry.h"
#include "third_party/blink/renderer/core/frame/font_matching_metrics.h"
#include "third_party/blink/renderer/core/frame/frame_console.h"
#include "third_party/blink/renderer/core/frame/history.h"
#include "third_party/blink/renderer/core/frame/intervention.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_client.h"
#include "third_party/blink/renderer/core/frame/local_frame_ukm_aggregator.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/page_dismissal_scope.h"
#include "third_party/blink/renderer/core/frame/performance_monitor.h"
#include "third_party/blink/renderer/core/frame/picture_in_picture_controller.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/frame/viewport_data.h"
#include "third_party/blink/renderer/core/frame/visual_viewport.h"
#include "third_party/blink/renderer/core/html/anchor_element_metrics_sender.h"
#include "third_party/blink/renderer/core/html/canvas/canvas_font_cache.h"
#include "third_party/blink/renderer/core/html/collection_type.h"
#include "third_party/blink/renderer/core/html/custom/custom_element.h"
#include "third_party/blink/renderer/core/html/custom/custom_element_definition.h"
#include "third_party/blink/renderer/core/html/custom/custom_element_descriptor.h"
#include "third_party/blink/renderer/core/html/custom/custom_element_registry.h"
#include "third_party/blink/renderer/core/html/document_all_name_collection.h"
#include "third_party/blink/renderer/core/html/document_name_collection.h"
#include "third_party/blink/renderer/core/html/forms/email_input_type.h"
#include "third_party/blink/renderer/core/html/forms/form_controller.h"
#include "third_party/blink/renderer/core/html/forms/html_form_element.h"
#include "third_party/blink/renderer/core/html/forms/html_input_element.h"
#include "third_party/blink/renderer/core/html/html_all_collection.h"
#include "third_party/blink/renderer/core/html/html_anchor_element.h"
#include "third_party/blink/renderer/core/html/html_base_element.h"
#include "third_party/blink/renderer/core/html/html_body_element.h"
#include "third_party/blink/renderer/core/html/html_collection.h"
#include "third_party/blink/renderer/core/html/html_dialog_element.h"
#include "third_party/blink/renderer/core/html/html_document.h"
#include "third_party/blink/renderer/core/html/html_frame_owner_element.h"
#include "third_party/blink/renderer/core/html/html_frame_set_element.h"
#include "third_party/blink/renderer/core/html/html_head_element.h"
#include "third_party/blink/renderer/core/html/html_html_element.h"
#include "third_party/blink/renderer/core/html/html_image_element.h"
#include "third_party/blink/renderer/core/html/html_link_element.h"
#include "third_party/blink/renderer/core/html/html_meta_element.h"
#include "third_party/blink/renderer/core/html/html_object_element.h"
#include "third_party/blink/renderer/core/html/html_plugin_element.h"
#include "third_party/blink/renderer/core/html/html_script_element.h"
#include "third_party/blink/renderer/core/html/html_style_element.h"
#include "third_party/blink/renderer/core/html/html_title_element.h"
#include "third_party/blink/renderer/core/html/html_unknown_element.h"
#include "third_party/blink/renderer/core/html/lazy_load_image_observer.h"
#include "third_party/blink/renderer/core/html/nesting_level_incrementer.h"
#include "third_party/blink/renderer/core/html/parser/html_document_parser.h"
#include "third_party/blink/renderer/core/html/parser/html_document_parser_fastpath.h"
#include "third_party/blink/renderer/core/html/parser/html_parser_idioms.h"
#include "third_party/blink/renderer/core/html/parser/text_resource_decoder.h"
#include "third_party/blink/renderer/core/html/parser/text_resource_decoder_builder.h"
#include "third_party/blink/renderer/core/html/plugin_document.h"
#include "third_party/blink/renderer/core/html/window_name_collection.h"
#include "third_party/blink/renderer/core/html_element_factory.h"
#include "third_party/blink/renderer/core/html_element_type_helpers.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/input/event_handler.h"
#include "third_party/blink/renderer/core/input/touch_list.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/core/inspector/inspector_trace_events.h"
#include "third_party/blink/renderer/core/intersection_observer/element_intersection_observer_data.h"
#include "third_party/blink/renderer/core/intersection_observer/intersection_observer_controller.h"
#include "third_party/blink/renderer/core/intersection_observer/intersection_observer_entry.h"
#include "third_party/blink/renderer/core/layout/adjust_for_absolute_zoom.h"
#include "third_party/blink/renderer/core/layout/hit_test_canvas_result.h"
#include "third_party/blink/renderer/core/layout/hit_test_result.h"
#include "third_party/blink/renderer/core/layout/layout_embedded_content.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/layout/pagination_utils.h"
#include "third_party/blink/renderer/core/layout/text_autosizer.h"
#include "third_party/blink/renderer/core/lcp_critical_path_predictor/lcp_critical_path_predictor.h"
#include "third_party/blink/renderer/core/loader/anchor_element_interaction_tracker.h"
#include "third_party/blink/renderer/core/loader/cookie_jar.h"
#include "third_party/blink/renderer/core/loader/document_loader.h"
#include "third_party/blink/renderer/core/loader/frame_fetch_context.h"
#include "third_party/blink/renderer/core/loader/frame_loader.h"
#include "third_party/blink/renderer/core/loader/http_refresh_scheduler.h"
#include "third_party/blink/renderer/core/loader/idleness_detector.h"
#include "third_party/blink/renderer/core/loader/interactive_detector.h"
#include "third_party/blink/renderer/core/loader/lazy_image_helper.h"
#include "third_party/blink/renderer/core/loader/no_state_prefetch_client.h"
#include "third_party/blink/renderer/core/loader/pending_link_preload.h"
#include "third_party/blink/renderer/core/loader/progress_tracker.h"
#include "third_party/blink/renderer/core/loader/render_blocking_resource_manager.h"
#include "third_party/blink/renderer/core/loader/resource/link_dictionary_resource.h"
#include "third_party/blink/renderer/core/mathml/mathml_element.h"
#include "third_party/blink/renderer/core/mathml/mathml_row_element.h"
#include "third_party/blink/renderer/core/mathml_element_factory.h"
#include "third_party/blink/renderer/core/mathml_names.h"
#include "third_party/blink/renderer/core/mobile_metrics/mobile_friendliness_checker.h"
#include "third_party/blink/renderer/core/origin_trials/origin_trial_context.h"
#include "third_party/blink/renderer/core/page/chrome_client.h"
#include "third_party/blink/renderer/core/page/event_with_hit_test_results.h"
#include "third_party/blink/renderer/core/page/focus_controller.h"
#include "third_party/blink/renderer/core/page/frame_tree.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/page/page_animator.h"
#include "third_party/blink/renderer/core/page/plugin_script_forbidden_scope.h"
#include "third_party/blink/renderer/core/page/pointer_lock_controller.h"
#include "third_party/blink/renderer/core/page/scrolling/fragment_anchor.h"
#include "third_party/blink/renderer/core/page/scrolling/root_scroller_controller.h"
#include "third_party/blink/renderer/core/page/scrolling/snap_coordinator.h"
#include "third_party/blink/renderer/core/page/scrolling/top_document_root_scroller_controller.h"
#include "third_party/blink/renderer/core/page/spatial_navigation_controller.h"
#include "third_party/blink/renderer/core/page/validation_message_client.h"
#include "third_party/blink/renderer/core/paint/paint_layer.h"
#include "third_party/blink/renderer/core/paint/paint_layer_scrollable_area.h"
#include "third_party/blink/renderer/core/paint/timing/first_meaningful_paint_detector.h"
#include "third_party/blink/renderer/core/paint/timing/paint_timing.h"
#include "third_party/blink/renderer/core/permissions_policy/dom_feature_policy.h"
#include "third_party/blink/renderer/core/permissions_policy/permissions_policy_parser.h"
#include "third_party/blink/renderer/core/probe/core_probes.h"
#include "third_party/blink/renderer/core/resize_observer/resize_observer.h"
#include "third_party/blink/renderer/core/resize_observer/resize_observer_controller.h"
#include "third_party/blink/renderer/core/resize_observer/resize_observer_entry.h"
#include "third_party/blink/renderer/core/resize_observer/resize_observer_size.h"
#include "third_party/blink/renderer/core/sanitizer/sanitizer_api.h"
#include "third_party/blink/renderer/core/script/detect_javascript_frameworks.h"
#include "third_party/blink/renderer/core/script/script_runner.h"
#include "third_party/blink/renderer/core/scroll/scrollbar_theme.h"
#include "third_party/blink/renderer/core/scroll/snap_event.h"
#include "third_party/blink/renderer/core/speculation_rules/document_speculation_rules.h"
#include "third_party/blink/renderer/core/svg/svg_document_extensions.h"
#include "third_party/blink/renderer/core/svg/svg_script_element.h"
#include "third_party/blink/renderer/core/svg/svg_svg_element.h"
#include "third_party/blink/renderer/core/svg/svg_title_element.h"
#include "third_party/blink/renderer/core/svg/svg_unknown_element.h"
#include "third_party/blink/renderer/core/svg/svg_use_element.h"
#include "third_party/blink/renderer/core/svg_element_factory.h"
#include "third_party/blink/renderer/core/svg_names.h"
#include "third_party/blink/renderer/core/timing/render_blocking_metrics_reporter.h"
#include "third_party/blink/renderer/core/timing/soft_navigation_heuristics.h"
#include "third_party/blink/renderer/core/trustedtypes/trusted_html.h"
#include "third_party/blink/renderer/core/view_transition/page_reveal_event.h"
#include "third_party/blink/renderer/core/view_transition/view_transition_supplement.h"
#include "third_party/blink/renderer/core/view_transition/view_transition_utils.h"
#include "third_party/blink/renderer/core/xml/parser/xml_document_parser.h"
#include "third_party/blink/renderer/core/xml_names.h"
#include "third_party/blink/renderer/core/xmlns_names.h"
#include "third_party/blink/renderer/platform/bindings/dom_data_store.h"
#include "third_party/blink/renderer/platform/bindings/dom_wrapper_world.h"
#include "third_party/blink/renderer/platform/bindings/exception_messages.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/script_forbidden_scope.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/bindings/source_location.h"
#include "third_party/blink/renderer/platform/bindings/v8_dom_wrapper.h"
#include "third_party/blink/renderer/platform/bindings/v8_per_isolate_data.h"
#include "third_party/blink/renderer/platform/fonts/font_performance.h"
#include "third_party/blink/renderer/platform/geometry/length_functions.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/heap/thread_state.h"
#include "third_party/blink/renderer/platform/instrumentation/histogram.h"
#include "third_party/blink/renderer/platform/instrumentation/instance_counters.h"
#include "third_party/blink/renderer/platform/instrumentation/resource_coordinator/document_resource_coordinator.h"
#include "third_party/blink/renderer/platform/instrumentation/tracing/trace_event.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/language.h"
#include "third_party/blink/renderer/platform/loader/fetch/null_resource_fetcher_properties.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_fetcher.h"
#include "third_party/blink/renderer/platform/network/content_security_policy_parsers.h"
#include "third_party/blink/renderer/platform/network/http_parsers.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/scheduler/public/event_loop.h"
#include "third_party/blink/renderer/platform/scheduler/public/frame_or_worker_scheduler.h"
#include "third_party/blink/renderer/platform/scheduler/public/post_cross_thread_task.h"
#include "third_party/blink/renderer/platform/text/platform_locale.h"
#include "third_party/blink/renderer/platform/web_test_support.h"
#include "third_party/blink/renderer/platform/weborigin/origin_access_entry.h"
#include "third_party/blink/renderer/platform/weborigin/scheme_registry.h"
#include "third_party/blink/renderer/platform/weborigin/security_origin.h"
#include "third_party/blink/renderer/platform/widget/frame_widget.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_functional.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "third_party/blink/renderer/platform/wtf/hash_functions.h"
#include "third_party/blink/renderer/platform/wtf/std_lib_extras.h"
#include "third_party/blink/renderer/platform/wtf/text/character_names.h"
#include "third_party/blink/renderer/platform/wtf/text/character_visitor.h"
#include "third_party/blink/renderer/platform/wtf/text/string_buffer.h"
#include "third_party/blink/renderer/platform/wtf/text/text_encoding_registry.h"

#ifndef NDEBUG
using WeakDocumentSet = blink::HeapHashSet<blink::WeakMember<blink::Document>>;
static WeakDocumentSet& LiveDocumentSet();
#endif

namespace blink {

namespace {

class IntrinsicSizeResizeObserverDelegate : public ResizeObserver::Delegate {
 public:
  void OnResize(const HeapVector<Member<ResizeObserverEntry>>& entries) final;
  ResizeObserver::DeliveryTime Delivery() const final;
  bool SkipNonAtomicInlineObservations() const final;
};

// Returns true if any of <object> ancestors don't start loading or are loading
// plugins/frames/images. If there are no <object> ancestors, this function
// returns false.
bool IsInIndeterminateObjectAncestor(const Element* element) {
  if (!element->isConnected())
    return false;
  for (; element; element = element->ParentOrShadowHostElement()) {
    if (const auto* object = DynamicTo<HTMLObjectElement>(element)) {
      if (!object->DidFinishLoading())
        return true;
    }
  }
  return false;
}

// Helper function to notify both `first` and `second` that the priority scroll
// anchor status changed. This is used when, for example, a focused element
// changes from `first` to `second`.
void NotifyPriorityScrollAnchorStatusChanged(Node* first, Node* second) {
  if (first)
    first->NotifyPriorityScrollAnchorStatusChanged();
  if (second)
    second->NotifyPriorityScrollAnchorStatusChanged();
}

// Before fetching the default URL, make sure it won't be blocked by CSP. The
// webpage didn't requested "/favicon.ico", it is automatic. Developers
// shouldn't suffer from any errors provoked by Chrome.
// See https://crbug.com/820846
bool DefaultFaviconAllowedByCSP(const Document* document, const IconURL& icon) {
  ExecutionContext* context = document->GetExecutionContext();
  if (!context) {
    // LocalFrame::UpdateFaviconURL() is sometimes called after a LocalFrame
    // swap. When this happens, the document has lost its ExecutionContext and
    // the favicon won't be loaded anyway. The output of this function doesn't
    // matter anymore.
    return false;
  }

  return context->GetContentSecurityPolicy()->AllowImageFromSource(
      icon.icon_url_, icon.icon_url_, RedirectStatus::kNoRedirect,
      ReportingDisposition::kSuppressReporting,
      ContentSecurityPolicy::CheckHeaderType::kCheckAll);
}

// The sampling rate for UKM.
constexpr double kUkmSamplingRate = 0.001;

}  // namespace

static const unsigned kCMaxWriteRecursionDepth = 21;

// This amount of time must have elapsed before we will even consider scheduling
// a layout without a delay.
// FIXME: For faster machines this value can really be lowered to 200.  250 is
// adequate, but a little high for dual G5s. :)
static const base::TimeDelta kCLayoutScheduleThreshold =
    base::Milliseconds(250);

// DOM Level 2 says (letters added):
//
// a) Name start characters must have one of the categories Ll, Lu, Lo, Lt, Nl.
// b) Name characters other than Name-start characters must have one of the
//    categories Mc, Me, Mn, Lm, or Nd.
// c) Characters in the compatibility area (i.e. with character code greater
//    than #xF900 and less than #xFFFE) are not allowed in XML names.
// d) Characters which have a font or compatibility decomposition (i.e. those
//    with a "compatibility formatting tag" in field 5 of the database -- marked
//    by field 5 beginning with a "<") are not allowed.
// e) The following characters are treated as name-start characters rather than
//    name characters, because the property file classifies them as Alphabetic:
//    [#x02BB-#x02C1], #x0559, #x06E5, #x06E6.
// f) Characters #x20DD-#x20E0 are excluded (in accordance with Unicode, section
//    5.14).
// g) Character #x00B7 is classified as an extender, because the property list
//    so identifies it.
// h) Character #x0387 is added as a name character, because #x00B7 is its
//    canonical equivalent.
// i) Characters ':' and '_' are allowed as name-start characters.
// j) Characters '-' and '.' are allowed as name characters.
//
// It also contains complete tables. If we decide it's better, we could include
// those instead of the following code.

static inline bool IsValidNameStart(UChar32 c) {
  // rule (e) above
  if ((c >= 0x02BB && c <= 0x02C1) || c == 0x559 || c == 0x6E5 || c == 0x6E6)
    return true;

  // rule (i) above
  if (c == ':' || c == '_')
    return true;

  // rules (a) and (f) above
  const uint32_t kNameStartMask =
      WTF::unicode::kLetter_Lowercase | WTF::unicode::kLetter_Uppercase |
      WTF::unicode::kLetter_Other | WTF::unicode::kLetter_Titlecase |
      WTF::unicode::kNumber_Letter;
  if (!(WTF::unicode::Category(c) & kNameStartMask))
    return false;

  // rule (c) above
  if (c >= 0xF900 && c < 0xFFFE)
    return false;

  // rule (d) above
  WTF::unicode::CharDecompositionType decomp_type =
      WTF::unicode::DecompositionType(c);
  if (decomp_type == WTF::unicode::kDecompositionFont ||
      decomp_type == WTF::unicode::kDecompositionCompat)
    return false;

  return true;
}

static inline bool IsValidNamePart(UChar32 c) {
  // rules (a), (e), and (i) above
  if (IsValidNameStart(c))
    return true;

  // rules (g) and (h) above
  if (c == 0x00B7 || c == 0x0387)
    return true;

  // rule (j) above
  if (c == '-' || c == '.')
    return true;

  // rules (b) and (f) above
  const uint32_t kOtherNamePartMask =
      WTF::unicode::kMark_NonSpacing | WTF::unicode::kMark_Enclosing |
      WTF::unicode::kMark_SpacingCombining | WTF::unicode::kLetter_Modifier |
      WTF::unicode::kNumber_DecimalDigit;
  if (!(WTF::unicode::Category(c) & kOtherNamePartMask))
    return false;

  // rule (c) above
  if (c >= 0xF900 && c < 0xFFFE)
    return false;

  // rule (d) above
  WTF::unicode::CharDecompositionType decomp_type =
      WTF::unicode::DecompositionType(c);
  if (decomp_type == WTF::unicode::kDecompositionFont ||
      decomp_type == WTF::unicode::kDecompositionCompat)
    return false;

  return true
```