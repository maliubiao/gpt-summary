Response:
The user wants a summary of the functionality of the provided C++ code snippet from a Chromium Blink engine file. The summary should include:
1. **Core function:** What is the primary purpose of this code?
2. **Relationship to web technologies:** How does this code relate to JavaScript, HTML, and CSS? Provide examples if applicable.
3. **Logic and data flow:** If there's any logical processing, describe it with example inputs and outputs.
4. **Common errors:** Point out potential user or programming errors.

The user explicitly states that this is the second part of a three-part request and requests a summary of its functionality.

**Plan:**

1. **Analyze the code:**  Identify the key functions and data structures. Focus on the purpose of each function and how they interact.
2. **Identify the main theme:** Determine the overarching goal of the code based on the function names and the data being processed. Keywords like "inspector," "trace events," and the specific event names are strong indicators.
3. **Relate to web technologies:**  Connect the concepts in the code (like layout, network requests, scripts, timers, etc.) to their corresponding web technologies (HTML, CSS, JavaScript).
4. **Illustrate with examples:**  Create simple scenarios to demonstrate the input and output of specific functions, especially those dealing with layout or network information.
5. **Consider errors:** Think about potential misuses of the API or common programming mistakes related to the functionalities observed.
6. **Synthesize the summary:** Combine the above points into a concise description of the code's purpose.
This code snippet defines and implements various functions responsible for emitting trace events related to the **Inspector** (developer tools) in the Chromium Blink rendering engine. These trace events provide detailed information about different aspects of the rendering process, network activity, and JavaScript execution, which can be recorded and analyzed to understand performance bottlenecks and debug issues.

Here's a breakdown of its functionality:

**Core Functionality:**

* **Emitting Detailed Trace Events:** The primary function is to generate structured data representing various events occurring within the Blink engine. This data is formatted for consumption by tracing tools like Perfetto, allowing developers to observe the internal workings of the browser.
* **Data Collection for Specific Events:** Each function (like `SetGeneratingNodeInfo`, `CreateLayoutRoot`, `inspector_send_request_event::Data`, etc.) is responsible for gathering relevant information about a specific type of event and formatting it into a `perfetto::TracedValue` which is essentially a dictionary or array of key-value pairs.
* **Linking Events to Context:** Many functions take arguments like `LayoutObject`, `DocumentLoader`, `ExecutionContext`, and `LocalFrame` to provide context for the emitted events. This allows the tracing system to correlate events and understand the sequence of operations.
* **Providing Identifiers:** The code uses `IdentifiersFactory` to generate unique identifiers for objects like frames, nodes, and requests, enabling cross-referencing of events.
* **Categorizing Events:**  The use of namespaces like `inspector_layout_event`, `inspector_send_request_event`, etc., helps to categorize the different types of trace events.
* **String Conversion:** Functions like `ResourcePriorityString` and `GetRenderBlockingStringFromBehavior` convert internal enum values into human-readable strings for the trace output.

**Relationship to JavaScript, HTML, and CSS:**

This code is deeply intertwined with the functionality of JavaScript, HTML, and CSS:

* **HTML:**
    * **`SetGeneratingNodeInfo` and `SetNodeInfo`:** These functions extract information about HTML nodes (`Node*`) that are involved in layout or other events. They are used to associate events with specific HTML elements.
    * **`CreateLayoutRoot`:**  This function deals with the root layout objects, which are directly derived from the HTML structure. The "quads" information relates to the bounding boxes of elements on the page.
    * **`inspector_layout_invalidation_tracking_event::Data`:** This tracks when changes in the HTML structure (DOM changes - `kDomChanged`) cause layout recalculations.
    * **`inspector_paint_event::Data`:**  This records paint events associated with specific layout objects, which ultimately render the HTML content to the screen.
    * **Frame Information:** Functions like `FrameEventData` and `FillCommonFrameData` extract information about HTML frames (`LocalFrame`).

    * **Example:** When an HTML element's position changes due to a JavaScript modification, a `inspector_layout_invalidation_tracking_event` might be emitted with the `reason` set to `kDomChanged`, and `SetGeneratingNodeInfo` would provide the ID of the affected HTML element.

* **CSS:**
    * **`inspector_layout_invalidation_tracking_event::Data`:** Changes in CSS styles (`kStyleChange`) can trigger layout invalidation.
    * **`inspector_parse_author_style_sheet_event::Data`:**  This tracks the parsing of CSS stylesheets.
    * **Layout related events:** Events like layout invalidation, layout, and paint are directly influenced by CSS rules.

    * **Example:** If a CSS rule changes the `width` of an element, a `inspector_layout_invalidation_tracking_event` might be emitted with the `reason` set to `kStyleChange`.

* **JavaScript:**
    * **`inspector_timer_install_event::Data`, `inspector_timer_remove_event::Data`, `inspector_timer_fire_event::Data`:** These functions track the lifecycle of `setTimeout` and `setInterval` calls in JavaScript.
    * **`inspector_animation_frame_event::Data`:** Tracks `requestAnimationFrame` callbacks.
    * **`inspector_idle_callback_request_event::Data`, etc.:** Tracks `requestIdleCallback`.
    * **`inspector_send_request_event::Data`:**  Can capture network requests initiated by JavaScript (e.g., via `fetch` or `XMLHttpRequest`).
    * **`inspector_evaluate_script_event::Data`:**  Records when JavaScript code is evaluated.
    * **`inspector_function_call_event::Data`:**  Traces JavaScript function calls.
    * **`inspector_handle_post_message_event::Data`, `inspector_schedule_post_message_event::Data`:**  Track the sending and receiving of `postMessage` calls between different browsing contexts.

    * **Example:** When JavaScript code calls `setTimeout(myFunction, 1000)`, an `inspector_timer_install_event` would be emitted. When the timer fires, an `inspector_timer_fire_event` would be emitted. The `SetCallStack` function within these events would capture the JavaScript call stack at the time of the event.

**Logic and Data Flow (with assumptions):**

Let's take `inspector_send_request_event::Data` as an example:

**Assumed Input:**

* `context`: A `perfetto::TracedValue` object where the event data will be written.
* `execution_context`: The JavaScript execution context where the request is initiated (e.g., a window or worker).
* `loader`: The `DocumentLoader` responsible for loading the resource.
* `identifier`: A unique ID for the resource request.
* `frame`: The `LocalFrame` associated with the request.
* `request`: A `ResourceRequest` object containing details about the network request (URL, method, headers, etc.).
* `resource_type`: The type of resource being requested (e.g., image, script, document).
* `render_blocking_behavior`: Indicates if the resource blocks rendering.
* `resource_loader_options`: Additional options for loading the resource.

**Output:**

The `context` object will be populated with a dictionary containing the following keys and values:

* `"requestId"`:  A string ID generated using `IdentifiersFactory::RequestId`.
* `"frame"`: A string ID generated using `IdentifiersFactory::FrameId`.
* `"url"`: The URL of the requested resource (from `request.Url().GetString()`).
* `"requestMethod"`: The HTTP method of the request (e.g., "GET", "POST").
* `"isLinkPreload"`: A boolean indicating if the request is a link preload.
* `"resourceType"`: A string representation of the resource type.
* `"renderBlocking"`: A string indicating the render-blocking behavior (if applicable).
* `"priority"`: A string representation of the resource priority.
* `"fetchPriorityHint"`: A string representation of the fetch priority hint.
* `"initiator"`: A nested dictionary containing information about the initiator of the request (e.g., script location).
* `"stackTrace"`: (Potentially) An array representing the JavaScript call stack at the time of the request.

**Example Input & Output:**

Imagine JavaScript code executes `fetch('https://example.com/image.png')`.

* **Input (relevant parts):**
    * `request.Url().GetString()`: `"https://example.com/image.png"`
    * `request.HttpMethod()`: `"GET"`
    * `resource_type`: `ResourceType::kImage`
    * `render_blocking_behavior`: `RenderBlockingBehavior::kNonBlocking` (assuming it's a typical image fetch)
* **Output (in the `context`):**
    * `"url"`: `"https://example.com/image.png"`
    * `"requestMethod"`: `"GET"`
    * `"resourceType"`: `"Image"`
    * `"renderBlocking"`: `"non_blocking"`

**User or Programming Common Usage Errors:**

* **Incorrectly interpreting trace event data:**  Developers might misinterpret the meaning of specific fields in the trace events, leading to incorrect performance analysis or debugging conclusions. For instance, confusing "encodedDataLength" with the actual size of the uncompressed resource.
* **Not understanding the context of events:**  Without understanding the relationships between different trace events (e.g., a layout invalidation leading to a paint), it can be difficult to pinpoint the root cause of an issue.
* **Over-reliance on trace data without other debugging techniques:** Trace data is valuable, but it shouldn't be the only tool used for debugging. Combining it with traditional debugging methods (breakpoints, logging) is often necessary.
* **Filtering trace events inappropriately:** Filtering out relevant events can hide crucial information. For example, filtering out "minor" layout invalidations might miss a recurring performance issue.
* **Assuming causality based on temporal proximity:** Just because one event happens before another doesn't necessarily mean the first caused the second. Trace data needs careful analysis to establish causality.

**Summary of Functionality (Part 2):**

This part of the `inspector_trace_events.cc` file focuses on defining and implementing functions that generate trace events related to **layout, network requests, resource loading, JavaScript timers and callbacks, script execution, and painting**. These functions meticulously gather relevant data about each event and format it into structured dictionaries and arrays for use by the Chromium Inspector's tracing system. This data is crucial for developers to understand the performance characteristics and internal workings of web pages within the Blink rendering engine.

Prompt: 
```
这是目录为blink/renderer/core/inspector/inspector_trace_events.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能

"""


static void SetGeneratingNodeInfo(
    perfetto::TracedDictionary& dict,
    const LayoutObject* layout_object,
    perfetto::StaticString id_field_name,
    perfetto::StaticString name_field_name = nullptr) {
  Node* node = nullptr;
  for (; layout_object && !node; layout_object = layout_object->Parent())
    node = layout_object->GeneratingNode();
  if (!node)
    return;

  SetNodeInfo(dict, node, id_field_name, name_field_name);
}

static void CreateLayoutRoot(perfetto::TracedValue context,
                             const LayoutObjectWithDepth& layout_root) {
  auto dict = std::move(context).WriteDictionary();
  SetGeneratingNodeInfo(dict, layout_root.object, "nodeId");
  dict.Add("depth", static_cast<int>(layout_root.depth));
  Vector<gfx::QuadF> quads;
  layout_root.object->AbsoluteQuads(quads);
  if (quads.size() > kMaxQuads)
    quads.Shrink(kMaxQuads);
  {
    auto array = dict.AddArray("quads");
    for (auto& quad : quads)
      CreateQuad(array.AppendItem(), quad);
  }
}

static void SetHeaders(perfetto::TracedValue context,
                       const HTTPHeaderMap& headers) {
  auto array = std::move(context).WriteArray();
  for (auto& header : headers) {
    auto item_dict = array.AppendDictionary();
    item_dict.Add("name", header.key);
    item_dict.Add("value", header.value);
  }
}

void inspector_layout_event::EndData(
    perfetto::TracedValue context,
    const HeapVector<LayoutObjectWithDepth>& layout_roots) {
  auto dict = std::move(context).WriteDictionary();
  {
    auto array = dict.AddArray("layoutRoots");
    unsigned numRoots = 0u;
    for (auto& layout_root : layout_roots) {
      if (++numRoots > kMaxLayoutRoots)
        break;
      CreateLayoutRoot(array.AppendItem(), layout_root);
    }
  }
}

namespace layout_invalidation_reason {
const char kUnknown[] = "Unknown";
const char kSizeChanged[] = "Size changed";
const char kAncestorMoved[] = "Ancestor moved";
const char kStyleChange[] = "Style changed";
const char kDomChanged[] = "DOM changed";
const char kTextChanged[] = "Text changed";
const char kPrintingChanged[] = "Printing changed";
const char kPaintPreview[] = "Enter/exit paint preview";
const char kAttributeChanged[] = "Attribute changed";
const char kColumnsChanged[] = "Attribute changed";
const char kChildAnonymousBlockChanged[] = "Child anonymous block changed";
const char kAnonymousBlockChange[] = "Anonymous block change";
const char kFontsChanged[] = "Fonts changed";
const char kFullscreen[] = "Fullscreen change";
const char kChildChanged[] = "Child changed";
const char kListValueChange[] = "List value change";
const char kListStyleTypeChange[] = "List style type change";
const char kCounterStyleChange[] = "Counter style change";
const char kImageChanged[] = "Image changed";
const char kSliderValueChanged[] = "Slider value changed";
const char kAncestorMarginCollapsing[] = "Ancestor margin collapsing";
const char kFieldsetChanged[] = "Fieldset changed";
const char kTextAutosizing[] = "Text autosizing (font boosting)";
const char kSvgResourceInvalidated[] = "SVG resource invalidated";
const char kFloatDescendantChanged[] = "Floating descendant changed";
const char kCountersChanged[] = "Counters changed";
const char kGridChanged[] = "Grid changed";
const char kMenuOptionsChanged[] = "Menu options changed";
const char kRemovedFromLayout[] = "Removed from layout";
const char kAddedToLayout[] = "Added to layout";
const char kTableChanged[] = "Table changed";
const char kPaddingChanged[] = "Padding changed";
const char kTextControlChanged[] = "Text control changed";
const char kSvgChanged[] = "SVG changed";
const char kScrollbarChanged[] = "Scrollbar changed";
const char kDisplayLock[] = "Display lock";
const char kDevtools[] = "Inspected by devtools";
const char kAnchorPositioning[] = "Anchor positioning";
}  // namespace layout_invalidation_reason

void inspector_layout_invalidation_tracking_event::Data(
    perfetto::TracedValue context,
    const LayoutObject* layout_object,
    LayoutInvalidationReasonForTracing reason) {
  DCHECK(layout_object);
  auto dict = std::move(context).WriteDictionary();
  dict.Add("frame", IdentifiersFactory::FrameId(layout_object->GetFrame()));
  SetGeneratingNodeInfo(dict, layout_object, "nodeId", "nodeName");
  dict.Add("reason", reason);
  auto source_location = CaptureSourceLocation();
  if (source_location->HasStackTrace())
    dict.Add("stackTrace", source_location);
}

void inspector_change_resource_priority_event::Data(
    perfetto::TracedValue context,
    DocumentLoader* loader,
    uint64_t identifier,
    const ResourceLoadPriority& load_priority) {
  String request_id = IdentifiersFactory::RequestId(loader, identifier);

  auto dict = std::move(context).WriteDictionary();
  dict.Add("requestId", request_id);
  dict.Add("priority", ResourcePriorityString(load_priority));
}

namespace {
String GetRenderBlockingStringFromBehavior(
    RenderBlockingBehavior render_blocking_behavior) {
  switch (render_blocking_behavior) {
    case RenderBlockingBehavior::kUnset:
      return String();
    case RenderBlockingBehavior::kBlocking:
      return "blocking";
    case RenderBlockingBehavior::kNonBlocking:
      return "non_blocking";
    case RenderBlockingBehavior::kNonBlockingDynamic:
      return "dynamically_injected_non_blocking";
    case RenderBlockingBehavior::kInBodyParserBlocking:
      return "in_body_parser_blocking";
    case RenderBlockingBehavior::kPotentiallyBlocking:
      return "potentially_blocking";
  }
}

}  // namespace

void SetInitiator(Document* document,
                  FetchInitiatorInfo initiator_info,
                  perfetto::TracedDictionary& dict) {
  auto initiator =
      InspectorNetworkAgent::BuildInitiatorObject(document, initiator_info, 0);
  auto initiatorDict = dict.AddDictionary("initiator");

  initiatorDict.Add("fetchType", initiator_info.name);
  initiatorDict.Add("type", initiator->getType());
  if (initiator->hasColumnNumber()) {
    initiatorDict.Add("columnNumber", initiator->getColumnNumber(-1));
  }
  if (initiator->hasLineNumber()) {
    initiatorDict.Add("lineNumber", initiator->getLineNumber(-1));
  }
  if (initiator->hasUrl()) {
    initiatorDict.Add("url", initiator->getUrl(""));
  }
}

void inspector_send_request_event::Data(
    perfetto::TracedValue context,
    ExecutionContext* execution_context,
    DocumentLoader* loader,
    uint64_t identifier,
    LocalFrame* frame,
    const ResourceRequest& request,
    ResourceType resource_type,
    RenderBlockingBehavior render_blocking_behavior,
    const ResourceLoaderOptions& resource_loader_options) {
  auto dict = std::move(context).WriteDictionary();
  dict.Add("requestId", IdentifiersFactory::RequestId(loader, identifier));
  dict.Add("frame", IdentifiersFactory::FrameId(frame));
  dict.Add("url", request.Url().GetString());
  dict.Add("requestMethod", request.HttpMethod());
  dict.Add("isLinkPreload",
           resource_loader_options.initiator_info.is_link_preload);
  String resource_type_string = InspectorPageAgent::ResourceTypeJson(
      InspectorPageAgent::ToResourceType(resource_type));
  dict.Add("resourceType", resource_type_string);
  String render_blocking_string =
      GetRenderBlockingStringFromBehavior(render_blocking_behavior);
  if (!render_blocking_string.IsNull()) {
    dict.Add("renderBlocking", render_blocking_string);
  }
  const char* priority = ResourcePriorityString(request.Priority());
  if (priority)
    dict.Add("priority", priority);
  dict.Add("fetchPriorityHint",
           FetchPriorityString(request.GetFetchPriorityHint()));
  SetCallStack(execution_context->GetIsolate(), dict);
  SetInitiator(frame ? frame->GetDocument() : nullptr,
               resource_loader_options.initiator_info, dict);
}

void inspector_change_render_blocking_behavior_event::Data(
    perfetto::TracedValue context,
    DocumentLoader* loader,
    uint64_t identifier,
    const ResourceRequestHead& request,
    RenderBlockingBehavior render_blocking_behavior) {
  String request_id = IdentifiersFactory::RequestId(loader, identifier);

  auto dict = std::move(context).WriteDictionary();
  dict.Add("requestId", request_id);
  dict.Add("url", request.Url().GetString());
  String render_blocking_string =
      GetRenderBlockingStringFromBehavior(render_blocking_behavior);
  if (!render_blocking_string.IsNull()) {
    dict.Add("renderBlocking", render_blocking_string);
  }
}

void inspector_send_navigation_request_event::Data(
    perfetto::TracedValue context,
    DocumentLoader* loader,
    uint64_t identifier,
    LocalFrame* frame,
    const KURL& url,
    const AtomicString& http_method) {
  auto dict = std::move(context).WriteDictionary();
  dict.Add("requestId", IdentifiersFactory::LoaderId(loader));
  dict.Add("frame", IdentifiersFactory::FrameId(frame));
  dict.Add("url", url.GetString());
  dict.Add("requestMethod", http_method);
  dict.Add("resourceType", protocol::Network::ResourceTypeEnum::Document);
  const char* priority =
      ResourcePriorityString(ResourceLoadPriority::kVeryHigh);
  if (priority)
    dict.Add("priority", priority);
  dict.Add("fetchPriorityHint",
           FetchPriorityString(mojom::blink::FetchPriorityHint::kAuto));
  SetCallStack(frame->DomWindow()->GetIsolate(), dict);
}

namespace {
void RecordTiming(perfetto::TracedValue context,
                  const ResourceLoadTiming& timing) {
  auto dict = std::move(context).WriteDictionary();
  dict.Add("requestTime", timing.RequestTime().since_origin().InSecondsF());
  dict.Add("proxyStart", timing.CalculateMillisecondDelta(timing.ProxyStart()));
  dict.Add("proxyEnd", timing.CalculateMillisecondDelta(timing.ProxyEnd()));
  dict.Add("dnsStart",
           timing.CalculateMillisecondDelta(timing.DomainLookupStart()));
  dict.Add("dnsEnd",
           timing.CalculateMillisecondDelta(timing.DomainLookupEnd()));
  dict.Add("connectStart",
           timing.CalculateMillisecondDelta(timing.ConnectStart()));
  dict.Add("connectEnd", timing.CalculateMillisecondDelta(timing.ConnectEnd()));
  dict.Add("sslStart", timing.CalculateMillisecondDelta(timing.SslStart()));
  dict.Add("sslEnd", timing.CalculateMillisecondDelta(timing.SslEnd()));
  dict.Add("workerStart",
           timing.CalculateMillisecondDelta(timing.WorkerStart()));
  dict.Add("workerReady",
           timing.CalculateMillisecondDelta(timing.WorkerReady()));
  dict.Add("sendStart", timing.CalculateMillisecondDelta(timing.SendStart()));
  dict.Add("sendEnd", timing.CalculateMillisecondDelta(timing.SendEnd()));
  dict.Add("receiveHeadersStart",
           timing.CalculateMillisecondDelta(timing.ReceiveHeadersStart()));
  dict.Add("receiveHeadersEnd",
           timing.CalculateMillisecondDelta(timing.ReceiveHeadersEnd()));
  dict.Add("pushStart", timing.PushStart().since_origin().InSecondsF());
  dict.Add("pushEnd", timing.PushEnd().since_origin().InSecondsF());
}
}  // namespace

void inspector_receive_response_event::Data(perfetto::TracedValue context,
                                            DocumentLoader* loader,
                                            uint64_t identifier,
                                            LocalFrame* frame,
                                            const ResourceResponse& response) {
  String request_id = IdentifiersFactory::RequestId(loader, identifier);

  auto dict = std::move(context).WriteDictionary();
  dict.Add("requestId", request_id);
  dict.Add("connectionId", response.ConnectionID());
  dict.Add("connectionReused", response.ConnectionReused());
  dict.Add("frame", IdentifiersFactory::FrameId(frame));
  dict.Add("statusCode", response.HttpStatusCode());
  dict.Add("mimeType", response.MimeType().GetString());
  dict.Add("encodedDataLength", response.EncodedDataLength());
  dict.Add("fromCache", response.WasCached());
  dict.Add("fromServiceWorker", response.WasFetchedViaServiceWorker());

  if (response.WasFetchedViaServiceWorker()) {
    switch (response.GetServiceWorkerResponseSource()) {
      case network::mojom::FetchResponseSource::kCacheStorage:
        dict.Add("serviceWorkerResponseSource", "cacheStorage");
        break;
      case network::mojom::FetchResponseSource::kHttpCache:
        dict.Add("serviceWorkerResponseSource", "httpCache");
        break;
      case network::mojom::FetchResponseSource::kNetwork:
        dict.Add("serviceWorkerResponseSource", "network");
        break;
      case network::mojom::FetchResponseSource::kUnspecified:
        dict.Add("serviceWorkerResponseSource", "fallbackCode");
    }
  }
  if (!response.ResponseTime().is_null()) {
    dict.Add("responseTime",
             response.ResponseTime().InMillisecondsFSinceUnixEpoch());
  }
  if (!response.CacheStorageCacheName().empty()) {
    dict.Add("cacheStorageCacheName", response.CacheStorageCacheName());
  }
  if (response.GetResourceLoadTiming()) {
    RecordTiming(dict.AddItem("timing"), *response.GetResourceLoadTiming());
  }
  if (response.WasFetchedViaServiceWorker()) {
    dict.Add("fromServiceWorker", true);
  }
  if (response.GetServiceWorkerRouterInfo()) {
    auto info = dict.AddDictionary("staticRoutingInfo");
    info.Add("ruleIdMatched",
             response.GetServiceWorkerRouterInfo()->RuleIdMatched());
    info.Add("matchedSourceType",
             response.GetServiceWorkerRouterInfo()->MatchedSourceType());
  }

  SetHeaders(dict.AddItem("headers"), response.HttpHeaderFields());
  dict.Add("protocol", InspectorNetworkAgent::GetProtocolAsString(response));
}

void inspector_receive_data_event::Data(perfetto::TracedValue context,
                                        DocumentLoader* loader,
                                        uint64_t identifier,
                                        LocalFrame* frame,
                                        uint64_t encoded_data_length) {
  String request_id = IdentifiersFactory::RequestId(loader, identifier);

  auto dict = std::move(context).WriteDictionary();
  dict.Add("requestId", request_id);
  dict.Add("frame", IdentifiersFactory::FrameId(frame));
  dict.Add("encodedDataLength", encoded_data_length);
}

void inspector_resource_finish_event::Data(perfetto::TracedValue context,
                                           DocumentLoader* loader,
                                           uint64_t identifier,
                                           base::TimeTicks finish_time,
                                           bool did_fail,
                                           int64_t encoded_data_length,
                                           int64_t decoded_body_length) {
  String request_id = IdentifiersFactory::RequestId(loader, identifier);

  auto dict = std::move(context).WriteDictionary();
  dict.Add("requestId", request_id);
  dict.Add("didFail", did_fail);
  dict.Add("encodedDataLength", encoded_data_length);
  dict.Add("decodedBodyLength", decoded_body_length);
  if (!finish_time.is_null())
    dict.Add("finishTime", finish_time.since_origin().InSecondsF());
}

void inspector_mark_resource_cached_event::Data(perfetto::TracedValue context,
                                                DocumentLoader* loader,
                                                uint64_t identifier) {
  auto dict = std::move(context).WriteDictionary();
  String request_id = IdentifiersFactory::RequestId(loader, identifier);
  dict.Add("requestId", request_id);
}

static LocalFrame* FrameForExecutionContext(ExecutionContext* context) {
  if (auto* window = DynamicTo<LocalDOMWindow>(context))
    return window->GetFrame();
  return nullptr;
}

static void GenericTimerData(perfetto::TracedDictionary& dict,
                             ExecutionContext* context,
                             int timer_id) {
  dict.Add("timerId", timer_id);
  if (LocalFrame* frame = FrameForExecutionContext(context))
    dict.Add("frame", IdentifiersFactory::FrameId(frame));
}

void inspector_timer_install_event::Data(perfetto::TracedValue trace_context,
                                         ExecutionContext* context,
                                         int timer_id,
                                         base::TimeDelta timeout,
                                         bool single_shot) {
  auto dict = std::move(trace_context).WriteDictionary();
  GenericTimerData(dict, context, timer_id);
  dict.Add("timeout", timeout.InMillisecondsF());
  dict.Add("singleShot", single_shot);
  SetCallStack(context->GetIsolate(), dict);
}

void inspector_timer_remove_event::Data(perfetto::TracedValue trace_context,
                                        ExecutionContext* context,
                                        int timer_id) {
  auto dict = std::move(trace_context).WriteDictionary();
  GenericTimerData(dict, context, timer_id);
  SetCallStack(context->GetIsolate(), dict);
}

void inspector_timer_fire_event::Data(perfetto::TracedValue trace_context,
                                      ExecutionContext* context,
                                      int timer_id) {
  auto dict = std::move(trace_context).WriteDictionary();
  GenericTimerData(dict, context, timer_id);
}

void inspector_animation_frame_event::Data(perfetto::TracedValue trace_context,
                                           ExecutionContext* context,
                                           int callback_id) {
  auto dict = std::move(trace_context).WriteDictionary();
  dict.Add("id", callback_id);
  if (auto* window = DynamicTo<LocalDOMWindow>(context)) {
    dict.Add("frame", IdentifiersFactory::FrameId(window->GetFrame()));
  } else if (auto* scope = DynamicTo<WorkerGlobalScope>(context)) {
    dict.Add("worker", ToHexString(scope));
  }
  SetCallStack(context->GetIsolate(), dict);
}

void GenericIdleCallbackEvent(perfetto::TracedDictionary& dict,
                              ExecutionContext* context,
                              int id) {
  dict.Add("id", id);
  if (LocalFrame* frame = FrameForExecutionContext(context))
    dict.Add("frame", IdentifiersFactory::FrameId(frame));
  SetCallStack(context->GetIsolate(), dict);
}

void inspector_idle_callback_request_event::Data(
    perfetto::TracedValue trace_context,
    ExecutionContext* context,
    int id,
    double timeout) {
  auto dict = std::move(trace_context).WriteDictionary();
  GenericIdleCallbackEvent(dict, context, id);
  dict.Add("timeout", timeout);
}

void inspector_idle_callback_cancel_event::Data(
    perfetto::TracedValue trace_context,
    ExecutionContext* context,
    int id) {
  auto dict = std::move(trace_context).WriteDictionary();
  GenericIdleCallbackEvent(dict, context, id);
}

void inspector_idle_callback_fire_event::Data(
    perfetto::TracedValue trace_context,
    ExecutionContext* context,
    int id,
    double allotted_milliseconds,
    bool timed_out) {
  auto dict = std::move(trace_context).WriteDictionary();
  GenericIdleCallbackEvent(dict, context, id);
  dict.Add("allottedMilliseconds", allotted_milliseconds);
  dict.Add("timedOut", timed_out);
}

void inspector_parse_author_style_sheet_event::Data(
    perfetto::TracedValue context,
    const CSSStyleSheetResource* cached_style_sheet) {
  auto dict = std::move(context).WriteDictionary();
  dict.Add("styleSheetUrl", cached_style_sheet->Url().GetString());
}

void inspector_xhr_ready_state_change_event::Data(
    perfetto::TracedValue trace_context,
    ExecutionContext* context,
    XMLHttpRequest* request) {
  auto dict = std::move(trace_context).WriteDictionary();
  dict.Add("url", request->Url().GetString());
  dict.Add("readyState", request->readyState());
  if (LocalFrame* frame = FrameForExecutionContext(context))
    dict.Add("frame", IdentifiersFactory::FrameId(frame));
  SetCallStack(context->GetIsolate(), dict);
}

void inspector_xhr_load_event::Data(perfetto::TracedValue trace_context,
                                    ExecutionContext* context,
                                    XMLHttpRequest* request) {
  auto dict = std::move(trace_context).WriteDictionary();
  dict.Add("url", request->Url().GetString());
  if (LocalFrame* frame = FrameForExecutionContext(context))
    dict.Add("frame", IdentifiersFactory::FrameId(frame));
  SetCallStack(context->GetIsolate(), dict);
}

void inspector_paint_event::Data(perfetto::TracedValue context,
                                 LocalFrame* frame,
                                 const LayoutObject* layout_object,
                                 const gfx::QuadF& quad,
                                 int layer_id) {
  auto dict = std::move(context).WriteDictionary();
  dict.Add("frame", IdentifiersFactory::FrameId(frame));
  CreateQuad(dict.AddItem("clip"), quad);
  SetGeneratingNodeInfo(dict, layout_object, "nodeId");
  dict.Add("layerId", layer_id);
  SetCallStack(frame->DomWindow()->GetIsolate(), dict);
}

void FrameEventData(perfetto::TracedDictionary& dict, LocalFrame* frame) {
  DCHECK(frame);
  dict.Add("isMainFrame", frame->IsMainFrame());
  dict.Add("isOutermostMainFrame", frame->IsOutermostMainFrame());
  // TODO(dgozman): this does not work with OOPIF, so everyone who
  // uses it should migrate to frame instead.
  dict.Add("page", IdentifiersFactory::FrameId(&frame->LocalFrameRoot()));
}

void FillCommonFrameData(perfetto::TracedDictionary& dict, LocalFrame* frame) {
  DCHECK(frame);
  dict.Add("frame", IdentifiersFactory::FrameId(frame));
  dict.Add("url", UrlForFrame(frame));
  dict.Add("name", frame->Tree().GetName());

  FrameOwner* owner = frame->Owner();
  if (auto* frame_owner_element = DynamicTo<HTMLFrameOwnerElement>(owner)) {
    dict.Add("nodeId", IdentifiersFactory::IntIdForNode(frame_owner_element));
  }
  Frame* parent = frame->Tree().Parent();
  if (IsA<LocalFrame>(parent))
    dict.Add("parent", IdentifiersFactory::FrameId(parent));
}

void inspector_commit_load_event::Data(perfetto::TracedValue context,
                                       LocalFrame* frame) {
  auto dict = std::move(context).WriteDictionary();
  FrameEventData(dict, frame);
  FillCommonFrameData(dict, frame);
}

void inspector_layerize_event::Data(perfetto::TracedValue context,
                                    LocalFrame* frame) {
  auto dict = std::move(context).WriteDictionary();
  FrameEventData(dict, frame);
  dict.Add("frame", IdentifiersFactory::FrameId(frame));
}

void inspector_mark_load_event::Data(perfetto::TracedValue context,
                                     LocalFrame* frame) {
  auto dict = std::move(context).WriteDictionary();
  FrameEventData(dict, frame);
  dict.Add("frame", IdentifiersFactory::FrameId(frame));
}

void inspector_pre_paint_event::Data(perfetto::TracedValue context,
                                     LocalFrame* frame) {
  auto dict = std::move(context).WriteDictionary();
  FrameEventData(dict, frame);
  dict.Add("frame", IdentifiersFactory::FrameId(frame));
}

void inspector_scroll_layer_event::Data(perfetto::TracedValue context,
                                        LayoutObject* layout_object) {
  auto dict = std::move(context).WriteDictionary();
  dict.Add("frame", IdentifiersFactory::FrameId(layout_object->GetFrame()));
  SetGeneratingNodeInfo(dict, layout_object, "nodeId");
}

namespace {
void FillLocation(perfetto::TracedDictionary& dict,
                  const String& url,
                  const TextPosition& text_position) {
  dict.Add("url", url);
  dict.Add("lineNumber", text_position.line_.OneBasedInt());
  dict.Add("columnNumber", text_position.column_.OneBasedInt());
}
}  // namespace

void inspector_evaluate_script_event::Data(perfetto::TracedValue context,
                                           v8::Isolate* isolate,
                                           LocalFrame* frame,
                                           const String& url,
                                           const TextPosition& text_position) {
  auto dict = std::move(context).WriteDictionary();
  FillLocation(dict, url, text_position);
  dict.Add("frame", IdentifiersFactory::FrameId(frame));
  SetCallStack(isolate, dict);
}

void inspector_target_rundown_event::Data(perfetto::TracedValue context,
                                          ExecutionContext* execution_context,
                                          v8::Isolate* isolate,
                                          ScriptState* scriptState,
                                          int scriptId) {
  // Target related info
  LocalDOMWindow* window = DynamicTo<LocalDOMWindow>(execution_context);
  LocalFrame* frame = window ? window->GetFrame() : nullptr;
  if (!frame) {
    return;
  }
  auto dict = std::move(context).WriteDictionary();
  String frameType = "page";
  if (frame->Parent() || frame->IsFencedFrameRoot()) {
    frameType = "iframe";
  }
  dict.Add("frame", IdentifiersFactory::FrameId(frame));
  dict.Add("frameType", frameType);
  dict.Add("url", window->Url().GetString());
  dict.Add("isolate", base::NumberToString(reinterpret_cast<size_t>(isolate)));

  // ExecutionContext related info
  DOMWrapperWorld& world = scriptState->World();
  String executionContextType = "default";
  const SecurityOrigin* origin = frame->DomWindow()->GetSecurityOrigin();
  if (world.IsIsolatedWorld()) {
    executionContextType = "isolated";
  } else if (world.IsWorkerOrWorkletWorld()) {
    executionContextType = "worker";
  }
  dict.Add("v8context", scriptState->GetToken().ToString());
  dict.Add("isDefault", world.IsMainWorld());
  dict.Add("contextType", executionContextType);
  dict.Add("origin", origin ? origin->ToRawString() : String());
  dict.Add("scriptId", scriptId);
}

void inspector_parse_script_event::Data(perfetto::TracedValue context,
                                        uint64_t identifier,
                                        const String& url) {
  String request_id = IdentifiersFactory::RequestId(
      static_cast<ExecutionContext*>(nullptr), identifier);
  auto dict = std::move(context).WriteDictionary();
  dict.Add("requestId", request_id);
  dict.Add("url", url);
}

void inspector_deserialize_script_event::Data(perfetto::TracedValue context,
                                              uint64_t identifier,
                                              const String& url) {
  String request_id = IdentifiersFactory::RequestId(
      static_cast<ExecutionContext*>(nullptr), identifier);
  auto dict = std::move(context).WriteDictionary();
  dict.Add("requestId", request_id);
  dict.Add("url", url);
}

inspector_compile_script_event::V8ConsumeCacheResult::V8ConsumeCacheResult(
    int cache_size,
    bool rejected,
    bool full)
    : cache_size(cache_size), rejected(rejected), full(full) {}

void inspector_compile_script_event::Data(
    perfetto::TracedValue context,
    const String& url,
    const TextPosition& text_position,
    std::optional<V8ConsumeCacheResult> consume_cache_result,
    bool eager,
    bool streamed,
    ScriptStreamer::NotStreamingReason not_streaming_reason) {
  auto dict = std::move(context).WriteDictionary();
  FillLocation(dict, url, text_position);

  if (consume_cache_result) {
    dict.Add("consumedCacheSize", consume_cache_result->cache_size);
    dict.Add("cacheRejected", consume_cache_result->rejected);
    dict.Add("cacheKind", consume_cache_result->full ? "full" : "normal");
  }
  if (eager) {
    // Eager compilation is rare so only add this key when it's set.
    dict.Add("eager", true);
  }
  dict.Add("streamed", streamed);
  if (!streamed) {
    dict.Add("notStreamedReason",
             NotStreamedReasonString(not_streaming_reason));
  }
}

void inspector_produce_script_cache_event::Data(
    perfetto::TracedValue context,
    const String& url,
    const TextPosition& text_position,
    int cache_size) {
  auto dict = std::move(context).WriteDictionary();
  FillLocation(dict, url, text_position);
  dict.Add("producedCacheSize", cache_size);
}

void inspector_handle_post_message_event::Data(
    perfetto::TracedValue context,
    ExecutionContext* execution_context,
    const MessageEvent& message_event) {
  auto dict = std::move(context).WriteDictionary();
  dict.Add("traceId", base::NumberToString(message_event.GetTraceId()));
}

void inspector_schedule_post_message_event::Data(
    perfetto::TracedValue context,
    ExecutionContext* execution_context,
    uint64_t trace_id) {
  auto dict = std::move(context).WriteDictionary();
  dict.Add("traceId", base::NumberToString(trace_id));
  SetCallStack(execution_context->GetIsolate(), dict);
}

void inspector_function_call_event::Data(
    perfetto::TracedValue trace_context,
    ExecutionContext* context,
    const v8::Local<v8::Function>& function) {
  auto dict = std::move(trace_context).WriteDictionary();
  if (LocalFrame* frame = FrameForExecutionContext(context))
    dict.Add("frame", IdentifiersFactory::FrameId(frame));

  if (function.IsEmpty())
    return;

  v8::Local<v8::Function> original_function = GetBoundFunction(function);
  v8::Local<v8::Value> function_name = original_function->GetDebugName();
  if (!function_name.IsEmpty() && function_name->IsString()) {
    dict.Add("functionName", ToCoreString(context->GetIsolate(),
                                          function_name.As<v8::String>()));
  }
  std::unique_ptr<SourceLocation> location =
      CaptureSourceLocation(context->GetIsolate(), original_function);
  dict.Add("scriptId", String::Number(location->ScriptId()));
  dict.Add("url", location->Url());
  dict.Add("lineNumber", location->LineNumber());
  dict.Add("columnNumber", location->ColumnNumber());
}

void inspector_paint_image_event::Data(perfetto::TracedValue context,
                                       const LayoutImage& layout_image,
                                       const gfx::RectF& src_rect,
                                       const gfx::RectF& dest_rect) {
  auto dict = std::move(context).WriteDictionary();
  SetGeneratingNodeInfo(dict, &layout_image, "nodeId");
  if (const ImageResourceContent* content = layout_image.CachedImage())
    dict.Add("url", content->Url().ElidedString());

  dict.Add("x", dest_rect.x());
  dict.Add("y", dest_rect.y());
  dict.Add("width", dest_rect.width());
  dict.Add("height", dest_rect.height());
  dict.Add("srcWidth", src_rect.width());
  dict.Add("srcHeight", src_rect.height());
}

void inspector_paint_image_event::Data(perfetto::TracedValue context,
                                       const LayoutObject& owning_layout_object,
                                       const StyleImage& style_image) {
  auto dict = std::move(context).WriteDictionary();
  SetGeneratingNodeInfo(dict, &owning_layout_object, "nodeId");
  if (const ImageResourceContent* content = style_image.CachedImage())
    dict.Add("url", content->Url().ElidedString());
}

void inspector_paint_image_event::Data(perfetto::TracedValue context,
                                       Node* node,
                                       const StyleImage& style_image,
                                       const gfx::RectF& src_rect,
                                       const gfx::RectF& dest_rect) {
  auto dict = std::move(context).WriteDictionary();
  if (node)
    SetNodeInfo(dict, node, "nodeId", nullptr);
  if (const ImageResourceContent* content = style_image.CachedImage())
    dict.Add("url", content->Url().ElidedString());

  dict.Add("x", dest_rect.x());
  dict.Add("y", dest_rect.y());
  dict.Add("width", dest_rect.width());
  dict.Add("height", dest_rect.height());
  dict.Add("srcWidth", src_rect.width());
  dict.Add("srcHeight", src_rect.height());
}

void inspector_paint_image_event::Data(
    perfetto::TracedValue context,
    const LayoutObject* owning_layout_object,
    const ImageResourceContent& image_content) {
  auto dict = std::move(context).WriteDictionary();
  SetGeneratingNodeInfo(dict, owning_layout_object, "nodeId");
  dict.Add("url", image_content.Url().ElidedString());
}

static size_t UsedHeapSize(v8::Isolate* isolate) {
  v8::HeapStatistics heap_statistics;
  isolate->GetHeapStatistics(&heap_statistics);
  return heap_statistics.used_heap_size();
}

void inspector_update_counters_event::Data(perfetto::TracedValue context,
                                           v8::Isolate* isolate) {
  auto dict = std::move(context).WriteDictionary();
  if (IsMainThread()) {
    dict.Add("documents", InstanceCounters::CounterValue(
                              InstanceCounters::kDocumentCounter));
    dict.Add("nodes",
             InstanceCounters::CounterValue(InstanceCounters::kNodeCounter));
    dict.Add("jsEventListeners",
             InstanceCounters::CounterValue(
                 InstanceCounters::kJSEventListenerCounter));
  }
  dict.Add("jsHeapSizeUsed", static_cast<double>(UsedHeapSize(isolate)));
}

void inspector_invalidate_layout_event::Data(perfetto::TracedValue context,
           
"""


```