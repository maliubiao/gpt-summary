Response:
The user is asking for a summary of the functionalities provided by the given C++ code snippet from `blink/renderer/core/testing/internals.cc`. This file appears to be part of Blink's internal testing infrastructure. It exposes various internal functionalities of the rendering engine to JavaScript for testing purposes.

Here's a breakdown of the thought process to arrive at the summary:

1. **Identify the Core Purpose:** The filename `internals.cc` within a `testing` directory strongly suggests that this code exposes internal Blink functionalities for testing. This is the primary function.

2. **Analyze Individual Methods:** Go through each method in the provided code and determine its purpose. Look for keywords and patterns:
    * **`getCSS...`:**  Retrieves information about CSS properties.
    * **`observeUseCounter`:**  Monitors usage of specific browser features.
    * **`set...State`:** Modifies internal states like Caps Lock or pseudo-class states.
    * **`setScrollbarVisibilityInScrollableArea`:** Controls scrollbar visibility.
    * **`monotonicTimeToZeroBasedDocumentTime` / `zeroBasedDocumentTimeToMonotonicTime` / `currentTimeTicks`:** Deals with time conversions and retrieval.
    * **`get...AnimationState`:** Retrieves the state of scroll animations.
    * **`crash`:** Intentionally crashes the browser – clearly for testing.
    * **`evaluateInInspectorOverlay`:**  Interacts with the browser's developer tools overlay.
    * **`setIsLowEndDevice` / `isLowEndDevice`:** Simulates low-end device characteristics.
    * **`supportedTextEncodingLabels`:**  Retrieves supported text encodings.
    * **`simulateRasterUnderInvalidations`:**  Triggers specific rasterization scenarios.
    * **`DisableIntersectionObserverThrottleDelay`:**  Modifies Intersection Observer behavior.
    * **`isSiteIsolated` / `isTrackingOcclusionForIFrame`:** Checks iframe isolation and occlusion tracking.
    * **`addEmbedderCustomElementName`:** Registers custom element names.
    * **`getParsedImportMap`:** Retrieves the parsed import map.
    * **`setDeviceEmulationScale`:**  Simulates different device scales.
    * **`ResolveResourcePriority`:**  Resolves resource loading priority (likely for testing resource loading).
    * **`getAgentId`:**  Retrieves a unique identifier.
    * **`useMockOverlayScrollbars` / `overlayScrollbarsEnabled`:** Controls the use of mock overlay scrollbars for testing.
    * **`generateTestReport`:** Sends test reports.
    * **`setIsAdFrame`:** Marks a frame as an ad frame.
    * **`createReadableStream` / `createWritableStreamAndSink` / `setAllowPerChunkTransferring`:**  Functions related to testing streams.
    * **`setBackForwardCacheRestorationBufferSize` / `setEventTimingBufferSize` / `stopResponsivenessMetricsUkmSampling`:**  Manipulates performance-related settings.
    * **`getCreatorScripts` / `lastCompiledScriptFileName` / `lastCompiledScriptUsedCodeCache`:**  Provides information about script execution.
    * **`LCPPrediction`:**  Triggers and observes Largest Contentful Paint (LCP) predictions.
    * **`exemptUrlFromNetworkRevocation`:**  Exempts URLs from network revocation (related to fenced frames and unpartitioned data access).

3. **Categorize Functionalities:** Group the identified methods into logical categories. This helps in creating a structured summary. Possible categories include:
    * CSS related
    * Event handling/state manipulation
    * Time and performance measurement
    * Debugging and inspection
    * Device simulation
    * Feature toggles/overrides
    * Frame/isolation related
    * Custom elements
    * Modules/Import Maps
    * Resource loading
    * Streams API testing
    * Performance API testing
    * Script execution details
    * Fenced Frames and related features.

4. **Identify Relationships to Web Technologies (JavaScript, HTML, CSS):**  Many of these functions directly or indirectly relate to web technologies:
    * CSS properties and aliases.
    * JavaScript features and their usage (use counters).
    * HTML elements (iframes, images).
    * DOM manipulation (setting pseudo-class states).
    * Browser APIs (Streams API, Performance API).
    * Concepts like site isolation and fenced frames.

5. **Consider Usage Scenarios and Potential Errors:** Think about how developers or testers might use these functions and what mistakes they could make. For example, providing an invalid pseudo-class name or using the functions in a non-testing context.

6. **Infer User Actions Leading to These Functions:** These functions are primarily accessed programmatically through JavaScript within a testing environment. A developer would write test code that calls these `internals` methods.

7. **Address the "Logical Reasoning" and "Input/Output" Requirement:** For some functions, it's possible to infer input and output. For example, `setCapsLockState(true)` would likely result in the Caps Lock being reported as "on" by the browser. However, many of these functions have side effects or are primarily used for observation, making direct input/output examples less straightforward without a specific test context.

8. **Structure the Summary:** Organize the findings into a coherent summary, addressing the user's specific questions (functionalities, relation to web technologies, examples, debugging, etc.).

9. **Final Review and Refinement:** Read through the summary to ensure accuracy, clarity, and completeness. Make sure it addresses all parts of the user's request. Specifically, confirm that this is part 5 of 5 and explicitly state that it's a summary.
好的，这是对 `blink/renderer/core/testing/internals.cc` 文件功能的归纳总结：

**功能归纳：**

`blink/renderer/core/testing/internals.cc` 文件是 Chromium Blink 引擎中一个专门用于**内部测试**的关键组件。它通过 JavaScript 接口暴露了 Blink 引擎的**内部状态、行为和机制**，允许开发者和测试人员对引擎的各个方面进行更深层次的检查、控制和模拟。

**核心功能可以归纳为以下几个方面：**

1. **访问和修改内部状态:**  它允许 JavaScript 代码访问和修改通常情况下不可访问的 Blink 内部状态，例如：
    * 获取 CSS 属性和别名。
    * 设置 Caps Lock 状态。
    * 强制设置元素的伪类状态。
    * 控制滚动条的可见性。
    * 修改设备是否被认为是低端设备的标志。
    * 启用/禁用模拟覆盖滚动条。
    * 将帧标记为广告帧。
    * 设置后退/前进缓存和事件计时的缓冲区大小。

2. **模拟和触发内部事件/行为:**  它提供了模拟和触发 Blink 内部事件和行为的能力，例如：
    * 观察特定 Web 功能的使用情况 (Use Counter)。
    * 模拟光栅化无效。
    * 禁用 Intersection Observer 的节流延迟。
    * 触发崩溃。
    * 在 Inspector Overlay 中执行 JavaScript 代码。
    * 模拟设备像素比。
    * 生成测试报告。

3. **提供内部信息和度量:**  它允许 JavaScript 代码获取 Blink 引擎的内部信息和度量数据，例如：
    * 将平台时间转换为文档时间，反之亦然。
    * 获取当前的单调时间戳。
    * 获取滚动动画的状态。
    * 获取已解析的 Import Map。
    * 获取唯一的 Agent ID。
    * 获取创建 `HTMLImageElement` 的脚本信息。
    * 获取最后编译的脚本文件名和是否使用了代码缓存。
    * 获取 LCP (Largest Contentful Paint) 的预测信息。
    * 判断 iframe 是否跨域隔离。
    * 判断 iframe 是否在进行遮挡追踪。

4. **提供测试辅助功能:**  它提供了一些专门为测试设计的辅助功能，例如：
    * 添加嵌入器自定义元素名称。
    * 创建可读/可写流，并控制其优化器。
    * 允许对可读流进行逐块传输。
    * 豁免 URL 的网络撤销 (用于测试 Fenced Frames)。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

`internals.cc` 作为一个测试工具，其功能直接服务于对 JavaScript, HTML 和 CSS 相关特性的测试。它允许测试人员在更底层去验证这些技术的实现细节和边界情况。

* **JavaScript:**
    * **`observeUseCounter`:** 可以用来测试 JavaScript API 的使用情况是否符合预期。例如，假设测试代码使用了 `fetch` API，可以通过 `Internals.observeUseCounter(document, WebFeature.FetchAPI)` 来验证该 API 是否被正确计数。
    * **`evaluateInInspectorOverlay`:** 允许在浏览器的开发者工具的覆盖层中执行 JavaScript 代码，这对于调试和检查 JavaScript 的行为非常有用。
    * **`createReadableStream` / `createWritableStreamAndSink`:**  可以用来测试 JavaScript 的 Streams API 的实现。例如，可以创建一个可读流和一个可写流，并在它们之间传输数据来验证流的正确性。
    * **`LCPPrediction`:**  允许测试在 JavaScript 中触发 LCP 预测的机制，并验证预测结果。

* **HTML:**
    * **`isSiteIsolated`:** 可以用来验证 iframe 是否实现了站点隔离，这对于测试安全特性至关重要。例如，可以创建一个跨域的 iframe，然后使用 `Internals.isSiteIsolated(iframe)` 来检查它是否被隔离。
    * **`setIsAdFrame`:**  允许将一个 iframe 标记为广告帧，这可以用来测试浏览器对广告帧的特殊处理逻辑。
    * **`getCreatorScripts`:**  可以用来追踪 HTML 元素的创建脚本，帮助理解页面的构建过程。例如，对于一个 `<img>` 元素，可以使用 `Internals.getCreatorScripts(img)` 来获取创建它的 JavaScript 代码片段。

* **CSS:**
    * **`getCSSPropertyNames` / `getCSSPropertyAliases`:** 可以获取所有支持的 CSS 属性和别名，用于验证 CSS 解析和渲染的正确性。
    * **`setPseudoClassState`:**  允许强制设置元素的伪类状态，例如 `:hover` 或 `:focus`，即使鼠标没有悬停或元素没有被聚焦。这对于测试 CSS 样式在特定状态下的表现非常有用。例如，可以调用 `Internals.setPseudoClassState(element, "hover", true)` 来模拟元素的 `:hover` 状态。
    * **`setScrollbarVisibilityInScrollableArea`:** 可以控制滚动条的显示与隐藏，用于测试不同滚动条状态下的布局和渲染。

**假设输入与输出 (逻辑推理举例):**

假设我们有一个 `<div>` 元素，并且想测试当它处于 `:hover` 状态时的样式。

* **假设输入:**
    * JavaScript 代码：`Internals.setPseudoClassState(myDivElement, "hover", true);`
    * CSS 规则：`.my-div:hover { background-color: red; }`
* **预期输出:**
    * `myDivElement` 的背景颜色应该变为红色，即使鼠标并没有实际悬停在上面。

**用户或编程常见的使用错误举例:**

* **错误使用场景:** 在非测试环境下（例如生产环境的网页代码中）调用 `Internals` 对象的方法。由于这些方法暴露了内部实现细节，并且可能绕过正常的安全检查，因此在生产环境中使用可能会导致不可预测的行为甚至安全漏洞。
* **错误示例:**  开发者可能会错误地尝试在正式上线的网站中使用 `Internals.crash()` 来处理某些错误情况，但这会导致用户的浏览器崩溃。
* **调试线索:** 如果在代码中遇到了 `Internals` 对象的方法调用，并且行为与预期不符，首先需要检查代码是否运行在正确的测试环境下。如果不是，则需要移除这些调用。

**用户操作如何一步步到达这里 (作为调试线索):**

通常情况下，普通用户无法直接触发 `internals.cc` 中的代码。这些方法主要是通过 **JavaScript 测试脚本** 在 Blink 的 **测试框架** 中被调用。

1. **开发者编写测试:**  Blink 的开发者或贡献者会编写 JavaScript 测试代码，这些测试代码会使用 `internals` 对象来访问和操作引擎的内部状态。这些测试通常位于 `blink/web_tests/` 目录下。
2. **运行测试:**  开发者会使用特定的测试工具（例如 `run_web_tests.py`）来运行这些测试。
3. **Blink 加载测试页面:**  测试工具会启动一个 Chromium 实例，并加载包含测试代码的 HTML 页面。
4. **JavaScript 执行并调用 `internals` 方法:**  测试页面中的 JavaScript 代码会被执行，当遇到对 `internals` 对象方法的调用时，Blink 引擎会将这些调用路由到 `blink/renderer/core/testing/internals.cc` 中的对应 C++ 方法。
5. **C++ 方法执行并影响引擎状态:**  `internals.cc` 中的 C++ 方法会被执行，从而修改 Blink 引擎的内部状态或执行特定的操作。
6. **测试断言:**  测试代码会检查引擎的状态是否符合预期，例如，检查元素的样式是否被正确应用，或者是否触发了预期的事件。

**总结:**

总而言之，`blink/renderer/core/testing/internals.cc` 是 Blink 引擎中一个至关重要的测试工具，它赋予测试人员强大的能力来深入了解和验证引擎的内部工作机制。虽然普通用户不会直接接触到它，但它对于保证 Blink 引擎的质量和稳定性起着至关重要的作用。它通过 JavaScript 暴露的接口，使得测试能够覆盖到 CSS 属性、HTML 结构、JavaScript 行为以及各种内部状态和事件，从而确保 Web 平台的各个方面都能按预期工作。

### 提示词
```
这是目录为blink/renderer/core/testing/internals.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第5部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
result.push_back(property_class.GetPropertyNameString());
    }
  }
  return result;
}

Vector<String> Internals::getCSSPropertyAliases() const {
  Vector<String> result;
  for (CSSPropertyID alias : kCSSPropertyAliasList) {
    DCHECK(IsPropertyAlias(alias));
    const CSSUnresolvedProperty& property_class = *GetPropertyInternal(alias);
    if (property_class.IsWebExposed(document_->GetExecutionContext())) {
      result.push_back(property_class.GetPropertyNameString());
    }
  }
  return result;
}

ScriptPromise<IDLUndefined> Internals::observeUseCounter(
    ScriptState* script_state,
    Document* document,
    uint32_t feature) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(script_state);
  auto promise = resolver->Promise();
  if (feature > static_cast<int32_t>(WebFeature::kMaxValue)) {
    resolver->Reject();
    return promise;
  }

  WebFeature use_counter_feature = static_cast<WebFeature>(feature);
  if (document->IsUseCounted(use_counter_feature)) {
    resolver->Resolve();
    return promise;
  }

  DocumentLoader* loader = document->Loader();
  if (!loader) {
    resolver->Reject();
    return promise;
  }

  loader->GetUseCounter().AddObserver(
      MakeGarbageCollected<UseCounterImplObserverImpl>(
          resolver, static_cast<WebFeature>(use_counter_feature)));
  return promise;
}

String Internals::unscopableAttribute() {
  return "unscopableAttribute";
}

String Internals::unscopableMethod() {
  return "unscopableMethod";
}

void Internals::setCapsLockState(bool enabled) {
  KeyboardEventManager::SetCurrentCapsLockState(
      enabled ? OverrideCapsLockState::kOn : OverrideCapsLockState::kOff);
}

void Internals::setPseudoClassState(Element* element,
                                    const String& pseudo,
                                    bool matches,
                                    ExceptionState& exception_state) {
  if (!element->GetDocument().SetPseudoStateForTesting(*element, pseudo,
                                                       matches)) {
    exception_state.ThrowDOMException(DOMExceptionCode::kNotSupportedError,
                                      pseudo + " is not supported");
  }
}

bool Internals::setScrollbarVisibilityInScrollableArea(Node* node,
                                                       bool visible) {
  if (ScrollableArea* scrollable_area = ScrollableAreaForNode(node)) {
    scrollable_area->SetScrollbarsHiddenForTesting(!visible);

    if (MacScrollbarAnimator* scrollbar_animator =
            scrollable_area->GetMacScrollbarAnimator()) {
      scrollbar_animator->SetScrollbarsVisibleForTesting(visible);
    }

    return scrollable_area->GetPageScrollbarTheme().UsesOverlayScrollbars();
  }
  return false;
}

double Internals::monotonicTimeToZeroBasedDocumentTime(
    double platform_time,
    ExceptionState& exception_state) {
  return document_->Loader()
      ->GetTiming()
      .MonotonicTimeToZeroBasedDocumentTime(base::TimeTicks() +
                                            base::Seconds(platform_time))
      .InSecondsF();
}

int64_t Internals::zeroBasedDocumentTimeToMonotonicTime(double dom_event_time) {
  return document_->Loader()->GetTiming().ZeroBasedDocumentTimeToMonotonicTime(
      dom_event_time);
}

int64_t Internals::currentTimeTicks() {
  return base::TimeTicks::Now().since_origin().InMicroseconds();
}

String Internals::getScrollAnimationState(Node* node) const {
  if (ScrollableArea* scrollable_area = ScrollableAreaForNode(node))
    return scrollable_area->GetScrollAnimator().RunStateAsText();
  return String();
}

String Internals::getProgrammaticScrollAnimationState(Node* node) const {
  if (ScrollableArea* scrollable_area = ScrollableAreaForNode(node))
    return scrollable_area->GetProgrammaticScrollAnimator().RunStateAsText();
  return String();
}

void Internals::crash() {
  CHECK(false) << "Intentional crash";
}

String Internals::evaluateInInspectorOverlay(const String& script) {
  LocalFrame* frame = GetFrame();
  if (frame && frame->Client())
    return frame->Client()->evaluateInInspectorOverlayForTesting(script);
  return g_empty_string;
}

void Internals::setIsLowEndDevice(bool is_low_end_device) {
  MemoryPressureListenerRegistry::SetIsLowEndDeviceForTesting(
      is_low_end_device);
}

bool Internals::isLowEndDevice() const {
  return MemoryPressureListenerRegistry::IsLowEndDevice();
}

Vector<String> Internals::supportedTextEncodingLabels() const {
  return WTF::TextEncodingAliasesForTesting();
}

void Internals::simulateRasterUnderInvalidations(bool enable) {
  RasterInvalidationTracking::SimulateRasterUnderInvalidations(enable);
}

void Internals::DisableIntersectionObserverThrottleDelay() const {
  // This gets reset by Internals::ResetToConsistentState
  IntersectionObserver::SetThrottleDelayEnabledForTesting(false);
}

bool Internals::isSiteIsolated(HTMLIFrameElement* iframe) const {
  return iframe->ContentFrame() && iframe->ContentFrame()->IsRemoteFrame();
}

bool Internals::isTrackingOcclusionForIFrame(HTMLIFrameElement* iframe) const {
  if (!iframe->ContentFrame() || !iframe->ContentFrame()->IsRemoteFrame())
    return false;
  RemoteFrame* remote_frame = To<RemoteFrame>(iframe->ContentFrame());
  return remote_frame->View()->NeedsOcclusionTracking();
}

void Internals::addEmbedderCustomElementName(const AtomicString& name,
                                             ExceptionState& exception_state) {
  CustomElement::AddEmbedderCustomElementNameForTesting(name, exception_state);
}

String Internals::getParsedImportMap(Document* document,
                                     ExceptionState& exception_state) {
  Modulator* modulator =
      Modulator::From(ToScriptStateForMainWorld(document->GetFrame()));

  if (!modulator) {
    exception_state.ThrowTypeError("No modulator");
    return String();
  }

  const ImportMap* import_map = modulator->GetImportMapForTest();
  if (!import_map)
    return "{}";

  return import_map->ToStringForTesting();
}

void Internals::setDeviceEmulationScale(float scale,
                                        ExceptionState& exception_state) {
  if (scale <= 0)
    return;
  auto* page = document_->GetPage();
  if (!page) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidAccessError,
        "The document's page cannot be retrieved.");
    return;
  }
  DeviceEmulationParams params;
  params.scale = scale;
  page->GetChromeClient().GetWebView()->EnableDeviceEmulation(params);
}

void Internals::ResolveResourcePriority(
    ScriptPromiseResolver<IDLLong>* resolver,
    int resource_load_priority) {
  resolver->Resolve(resource_load_priority);
}

String Internals::getAgentId(DOMWindow* window) {
  if (!window->IsLocalDOMWindow())
    return String();

  // Create a unique id from the process id and the address of the agent.
  const base::ProcessId process_id = base::GetCurrentProcId();
  uintptr_t agent_address =
      reinterpret_cast<uintptr_t>(To<LocalDOMWindow>(window)->GetAgent());

  // This serializes a pointer as a decimal number, which is a bit ugly, but
  // it works. Is there any utility to dump a number in a hexadecimal form?
  // I couldn't find one in WTF.
  return String::Number(process_id) + ":" + String::Number(agent_address);
}

void Internals::useMockOverlayScrollbars() {
  // Note: it's important to reset `g_mock_overlay_scrollbars` before the
  // assignment, since if `g_mock_overlay_scrollbars` is non-null, its
  // destructor will end up running after the constructor for the new
  // ScopedMockOverlayScrollbars runs, meaning the global state the new pointer
  // stores will in fact be the state from the previous pointer, which may not
  // be what was intended. E.g. if a test calls this function twice, then
  // whatever the original global state was in Blink's ScrollbarThemeSettings
  // will be lost, and the state after the second call may be wrong.
  ResetMockOverlayScrollbars();
  g_mock_overlay_scrollbars = new ScopedMockOverlayScrollbars(true);
}

bool Internals::overlayScrollbarsEnabled() const {
  return ScrollbarThemeSettings::OverlayScrollbarsEnabled();
}

void Internals::generateTestReport(const String& message) {
  // Construct the test report.
  TestReportBody* body = MakeGarbageCollected<TestReportBody>(message);
  Report* report =
      MakeGarbageCollected<Report>("test", document_->Url().GetString(), body);

  // Send the test report to any ReportingObservers.
  ReportingContext::From(document_->domWindow())->QueueReport(report);
}

void Internals::setIsAdFrame(Document* target_doc,
                             ExceptionState& exception_state) {
  LocalFrame* frame = target_doc->GetFrame();

  if (frame->IsMainFrame() && !frame->IsInFencedFrameTree()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotSupportedError,
        "Frame must be an iframe or a fenced frame.");
    return;
  }

  blink::FrameAdEvidence ad_evidence(/*parent_is_ad=*/frame->Parent() &&
                                     frame->Parent()->IsAdFrame());
  ad_evidence.set_created_by_ad_script(
      mojom::FrameCreationStackEvidence::kCreatedByAdScript);
  ad_evidence.set_is_complete();
  frame->SetAdEvidence(ad_evidence);
}

ReadableStream* Internals::createReadableStream(
    ScriptState* script_state,
    int32_t queue_size,
    const String& optimizer,
    ExceptionState& exception_state) {
  TestReadableStreamSource::Type type;
  if (optimizer.empty()) {
    type = TestReadableStreamSource::Type::kWithNullOptimizer;
  } else if (optimizer == "perform-null") {
    type = TestReadableStreamSource::Type::kWithPerformNullOptimizer;
  } else if (optimizer == "observable") {
    type = TestReadableStreamSource::Type::kWithObservableOptimizer;
  } else if (optimizer == "perfect") {
    type = TestReadableStreamSource::Type::kWithPerformNullOptimizer;
  } else {
    exception_state.ThrowRangeError(
        "The \"optimizer\" parameter is not correctly set.");
    return nullptr;
  }
  auto* source =
      MakeGarbageCollected<TestReadableStreamSource>(script_state, type);
  source->Attach(std::make_unique<TestReadableStreamSource::Generator>(10));
  return ReadableStream::CreateWithCountQueueingStrategy(
      script_state, source, queue_size, AllowPerChunkTransferring(false),
      source->CreateTransferringOptimizer(script_state));
}

ScriptValue Internals::createWritableStreamAndSink(
    ScriptState* script_state,
    int32_t queue_size,
    const String& optimizer,
    ExceptionState& exception_state) {
  TestWritableStreamSink::Type type;
  if (optimizer.empty()) {
    type = TestWritableStreamSink::Type::kWithNullOptimizer;
  } else if (optimizer == "perform-null") {
    type = TestWritableStreamSink::Type::kWithPerformNullOptimizer;
  } else if (optimizer == "observable") {
    type = TestWritableStreamSink::Type::kWithObservableOptimizer;
  } else if (optimizer == "perfect") {
    type = TestWritableStreamSink::Type::kWithPerfectOptimizer;
  } else {
    exception_state.ThrowRangeError(
        "The \"optimizer\" parameter is not correctly set.");
    return ScriptValue();
  }

  ExecutionContext* context = ExecutionContext::From(script_state);
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLString>>(script_state);
  auto internal_sink = std::make_unique<TestWritableStreamSink::InternalSink>(
      context->GetTaskRunner(TaskType::kInternalDefault),
      CrossThreadBindOnce(&TestWritableStreamSink::Resolve,
                          MakeUnwrappingCrossThreadHandle(resolver)),
      CrossThreadBindOnce(&TestWritableStreamSink::Reject,
                          MakeUnwrappingCrossThreadHandle(resolver)));
  auto* sink = MakeGarbageCollected<TestWritableStreamSink>(script_state, type);

  sink->Attach(std::move(internal_sink));
  auto* stream = WritableStream::CreateWithCountQueueingStrategy(
      script_state, sink, queue_size,
      sink->CreateTransferringOptimizer(script_state));

  v8::Local<v8::Object> object = v8::Object::New(script_state->GetIsolate());
  object
      ->Set(script_state->GetContext(),
            V8String(script_state->GetIsolate(), "stream"),
            ToV8Traits<WritableStream>::ToV8(script_state, stream))
      .Check();
  object
      ->Set(script_state->GetContext(),
            V8String(script_state->GetIsolate(), "sink"),
            ToV8Traits<IDLPromise<IDLString>>::ToV8(script_state,
                                                    resolver->Promise()))
      .Check();
  return ScriptValue(script_state->GetIsolate(), object);
}

void Internals::setAllowPerChunkTransferring(ReadableStream* stream) {
  if (!stream) {
    return;
  }
  stream->SetAllowPerChunkTransferringForTesting(
      AllowPerChunkTransferring(true));
}

void Internals::setBackForwardCacheRestorationBufferSize(unsigned int maxSize) {
  WindowPerformance& perf =
      *DOMWindowPerformance::performance(*document_->domWindow());
  perf.setBackForwardCacheRestorationBufferSizeForTest(maxSize);
}

void Internals::setEventTimingBufferSize(unsigned int maxSize) {
  WindowPerformance& perf =
      *DOMWindowPerformance::performance(*document_->domWindow());
  perf.setEventTimingBufferSizeForTest(maxSize);
}

void Internals::stopResponsivenessMetricsUkmSampling() {
  WindowPerformance& perf =
      *DOMWindowPerformance::performance(*document_->domWindow());
  perf.GetResponsivenessMetrics().StopUkmSamplingForTesting();
}

Vector<String> Internals::getCreatorScripts(HTMLImageElement* img) {
  DCHECK(img);
  return Vector<String>(img->creator_scripts());
}

String Internals::lastCompiledScriptFileName(Document* document) {
  return ToScriptStateForMainWorld(document->GetFrame())
      ->last_compiled_script_file_name();
}

bool Internals::lastCompiledScriptUsedCodeCache(Document* document) {
  return ToScriptStateForMainWorld(document->GetFrame())
      ->last_compiled_script_used_code_cache();
}

ScriptPromise<IDLString> Internals::LCPPrediction(ScriptState* script_state,
                                                  Document* document) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLString>>(script_state);
  auto promise = resolver->Promise();

  LCPCriticalPathPredictor* lcpp = document->GetFrame()->GetLCPP();
  CHECK(lcpp);
  lcpp->AddLCPPredictedCallback(
      WTF::BindOnce(&OnLCPPredicted, WrapPersistent(resolver)));
  return promise;
}

void ExemptUrlFromNetworkRevocationComplete(
    ScriptPromiseResolver<IDLUndefined>* resolver) {
  resolver->Resolve();
}

ScriptPromise<IDLUndefined> Internals::exemptUrlFromNetworkRevocation(
    ScriptState* script_state,
    const String& url) {
  if (!blink::features::IsFencedFramesEnabled()) {
    return EmptyPromise();
  }
  if (!base::FeatureList::IsEnabled(
          blink::features::kFencedFramesLocalUnpartitionedDataAccess)) {
    return EmptyPromise();
  }
  if (!base::FeatureList::IsEnabled(
          blink::features::kExemptUrlFromNetworkRevocationForTesting)) {
    return EmptyPromise();
  }
  if (!GetFrame()) {
    return EmptyPromise();
  }
  LocalFrame* frame = GetFrame();
  DCHECK(frame->GetDocument());
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(script_state);
  auto promise = resolver->Promise();
  frame->GetLocalFrameHostRemote().ExemptUrlFromNetworkRevocationForTesting(
      url_test_helpers::ToKURL(url.Utf8()),
      WTF::BindOnce(&ExemptUrlFromNetworkRevocationComplete,
                    WrapPersistent(resolver)));
  return promise;
}

}  // namespace blink
```