Response:
Let's break down the thought process for analyzing this code snippet and generating the comprehensive response.

**1. Understanding the Request:**

The core request is to analyze a specific Chromium Blink source code file (`inspector_page_agent.cc`) and identify its functions, relationships to web technologies (JavaScript, HTML, CSS), potential logic, and common usage errors. The request also emphasizes this is part 3 of 3, implying a need for a summary.

**2. Initial Scan and Keyword Spotting:**

The first step is to quickly scan the code, looking for keywords and patterns that indicate functionality. Key terms that jump out are:

* `InspectorPageAgent`: The central class.
* `protocol::Page::`, `protocol::DOM::`:  Indicates communication using a protocol, likely the Chrome DevTools Protocol (CDP).
* `LayoutViewport`, `VisualViewport`, `ContentSize`:  Terms related to page layout and rendering.
* `createIsolatedWorld`: Hints at creating JavaScript execution environments.
* `setFontFamilies`, `setFontSizes`:  Directly related to CSS styling.
* `CompilationCache`:  Related to JavaScript performance optimization.
* `FileChooserOpened`:  Related to file uploads in HTML forms.
* `WaitForDebugger`:  A debugging function.
* `GenerateTestReport`:  Potentially for automated testing.
* `OriginTrials`: A specific web platform feature.
* `LocalFrame`, `LocalDOMWindow`:  Blink internal classes representing document structure.
* `gfx::Rect`, `gfx::Size`:  Geometric data structures.
* `v8::`:  Interaction with the V8 JavaScript engine.

**3. Grouping Functionality:**

Based on the keywords and the structure of the code (methods within the `InspectorPageAgent` class), I started grouping related functionalities:

* **Viewport and Layout:**  The `getLayoutMetrics` function clearly deals with obtaining information about the layout viewport, visual viewport, and content size. This directly relates to how the browser renders the page (HTML and CSS).
* **Isolated Worlds:**  The `createIsolatedWorld` family of functions is about creating isolated JavaScript execution environments within a frame. This is crucial for debugging and extensions.
* **Font Settings:**  `setFontFamilies` and `setFontSizes` are directly about manipulating CSS font properties.
* **JavaScript Compilation Cache:** The functions `ApplyCompilationModeOverride`, `DidProduceCompilationCache`, `produceCompilationCache`, `addCompilationCache`, and `clearCompilationCache` are all related to optimizing JavaScript loading and execution.
* **File Chooser Interception:** `FileChooserOpened` and `setInterceptFileChooserDialog` deal with controlling the browser's file selection dialog.
* **Debugging:** `waitForDebugger` is a straightforward debugging command.
* **Testing:** `generateTestReport` indicates support for sending test results.
* **Origin Trials:** `getOriginTrials` retrieves information about experimental browser features.

**4. Analyzing Individual Functions and their Relationships:**

For each group, I examined the specific functions in more detail:

* **Viewport and Layout:**  I noted the calculations involving scaling factors (`css_to_physical`, `physical_to_css`, `page_zoom_factor`) and how they convert between physical and CSS pixels. This highlights the interaction between the browser's rendering engine and CSS layout.
* **Isolated Worlds:** I recognized the logic for handling provisional frames and the use of `DOMWrapperWorld`. This relates to JavaScript execution contexts and how they're isolated.
* **Font Settings:**  I analyzed how the code iterates through script-specific font families and updates the `GenericFontFamilySettings`. This directly manipulates how text is rendered based on CSS.
* **JavaScript Compilation Cache:**  I focused on the interaction with the V8 engine's caching mechanisms and the different compilation modes (eager vs. default). This is about optimizing JavaScript performance.
* **File Chooser Interception:** The key observation was the `intercept_file_chooser_` flag and how it prevents the native file dialog from appearing.
* **Debugging, Testing, Origin Trials:** These were relatively straightforward, indicating their specific purposes.

**5. Identifying Connections to Web Technologies:**

This involved explicitly linking the identified functionalities to JavaScript, HTML, and CSS:

* **JavaScript:** Isolated worlds, compilation cache, debugging, file chooser (form elements).
* **HTML:** File chooser (input elements), potentially the structure being analyzed for layout metrics.
* **CSS:** Font families and sizes, layout metrics (viewport and content size).

**6. Generating Examples (Logic, Usage Errors):**

* **Logic (Viewport):**  I created a simple scenario with specific input values (visible content rectangle) and showed how the code would calculate the CSS layout viewport. This demonstrates the conversion logic.
* **Usage Errors (Isolated Worlds):** I focused on the error case where the agent isn't enabled, which is a common setup issue.
* **Usage Errors (Font Families):** I highlighted the "set once" limitation, a specific constraint in the implementation.

**7. Formulating Assumptions and Outputs:**

For the logical examples, I explicitly stated the assumptions made about the input and clearly showed the expected output based on the code's logic.

**8. Structuring the Response:**

I organized the findings into clear sections:

* **Overall Function:** A high-level summary.
* **Detailed Functions:**  Breaking down each functionality group.
* **Relationships with Web Technologies:** Explicit connections to JavaScript, HTML, and CSS with examples.
* **Logic and Reasoning:**  Presenting the logical example with assumptions and output.
* **Common Usage Errors:** Listing potential issues.
* **Summary (Part 3):**  A concise recap of the agent's role.

**9. Refinement and Review:**

I reread the generated response to ensure clarity, accuracy, and completeness. I checked that all parts of the original request were addressed and that the examples were easy to understand. I made sure the language was precise and avoided jargon where possible. For example, instead of just saying "CDP," I clarified it as "Chrome DevTools Protocol."

This iterative process of scanning, grouping, analyzing, connecting, and refining allowed for a comprehensive understanding and explanation of the `InspectorPageAgent`'s functionality.
好的，这是对 `blink/renderer/core/inspector/inspector_page_agent.cc` 文件功能的归纳总结，并结合了之前两部分的分析。

**整体功能归纳（基于全部三部分）：**

`InspectorPageAgent` 是 Chromium Blink 引擎中负责连接渲染引擎核心与 Chrome DevTools 前端的关键组件。它作为 DevTools 中 "Page" 面板的后端实现，允许开发者通过 DevTools 界面来检查和操作页面的各种属性和行为。

**具体功能列表 (结合第三部分内容)：**

* **获取和设置页面布局和视口信息:**
    * **`getLayoutMetrics`:**  计算并返回页面的各种布局指标，包括布局视口（LayoutViewport）、可视视口（VisualViewport）和内容大小（ContentSize）。这些信息可以以物理像素和 CSS 像素两种单位返回。
        * **与 HTML, CSS 的关系:**  这些指标直接反映了浏览器如何解析和渲染 HTML 结构以及 CSS 样式。例如，`clientWidth` 和 `clientHeight` 反映了 CSS 中设置的元素尺寸，而滚动偏移量则与用户在 HTML 页面中的滚动操作有关。
        * **逻辑推理 (假设输入与输出):**
            * **假设输入:**  主 Frame 的可视内容矩形 (物理像素) 为 `(0, 0, 800, 600)`，布局缩放因子为 `1.0` (无缩放)，页面缩放因子也为 `1.0`。
            * **输出 (部分):**  计算出的 CSS 布局视口 `LayoutViewport` 的 `pageX` 为 0，`pageY` 为 0，`clientWidth` 为 800，`clientHeight` 为 600。CSS 可视视口 `VisualViewport` 的 `clientWidth` 和 `clientHeight` 也将是 800 和 600。
* **创建隔离的 JavaScript 执行环境 (Isolated Worlds):**
    * **`createIsolatedWorld` / `CreateIsolatedWorldImpl`:** 允许在特定的 Frame 中创建一个新的、隔离的 JavaScript 执行环境。这对于调试和注入不与页面原有 JavaScript 冲突的脚本非常有用。
        * **与 JavaScript 的关系:**  此功能直接操作 JavaScript 的执行上下文，允许开发者在隔离的环境中运行 JavaScript 代码。
        * **用户/编程常见的使用错误:**  在 `createIsolatedWorld` 被调用前，如果 Inspector Agent 没有被启用，会导致调用失败。代码中通过检查 `enabled_.Get()` 来避免这种情况。
* **设置页面字体:**
    * **`setFontFamilies`:** 允许为不同的脚本设置特定的字体族。
        * **与 CSS 的关系:**  直接影响页面的文本渲染，等价于修改 CSS 中的 `font-family` 属性。
    * **`setFontSizes`:** 允许设置默认的字号和固定字号。
        * **与 CSS 的关系:**  直接影响页面的文本渲染，等价于修改 CSS 中的 `font-size` 属性。
        * **用户/编程常见的使用错误:**  `setFontFamilies` 中有逻辑限制，同一种字体设置只能设置一次。如果重复设置会返回错误。
* **JavaScript 编译缓存控制:**
    * **`ApplyCompilationModeOverride`:**  在 JavaScript 脚本编译前，根据配置修改编译选项（例如，强制进行 eager compilation）。
        * **与 JavaScript 的关系:**  影响 JavaScript 的编译过程，可以用于性能优化。
    * **`DidProduceCompilationCache`:**  当 JavaScript 脚本编译完成后，接收编译缓存数据并通知 DevTools 前端。
        * **与 JavaScript 的关系:**  与 JavaScript 的性能相关，通过缓存编译结果加速加载。
    * **`produceCompilationCache`:**  请求生成指定 URL JavaScript 文件的编译缓存。
        * **与 JavaScript 的关系:**  主动请求生成缓存，用于性能优化。
    * **`addCompilationCache`:**  手动添加 JavaScript 编译缓存。
        * **与 JavaScript 的关系:**  允许开发者提供预编译的缓存数据。
    * **`clearCompilationCache`:**  清除当前页面的 JavaScript 编译缓存。
        * **与 JavaScript 的关系:**  清除缓存，用于测试或解决缓存相关问题。
* **文件选择器 (File Chooser) 控制:**
    * **`FileChooserOpened`:**  当页面打开文件选择对话框时被调用，通知 DevTools 前端。
        * **与 HTML 的关系:**  与 HTML 中的 `<input type="file">` 元素相关。
    * **`setInterceptFileChooserDialog`:**  允许拦截和控制文件选择对话框的行为。
        * **与 HTML 的关系:**  允许 DevTools 控制用户与文件选择对话框的交互。
        * **用户/编程常见的使用错误:**  如果启用了拦截，但 DevTools 前端没有处理 `fileChooserOpened` 事件并提供文件，用户将无法完成文件选择。
* **触发 Debugger 断点:**
    * **`waitForDebugger`:**  暂停 JavaScript 执行，触发 debugger 断点。
        * **与 JavaScript 的关系:**  用于 JavaScript 调试。
* **生成测试报告:**
    * **`generateTestReport`:**  允许从页面生成并发送测试报告。
        * **与 JavaScript 的关系:**  通常由 JavaScript 代码调用来生成测试结果。
* **获取 Origin Trials 信息:**
    * **`getOriginTrials`:**  获取指定 Frame 的 Origin Trials 信息。
        * **与 JavaScript, HTML 的关系:** Origin Trials 是一种允许在正式发布前测试实验性 Web 平台特性的机制，可能涉及到 JavaScript API 或 HTML 特性的变化。

**总结:**

`InspectorPageAgent` 扮演着 DevTools "Page" 面板与 Blink 渲染引擎之间的桥梁角色。它提供了丰富的功能，涵盖了页面布局、JavaScript 执行环境、字体设置、JavaScript 性能优化、文件选择控制、调试支持和测试报告生成等多个方面。它允许开发者深入了解和操控页面的内部状态，是 Web 开发和调试的重要工具。

希望这个更全面的总结能够帮助你理解 `InspectorPageAgent` 的功能。

### 提示词
```
这是目录为blink/renderer/core/inspector/inspector_page_agent.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第3部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
evice pixels" coming from Blink are also unscaled by
  // pinch-zoom.
  float css_to_physical = main_frame->LayoutZoomFactor();
  float physical_to_css = 1.f / css_to_physical;

  // `visible_contents` is in physical pixels. Normlisation is needed to
  // convert it to CSS pixels. Details: https://crbug.com/1181313
  gfx::Rect css_visible_contents =
      gfx::ScaleToEnclosedRect(visible_contents, physical_to_css);

  *out_css_layout_viewport = protocol::Page::LayoutViewport::create()
                                 .setPageX(css_visible_contents.x())
                                 .setPageY(css_visible_contents.y())
                                 .setClientWidth(css_visible_contents.width())
                                 .setClientHeight(css_visible_contents.height())
                                 .build();

  LocalFrameView* frame_view = main_frame->View();

  gfx::Size content_size = frame_view->GetScrollableArea()->ContentsSize();
  *out_content_size = protocol::DOM::Rect::create()
                          .setX(0)
                          .setY(0)
                          .setWidth(content_size.width())
                          .setHeight(content_size.height())
                          .build();

  // `content_size` is in physical pixels. Normlisation is needed to convert it
  // to CSS pixels. Details: https://crbug.com/1181313
  gfx::Size css_content_size =
      gfx::ScaleToFlooredSize(content_size, physical_to_css);
  *out_css_content_size = protocol::DOM::Rect::create()
                              .setX(0.0)
                              .setY(0.0)
                              .setWidth(css_content_size.width())
                              .setHeight(css_content_size.height())
                              .build();

  // page_zoom_factor transforms CSS pixels into DIPs (device independent
  // pixels).  This is the zoom factor coming only from browser ctrl+/-
  // zooming.
  float page_zoom_factor =
      css_to_physical /
      main_frame->GetPage()->GetChromeClient().WindowToViewportScalar(
          main_frame, 1.f);
  gfx::RectF visible_rect = visual_viewport.VisibleRect();
  float scale = visual_viewport.Scale();
  ScrollOffset page_offset = frame_view->GetScrollableArea()->GetScrollOffset();
  *out_visual_viewport = protocol::Page::VisualViewport::create()
                             .setOffsetX(visible_rect.x() * physical_to_css)
                             .setOffsetY(visible_rect.y() * physical_to_css)
                             .setPageX(page_offset.x() * physical_to_css)
                             .setPageY(page_offset.y() * physical_to_css)
                             .setClientWidth(visible_rect.width())
                             .setClientHeight(visible_rect.height())
                             .setScale(scale)
                             .setZoom(page_zoom_factor)
                             .build();

  *out_css_visual_viewport =
      protocol::Page::VisualViewport::create()
          .setOffsetX(visible_rect.x() * physical_to_css)
          .setOffsetY(visible_rect.y() * physical_to_css)
          .setPageX(page_offset.x() * physical_to_css)
          .setPageY(page_offset.y() * physical_to_css)
          .setClientWidth(visible_rect.width() * physical_to_css)
          .setClientHeight(visible_rect.height() * physical_to_css)
          .setScale(scale)
          .setZoom(page_zoom_factor)
          .build();
  return protocol::Response::Success();
}

void InspectorPageAgent::createIsolatedWorld(
    const String& frame_id,
    Maybe<String> world_name,
    Maybe<bool> grant_universal_access,
    std::unique_ptr<CreateIsolatedWorldCallback> callback) {
  LocalFrame* frame =
      IdentifiersFactory::FrameById(inspected_frames_, frame_id);
  if (!frame) {
    callback->sendFailure(
        protocol::Response::InvalidParams("No frame for given id found"));
    return;
  }
  if (frame->IsProvisional()) {
    // If we're not enabled, we won't have DidClearWindowObject, so the below
    // won't work!
    if (!enabled_.Get()) {
      callback->sendFailure(
          protocol::Response::ServerError("Agent needs to be enabled first"));
      return;
    }
    pending_isolated_worlds_.insert(frame, Vector<IsolatedWorldRequest>())
        .stored_value->value.push_back(IsolatedWorldRequest(
            world_name.value_or(""), grant_universal_access.value_or(false),
            std::move(callback)));
    return;
  }
  CreateIsolatedWorldImpl(*frame, world_name.value_or(""),
                          grant_universal_access.value_or(false),
                          std::move(callback));
}

void InspectorPageAgent::CreateIsolatedWorldImpl(
    LocalFrame& frame,
    String world_name,
    bool grant_universal_access,
    std::unique_ptr<CreateIsolatedWorldCallback> callback) {
  DCHECK(!frame.IsProvisional());
  DOMWrapperWorld* world =
      EnsureDOMWrapperWorld(&frame, world_name, grant_universal_access);
  if (!world) {
    callback->sendFailure(
        protocol::Response::ServerError("Could not create isolated world"));
    return;
  }

  LocalWindowProxy* isolated_world_window_proxy =
      frame.DomWindow()->GetScriptController().WindowProxy(*world);
  v8::HandleScope handle_scope(frame.DomWindow()->GetIsolate());

  callback->sendSuccess(v8_inspector::V8ContextInfo::executionContextId(
      isolated_world_window_proxy->ContextIfInitialized()));
}

protocol::Response InspectorPageAgent::setFontFamilies(
    GenericFontFamilySettings& family_settings,
    const protocol::Array<protocol::Page::ScriptFontFamilies>&
        script_font_families) {
  for (const auto& entry : script_font_families) {
    UScriptCode script = ScriptNameToCode(entry->getScript());
    if (script == USCRIPT_INVALID_CODE) {
      return protocol::Response::InvalidParams("Invalid script name: " +
                                               entry->getScript().Utf8());
    }
    auto* font_families = entry->getFontFamilies();
    if (font_families->hasStandard()) {
      family_settings.UpdateStandard(
          AtomicString(font_families->getStandard(String())), script);
    }
    if (font_families->hasFixed()) {
      family_settings.UpdateFixed(
          AtomicString(font_families->getFixed(String())), script);
    }
    if (font_families->hasSerif()) {
      family_settings.UpdateSerif(
          AtomicString(font_families->getSerif(String())), script);
    }
    if (font_families->hasSansSerif()) {
      family_settings.UpdateSansSerif(
          AtomicString(font_families->getSansSerif(String())), script);
    }
    if (font_families->hasCursive()) {
      family_settings.UpdateCursive(
          AtomicString(font_families->getCursive(String())), script);
    }
    if (font_families->hasFantasy()) {
      family_settings.UpdateFantasy(
          AtomicString(font_families->getFantasy(String())), script);
    }
    if (font_families->hasMath()) {
      family_settings.UpdateMath(AtomicString(font_families->getMath(String())),
                                 script);
    }
  }
  return protocol::Response::Success();
}

protocol::Response InspectorPageAgent::setFontFamilies(
    std::unique_ptr<protocol::Page::FontFamilies> font_families,
    Maybe<protocol::Array<protocol::Page::ScriptFontFamilies>> for_scripts) {
  LocalFrame* frame = inspected_frames_->Root();
  auto* settings = frame->GetSettings();
  if (!settings) {
    return protocol::Response::ServerError("No settings");
  }

  if (!script_font_families_cbor_.Get().empty()) {
    return protocol::Response::ServerError(
        "Font families can only be set once");
  }

  if (!for_scripts) {
    for_scripts =
        std::make_unique<protocol::Array<protocol::Page::ScriptFontFamilies>>();
  }
  auto& script_fonts = *for_scripts;
  script_fonts.push_back(protocol::Page::ScriptFontFamilies::create()
                             .setScript(blink::web_pref::kCommonScript)
                             .setFontFamilies(std::move(font_families))
                             .build());

  auto response =
      setFontFamilies(settings->GetGenericFontFamilySettings(), script_fonts);
  if (response.IsError())
    return response;
  std::vector<uint8_t> serialized;
  crdtp::ProtocolTypeTraits<protocol::Array<
      protocol::Page::ScriptFontFamilies>>::Serialize(script_fonts,
                                                      &serialized);
  script_font_families_cbor_.Set(serialized);
  settings->NotifyGenericFontFamilyChange();
  return protocol::Response::Success();
}

protocol::Response InspectorPageAgent::setFontSizes(
    std::unique_ptr<protocol::Page::FontSizes> font_sizes) {
  LocalFrame* frame = inspected_frames_->Root();
  auto* settings = frame->GetSettings();
  if (settings) {
    if (font_sizes->hasStandard()) {
      standard_font_size_.Set(font_sizes->getStandard(0));
      settings->SetDefaultFontSize(standard_font_size_.Get());
    }
    if (font_sizes->hasFixed()) {
      fixed_font_size_.Set(font_sizes->getFixed(0));
      settings->SetDefaultFixedFontSize(fixed_font_size_.Get());
    }
  }

  return protocol::Response::Success();
}

void InspectorPageAgent::ApplyCompilationModeOverride(
    const ClassicScript& classic_script,
    v8::ScriptCompiler::CachedData** cached_data,
    v8::ScriptCompiler::CompileOptions* compile_options) {
  if (classic_script.SourceLocationType() !=
      ScriptSourceLocationType::kExternalFile)
    return;
  if (classic_script.SourceUrl().IsEmpty())
    return;
  auto it = compilation_cache_.find(classic_script.SourceUrl().GetString());
  if (it == compilation_cache_.end()) {
    auto requested = requested_compilation_cache_.find(
        classic_script.SourceUrl().GetString());
    if (requested != requested_compilation_cache_.end() && requested->value)
      *compile_options = v8::ScriptCompiler::kEagerCompile;
    return;
  }
  const protocol::Binary& data = it->value;
  *cached_data = new v8::ScriptCompiler::CachedData(
      data.data(), base::checked_cast<int>(data.size()),
      v8::ScriptCompiler::CachedData::BufferNotOwned);
}

void InspectorPageAgent::DidProduceCompilationCache(
    const ClassicScript& classic_script,
    v8::Local<v8::Script> script) {
  KURL url = classic_script.SourceUrl();
  if (url.IsEmpty())
    return;
  String url_string = url.GetString();
  auto requested = requested_compilation_cache_.find(url_string);
  if (requested == requested_compilation_cache_.end())
    return;
  requested_compilation_cache_.erase(requested);
  if (classic_script.SourceLocationType() !=
      ScriptSourceLocationType::kExternalFile)
    return;
  // TODO(caseq): should we rather issue updates if compiled code differs?
  if (compilation_cache_.Contains(url_string))
    return;
  static const int kMinimalCodeLength = 1024;
  if (classic_script.SourceText().length() < kMinimalCodeLength)
    return;
  std::unique_ptr<v8::ScriptCompiler::CachedData> cached_data(
      v8::ScriptCompiler::CreateCodeCache(script->GetUnboundScript()));
  if (cached_data) {
    CHECK_EQ(cached_data->buffer_policy,
             v8::ScriptCompiler::CachedData::BufferOwned);
    auto data = protocol::Binary::fromCachedData(std::move(cached_data));
    // This also prevents the notification from being re-issued.
    compilation_cache_.Set(url_string, data);
    // CachedData produced by CreateCodeCache always owns its buffer.
    GetFrontend()->compilationCacheProduced(url_string, data);
  }
}

void InspectorPageAgent::FileChooserOpened(LocalFrame* frame,
                                           HTMLInputElement* element,
                                           bool multiple,
                                           bool* intercepted) {
  *intercepted |= intercept_file_chooser_.Get();
  if (!intercept_file_chooser_.Get())
    return;
  GetFrontend()->fileChooserOpened(
      IdentifiersFactory::FrameId(frame),
      multiple ? protocol::Page::FileChooserOpened::ModeEnum::SelectMultiple
               : protocol::Page::FileChooserOpened::ModeEnum::SelectSingle,
      element ? Maybe<int>(element->GetDomNodeId()) : Maybe<int>());
}

protocol::Response InspectorPageAgent::produceCompilationCache(
    std::unique_ptr<protocol::Array<protocol::Page::CompilationCacheParams>>
        scripts) {
  if (!enabled_.Get())
    return protocol::Response::ServerError("Agent needs to be enabled first");
  for (const auto& script : *scripts) {
    requested_compilation_cache_.Set(script->getUrl(), script->getEager(false));
  }
  return protocol::Response::Success();
}

protocol::Response InspectorPageAgent::addCompilationCache(
    const String& url,
    const protocol::Binary& data) {
  // TODO(caseq): this is temporary undocumented behavior, remove after m91.
  if (!data.size()) {
    requested_compilation_cache_.Set(url, true);
  } else {
    compilation_cache_.Set(url, data);
  }
  return protocol::Response::Success();
}

protocol::Response InspectorPageAgent::clearCompilationCache() {
  compilation_cache_.clear();
  return protocol::Response::Success();
}

protocol::Response InspectorPageAgent::waitForDebugger() {
  client_->WaitForDebugger();
  return protocol::Response::Success();
}

protocol::Response InspectorPageAgent::setInterceptFileChooserDialog(
    bool enabled) {
  intercept_file_chooser_.Set(enabled);
  return protocol::Response::Success();
}

protocol::Response InspectorPageAgent::generateTestReport(const String& message,
                                                          Maybe<String> group) {
  LocalDOMWindow* window = inspected_frames_->Root()->DomWindow();

  // Construct the test report.
  TestReportBody* body = MakeGarbageCollected<TestReportBody>(message);
  Report* report = MakeGarbageCollected<Report>(
      "test", window->document()->Url().GetString(), body);

  // Send the test report to any ReportingObservers.
  ReportingContext::From(window)->QueueReport(report);

  return protocol::Response::Success();
}

void InspectorPageAgent::Trace(Visitor* visitor) const {
  visitor->Trace(inspected_frames_);
  visitor->Trace(pending_isolated_worlds_);
  visitor->Trace(inspector_resource_content_loader_);
  visitor->Trace(isolated_worlds_);
  InspectorBaseAgent::Trace(visitor);
}

void InspectorPageAgent::Dispose() {
  InspectorBaseAgent::Dispose();
  v8_session_ = nullptr;
}

protocol::Response InspectorPageAgent::getOriginTrials(
    const String& frame_id,
    std::unique_ptr<protocol::Array<protocol::Page::OriginTrial>>*
        originTrials) {
  LocalFrame* frame =
      IdentifiersFactory::FrameById(inspected_frames_, frame_id);

  if (!frame)
    return protocol::Response::InvalidParams("Invalid frame id");

  *originTrials = CreateOriginTrials(frame->DomWindow());

  return protocol::Response::Success();
}

}  // namespace blink
```