Response:
The user wants to understand the functionality of the provided C++ code snippet from `script_loader.cc`. This is the second part of the file.

To achieve this, I need to:

1. **Summarize the overall purpose of this code block.**  It seems to handle the preparation and loading of `<script>` elements.
2. **Identify its relationship to web technologies (JavaScript, HTML, CSS).** The code directly deals with how scripts are fetched, parsed, and executed based on attributes of the `<script>` tag.
3. **Analyze the conditional logic and provide examples of input and output.**  Focus on the `if` and `switch` statements that determine different behaviors based on script attributes like `src`, `type`, `async`, `defer`.
4. **Point out potential user/programming errors.**  Consider cases where incorrect attributes or values are used in the `<script>` tag.
5. **Explain how a user's actions might lead to this code being executed.**  Think about the browser's process of parsing HTML and encountering `<script>` tags.
6. **Synthesize a concise summary of the code's function.** Combine the key aspects identified in the previous steps.
好的，这是 `blink/renderer/core/script/script_loader.cc` 文件的第二部分代码，其主要功能是继续处理 `<script>` 元素的加载和执行准备工作。以下对其功能进行归纳：

**主要功能归纳：**

这段代码主要负责处理 `<script>` 元素的以下几个方面：

1. **处理外部脚本 (带有 `src` 属性的 `<script>`)：**
   - 检查 `type` 属性，如果为 `importmap` 则触发错误事件。
   - 获取 `src` 属性的值，并进行空格去除等处理。
   - 如果 `src` 为空，则触发错误事件。
   - 将脚本标记为来自外部文件。
   - 解析 `src` 属性生成 URL，如果解析失败则触发错误事件。
   - 处理 `attributionsrc` 属性相关的逻辑。
   - 如果脚本可能阻塞渲染，则将其添加到渲染阻塞资源管理器。
   - 根据 `type` 属性分别处理：
     - **`classic`**: 获取字符编码，调用 `ClassicPendingScript::Fetch` 发起脚本的下载请求。根据 `async` 和 `defer` 属性以及是否为 parser 插入来决定加载优先级。
     - **`module`**: 调用 `Modulator::FetchModuleScriptTree` 发起模块脚本及其依赖的下载请求。处理 `integrity` 属性。
     - **`speculationrules` 和 `webbundle`**:  目前不支持外部链接，会添加控制台错误消息并触发错误事件。

2. **处理内联脚本 (不带有 `src` 属性的 `<script>`)：**
   - 获取文档的基础 URL。
   - 根据 `type` 属性分别处理：
     - **`importmap`**:  创建 `PendingImportMap` 对象，解析并注册 import map。会检查是否支持多个 import map。
     - **`webbundle`**: 创建或重用 `ScriptWebBundle` 对象，处理内联 webbundle 的解析，如果解析出错会触发错误事件或报告异常。
     - **`speculationrules`**:  创建 `SpeculationRuleSet::Source` 对象并解析推测规则，添加到文档的推测规则列表中。
     - **`classic`**: 创建 `ClassicPendingScript` 对象，标记为内联脚本。
     - **`module`**: 创建 `ModuleScript` 对象，并调用 `Modulator::FetchDescendantsForInlineScript` 处理模块依赖的下载。

3. **确定脚本的调度类型 (ScriptSchedulingType)：**
   - 根据 `<script>` 标签的属性（如 `async`, `defer`）、是否为 parser 插入、脚本类型等因素，决定脚本的执行时机。可能的类型包括：`kAsync` (异步)、`kInOrder` (按顺序)、`kDefer` (延迟)、`kParserBlocking` (阻塞解析器)、`kParserBlockingInline` (阻塞解析器的内联脚本)、`kImmediate` (立即执行)。
   - 实现了针对 `SelectiveInOrderScript` 和 `ForceInOrderScript` 的干预逻辑，根据特定条件调整脚本的调度类型，以保证某些脚本的执行顺序。
   - 如果存在尚未执行的 `ForceInOrder` 脚本，并且当前处理的是内联脚本，则可能将其标记为 `kParserBlockingInline` 以推迟执行。

4. **将准备好的脚本添加到执行队列：**
   - 根据确定的调度类型，将 `PendingScript` 对象添加到相应的执行队列中，由 `ScriptRunner` 负责后续的执行。
   - 对于 `kAsync` 和 `kInOrder` 类型的外部脚本，在加载完成后会释放对 `Resource` 对象的引用（除非是 Signed Exchange）。
   - 对于内联脚本，如果是立即执行 (`kImmediate`)，则直接调用 `ExecuteScriptBlock()` 执行。

5. **处理 `event` 和 `for` 属性：**
   - `IsScriptForEventSupported()` 函数用于检查是否支持 `<script>` 标签的 `event` 和 `for` 属性（仅限 `type="classic"`）。

6. **获取脚本文本内容：**
   - `GetScriptText()` 函数用于获取 `<script>` 标签的文本内容，会考虑 Trusted Types 的影响。

7. **添加和移除推测规则集：**
   - `AddSpeculationRuleSet()` 用于解析并添加内联的推测规则。
   - `RemoveSpeculationRuleSet()` 用于移除不再适用的推测规则。

**与 JavaScript、HTML、CSS 的关系及举例说明：**

* **JavaScript:**  这段代码的核心功能是加载和准备 JavaScript 代码的执行。
    * **举例：** 当 HTML 中遇到 `<script src="my_script.js"></script>` 时，这段代码会解析 `src` 属性，发起网络请求下载 `my_script.js` 文件，并根据其他属性决定何时执行该脚本。
    * **举例：** 当遇到 `<script type="module"> import ... </script>` 时，代码会识别为模块脚本，并处理模块的依赖关系。
* **HTML:**  这段代码是 HTML 解析和渲染流程中的一部分，负责处理 HTML 中的 `<script>` 标签。
    * **举例：** HTML 解析器在解析 HTML 文档时遇到 `<script>` 标签，会调用 `ScriptLoader` 来处理该标签。
    * **举例：** `<script async src="analytics.js"></script>` 中的 `async` 属性会影响 `ScriptLoader` 决定脚本的调度类型。
* **CSS:**  CSS 的加载可能会影响 JavaScript 的执行，特别是内联脚本。
    * **举例：** 如果 HTML 解析器遇到一个内联脚本 `<script> ... </script>`，并且文档中存在阻塞脚本的 CSS 样式表，那么该内联脚本可能会被标记为 `kParserBlockingInline`，需要等待 CSSOM 构建完成后才能执行。

**逻辑推理的假设输入与输出：**

假设输入为一个 HTML 文档片段：

```html
<script src="external.js"></script>
<script>console.log("inline script");</script>
<script async src="async.js"></script>
<script defer src="defer.js"></script>
<script type="module" src="module.js"></script>
```

对于上述每个 `<script>` 标签，`ScriptLoader` 的处理流程（简化）：

* **`<script src="external.js"></script>`:**
    * `GetScriptType()` 返回 `kClassic`。
    * `element_->HasSourceAttribute()` 为 true。
    * `ScriptSchedulingTypePerSpec` 根据是否为 parser 插入等因素，可能返回 `kParserBlocking` 或 `kInOrder`。
    * 输出：发起对 `external.js` 的网络请求，并将 `PendingScript` 对象添加到相应的执行队列。

* **`<script>console.log("inline script");</script>`:**
    * `GetScriptType()` 返回 `kClassic`。
    * `element_->HasSourceAttribute()` 为 false。
    * `ScriptSchedulingTypePerSpec` 根据是否存在阻塞脚本的 CSS 样式表，可能返回 `kImmediate` 或 `kParserBlockingInline`。
    * 输出：如果为 `kImmediate`，则立即执行 `console.log("inline script");`，否则将 `PendingScript` 对象添加到相应的执行队列。

* **`<script async src="async.js"></script>`:**
    * `GetScriptType()` 返回 `kClassic`。
    * `element_->AsyncAttributeValue()` 为 true。
    * `ScriptSchedulingTypePerSpec` 返回 `kAsync`。
    * 输出：发起对 `async.js` 的网络请求，并将 `PendingScript` 对象添加到异步执行队列。

* **`<script defer src="defer.js"></script>`:**
    * `GetScriptType()` 返回 `kClassic`。
    * `element_->DeferAttributeValue()` 为 true。
    * `ScriptSchedulingTypePerSpec` 返回 `kDefer`。
    * 输出：发起对 `defer.js` 的网络请求，并将 `PendingScript` 对象添加到延迟执行队列。

* **`<script type="module" src="module.js"></script>`:**
    * `GetScriptType()` 返回 `kModule`。
    * `ScriptSchedulingTypePerSpec` 返回 `kDefer` (默认) 或 `kAsync` (如果带有 `async` 属性)。
    * 输出：发起对 `module.js` 及其依赖模块的网络请求。

**用户或编程常见的使用错误举例：**

* **错误的 `type` 属性值：** 例如 `<script type="text/vbscript">`，`ScriptLoader` 可能无法识别，导致脚本不执行或报错。
* **外部脚本 `src` 路径错误：** 例如 `<script src="not_exist.js"></script>`，会导致网络请求失败，触发错误事件。
* **内联 `importmap` 语法错误：**  会导致 `PendingImportMap::CreateInline` 解析失败，触发错误事件。
* **在不支持的环境中使用 `type="module"`：**  旧版本的浏览器可能不支持模块脚本。
* **混用 `async` 和 `defer` 属性：**  虽然浏览器会定义行为，但可能导致开发者困惑。

**用户操作如何一步步到达这里 (调试线索)：**

1. **用户在浏览器中输入网址或点击链接。**
2. **浏览器开始请求并下载 HTML 文档。**
3. **HTML 解析器开始解析下载的 HTML 文档。**
4. **当解析器遇到 `<script>` 标签时，会创建对应的 DOM 元素。**
5. **Blink 引擎会创建 `ScriptLoader` 对象来处理这个 `<script>` 元素。**
6. **`PrepareScript()` 函数会被调用，并最终执行到这段代码，根据 `<script>` 标签的属性和文档状态，决定如何加载和准备执行脚本。**

通过在 `ScriptLoader` 的相关函数中设置断点，例如 `PrepareScript()`, `Fetch()`, `FetchModuleScriptTree()`, `ExecuteScriptBlock()` 等，可以观察脚本的加载和执行流程。 检查 `<script>` 元素的属性值、文档状态以及网络请求情况可以帮助定位问题。

总而言之，这段代码是 Chromium Blink 引擎中处理 `<script>` 标签的核心部分，它根据 HTML 规范和各种优化策略，负责安全有效地加载和准备执行 JavaScript 代码，是连接 HTML 结构和 JavaScript 逻辑的关键桥梁。

### 提示词
```
这是目录为blink/renderer/core/script/script_loader.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
ype is "importmap", then queue an element task
    // on the DOM manipulation task source given el to fire an event named error
    // at el, and return.
    if (GetScriptType() == ScriptTypeAtPrepare::kImportMap) {
      element_document.GetTaskRunner(TaskType::kDOMManipulation)
          ->PostTask(FROM_HERE,
                     WTF::BindOnce(&ScriptElementBase::DispatchErrorEvent,
                                   WrapPersistent(element_.Get())));
      return nullptr;
    }
    // <spec step="31.2">Let src be the value of el's src attribute.</spec>
    String src =
        StripLeadingAndTrailingHTMLSpaces(element_->SourceAttributeValue());

    // <spec step="31.3">If src is the empty string, then queue a task to fire
    // an event named error at el, and return.</spec>
    if (src.empty()) {
      element_document.GetTaskRunner(TaskType::kDOMManipulation)
          ->PostTask(FROM_HERE,
                     WTF::BindOnce(&ScriptElementBase::DispatchErrorEvent,
                                   WrapPersistent(element_.Get())));
      return nullptr;
    }

    // <spec step="31.4">Set el's from an external file to true.</spec>
    is_external_script_ = true;

    // <spec step="31.5">Let url be the result of encoding-parsing a URL given
    // src, relative to el's node document.</spec>
    KURL url = element_document.CompleteURL(src);

    // <spec step="31.6">If url is failure, then queue an element task on the
    // DOM manipulation task source given el to fire an event named error at el,
    // and return.</spec>
    if (!url.IsValid()) {
      element_document.GetTaskRunner(TaskType::kDOMManipulation)
          ->PostTask(FROM_HERE,
                     WTF::BindOnce(&ScriptElementBase::DispatchErrorEvent,
                                   WrapPersistent(element_.Get())));
      return nullptr;
    }

    // TODO(apaseltiner): Propagate the element instead of passing nullptr.
    if (element_->HasAttributionsrcAttribute() &&
        context_window->GetFrame()->GetAttributionSrcLoader()->CanRegister(
            url,
            /*element=*/nullptr,
            /*request_id=*/std::nullopt)) {
      options.SetAttributionReportingEligibility(
          ScriptFetchOptions::AttributionReportingEligibility::kEligible);
    }

    // <spec step="31.7">If el is potentially render-blocking, then block
    // rendering on el.</spec>
    if (potentially_render_blocking &&
        element_document.GetRenderBlockingResourceManager()) {
      element_document.GetRenderBlockingResourceManager()->AddPendingScript(
          *element_);
    }

    // <spec step="31.8">Set el's delaying the load event to true.</spec>
    //
    // <spec step="32.2.B.1">Set el's delaying the load event to true.</spec>
    //
    // When controlled by ScriptRunner, implemented by
    // ScriptRunner::QueueScriptForExecution(). Otherwise (controlled by a
    // parser), then the parser evaluates the script (e.g. parser-blocking,
    // defer, etc.) before DOMContentLoaded, and thus explicit logic for this is
    // not needed.

    // <spec step="31.11">Switch on el's type:</spec>
    switch (GetScriptType()) {
      case ScriptTypeAtPrepare::kInvalid:
      case ScriptTypeAtPrepare::kImportMap:
        NOTREACHED();

      case ScriptTypeAtPrepare::kSpeculationRules:
        // TODO(crbug.com/1182803): Implement external speculation rules.
        element_document.AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
            mojom::blink::ConsoleMessageSource::kJavaScript,
            mojom::blink::ConsoleMessageLevel::kError,
            "External speculation rules are not yet supported."));
        return nullptr;

      case ScriptTypeAtPrepare::kWebBundle:
        element_document.AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
            mojom::blink::ConsoleMessageSource::kJavaScript,
            mojom::blink::ConsoleMessageLevel::kError,
            "External webbundle is not yet supported."));
        element_document.GetTaskRunner(TaskType::kDOMManipulation)
            ->PostTask(FROM_HERE,
                       WTF::BindOnce(&ScriptElementBase::DispatchErrorEvent,
                                     WrapPersistent(element_.Get())));
        return nullptr;

      case ScriptTypeAtPrepare::kClassic: {
        // - "classic":

        // <spec step="20">If el has a charset attribute, then let encoding be
        // the result of getting an encoding from the value of the charset
        // attribute. If el does not have a charset attribute, or if getting an
        // encoding failed, then let encoding be el's node document's the
        // encoding.</spec>
        //
        // TODO(hiroshige): Should we handle failure in getting an encoding?
        WTF::TextEncoding encoding;
        if (!element_->CharsetAttributeValue().empty()) {
          encoding = WTF::TextEncoding(element_->CharsetAttributeValue());
        } else {
          encoding = element_document.Encoding();
        }

        // <spec step="31.11.A">"classic"
        //
        // Fetch a classic script given url, settings object, options, classic
        // script CORS setting, and encoding.</spec>
        FetchParameters::DeferOption defer = FetchParameters::kNoDefer;
        if (!parser_inserted_ || element_->AsyncAttributeValue() ||
            element_->DeferAttributeValue()) {
          if (!IsEligibleForLowPriorityScriptLoading(element_document,
                                                     *element_, url)) {
            defer = FetchParameters::kLazyLoad;
          } else {
            defer = FetchParameters::kIdleLoad;
          }
        }
        ClassicPendingScript* pending_script = ClassicPendingScript::Fetch(
            url, element_document, options, cross_origin, encoding, element_,
            defer, GetRunningTask(script_state));
        prepared_pending_script_ = pending_script;
        Resource* resource = pending_script->GetResource();
        resource_keep_alive_ = resource;
        is_eligible_for_delay =
            IsEligibleForDelay(*resource, element_document, *element_);
        is_eligible_for_selective_in_order =
            IsEligibleForSelectiveInOrder(*resource, element_document);
        break;
      }
      case ScriptTypeAtPrepare::kModule: {
        // - "module":

        // Step 15 is skipped because they are not used in module
        // scripts.

        // <spec step="31.11.B">"module"
        //
        // Fetch an external module script graph given url, settings object, and
        // options.</spec>
        Modulator* modulator = Modulator::From(script_state);
        if (integrity_attr.IsNull()) {
          // <spec step="31.11.B">If el does not have an integrity attribute,
          // then set options's integrity metadata to the result of resolving a
          // module integrity metadata with url and settings object </spec>
          options.SetIntegrityMetadata(modulator->GetIntegrityMetadata(url));
          options.SetIntegrityAttributeValue(
              modulator->GetIntegrityMetadataString(url));
        }
        FetchModuleScriptTree(url, fetch_client_settings_object_fetcher,
                              modulator, options);
      } break;
    }
  }

  // <spec step="32">If el does not have a src content attribute:</spec>
  if (!element_->HasSourceAttribute()) {
    // <spec step="32.1">Let base URL be el's node document's document base
    // URL.</spec>
    KURL base_url = element_document.BaseURL();

    // Don't report source_url to DevTools for dynamically created module or
    // classic scripts.
    // If we report a source_url here, the dynamic script would look like
    // an inline script of the current document to DevTools, which leads to
    // a confusing debugging experience. The dynamic scripts' source is not
    // present in the document, so stepping in the document as we would for
    // an inline script doesn't make any sense.
    KURL source_url = (!is_in_document_write && parser_inserted_)
                          ? element_document.Url()
                          : KURL();

    // <spec step="32.2">Switch on el's type:</spec>

    switch (GetScriptType()) {
      case ScriptTypeAtPrepare::kInvalid:
        NOTREACHED();

      // <spec step="32.2.C">"importmap"</spec>
      case ScriptTypeAtPrepare::kImportMap: {
        if (!RuntimeEnabledFeatures::MultipleImportMapsEnabled()) {
          // TODO(crbug.com/365578430): Remove this logic once the
          // MultipleImportMaps flag is removed.
          //
          // <spec step="32.2.C.1">If el's relevant global object's import maps
          // allowed is false, then queue an element task on the DOM
          // manipulation task source given el to fire an event named error at
          // el, and return.</spec>
          Modulator* modulator = Modulator::From(script_state);
          auto acquiring_state = modulator->GetAcquiringImportMapsState();
          switch (acquiring_state) {
            case Modulator::AcquiringImportMapsState::kAfterModuleScriptLoad:
            case Modulator::AcquiringImportMapsState::kMultipleImportMaps:
              element_document.AddConsoleMessage(MakeGarbageCollected<
                                                 ConsoleMessage>(
                  mojom::blink::ConsoleMessageSource::kJavaScript,
                  mojom::blink::ConsoleMessageLevel::kError,
                  acquiring_state == Modulator::AcquiringImportMapsState::
                                         kAfterModuleScriptLoad
                      ? "An import map is added after module script load was "
                        "triggered."
                      : "Multiple import maps are not yet supported. "
                        "https://crbug.com/927119"));
              element_document.GetTaskRunner(TaskType::kDOMManipulation)
                  ->PostTask(
                      FROM_HERE,
                      WTF::BindOnce(&ScriptElementBase::DispatchErrorEvent,
                                    WrapPersistent(element_.Get())));
              return nullptr;

            case Modulator::AcquiringImportMapsState::kAcquiring:
              modulator->SetAcquiringImportMapsState(
                  Modulator::AcquiringImportMapsState::kMultipleImportMaps);

              break;
          }
        }
        UseCounter::Count(*context_window, WebFeature::kImportMap);

        // <spec step="32.2.C.3">Let result be the result of creating an import
        // map parse result given source text and base URL.</spec>
        PendingImportMap* pending_import_map =
            PendingImportMap::CreateInline(*element_, source_text, base_url);

        // Because we currently support inline import maps only, the pending
        // import map is ready immediately and thus we call `register an import
        // map` synchronously here.
        //
        // https://html.spec.whatwg.org/C#execute-the-script-element step 6.C
        pending_import_map->RegisterImportMap();

        return nullptr;
      }
      case ScriptTypeAtPrepare::kWebBundle: {
        DCHECK(!script_web_bundle_);

        absl::variant<ScriptWebBundle*, ScriptWebBundleError>
            script_web_bundle_or_error =
                ScriptWebBundle::CreateOrReuseInline(*element_, source_text);
        if (absl::holds_alternative<ScriptWebBundle*>(
                script_web_bundle_or_error)) {
          script_web_bundle_ =
              absl::get<ScriptWebBundle*>(script_web_bundle_or_error);
          DCHECK(script_web_bundle_);
        }
        if (absl::holds_alternative<ScriptWebBundleError>(
                script_web_bundle_or_error)) {
          ScriptWebBundleError error =
              absl::get<ScriptWebBundleError>(script_web_bundle_or_error);
          // Errors with type kSystemError should fire an error event silently
          // for the user, while the other error types should report an
          // exception.
          if (error.GetType() == ScriptWebBundleError::Type::kSystemError) {
            element_->DispatchErrorEvent();
          } else {
            if (script_state->ContextIsValid()) {
              ScriptState::Scope scope(script_state);
              V8ScriptRunner::ReportException(script_state->GetIsolate(),
                                              error.ToV8(script_state));
            }
          }
        }
        return nullptr;
      }

      case ScriptTypeAtPrepare::kSpeculationRules: {
        auto* source = SpeculationRuleSet::Source::FromInlineScript(
            source_text, element_document, element_->GetDOMNodeId());
        AddSpeculationRuleSet(source);
        return nullptr;
      }

        // <spec step="30.2.A">"classic"</spec>
      case ScriptTypeAtPrepare::kClassic: {
        // <spec step="30.2.A.1">Let script be the result of creating a classic
        // script using source text, settings object, base URL, and
        // options.</spec>

        ScriptSourceLocationType script_location_type =
            ScriptSourceLocationType::kInline;
        if (!parser_inserted_) {
          script_location_type =
              ScriptSourceLocationType::kInlineInsideGeneratedElement;
        } else if (is_in_document_write) {
          script_location_type =
              ScriptSourceLocationType::kInlineInsideDocumentWrite;
        }

        prepared_pending_script_ = ClassicPendingScript::CreateInline(
            element_, position, source_url, base_url, source_text,
            script_location_type, options, GetRunningTask(script_state));

        // <spec step="30.2.A.2">Mark as ready el given script.</spec>
        //
        // Implemented by ClassicPendingScript.
        break;
      }

        // <spec step="30.2.B">"module"</spec>
      case ScriptTypeAtPrepare::kModule: {
        // <spec step="30.2.B.2">Fetch an inline module script graph, given
        // source text, base URL, settings object, and options. When this
        // asynchronously completes with result, mark as ready el given
        // result.</spec>
        //
        // <specdef label="fetch-an-inline-module-script-graph"
        // href="https://html.spec.whatwg.org/C/#fetch-an-inline-module-script-graph">

        // Strip any fragment identifiers from the source URL reported to
        // DevTools, so that breakpoints hit reliably for inline module
        // scripts, see crbug.com/1338257 for more details.
        if (source_url.HasFragmentIdentifier()) {
          source_url.RemoveFragmentIdentifier();
        }
        Modulator* modulator = Modulator::From(script_state);

        // <spec label="fetch-an-inline-module-script-graph" step="2">Let script
        // be the result of creating a JavaScript module script using source
        // text, settings object, base URL, and options.</spec>
        ModuleScriptCreationParams params(
            source_url, base_url, ScriptSourceLocationType::kInline,
            ModuleType::kJavaScript, ParkableString(source_text.Impl()),
            nullptr, network::mojom::ReferrerPolicy::kDefault);
        ModuleScript* module_script =
            JSModuleScript::Create(params, modulator, options, position);

        // TODO(crbug.com/364904756) - This spec step no longer exists.
        // <spec label="fetch-an-inline-module-script-graph" step="?">If script
        // is null, asynchronously complete this algorithm with null, and
        // return.</spec>
        if (!module_script) {
          return nullptr;
        }

        if (RuntimeEnabledFeatures::RenderBlockingInlineModuleScriptEnabled() &&
            potentially_render_blocking &&
            element_document.GetRenderBlockingResourceManager()) {
          // TODO(crbug.com/364904756) - This spec step does not exist. The PR
          // below has landed, but doesn't contain it. After
          // https://github.com/whatwg/html/pull/10035: <spec
          // label="fetch-an-inline-module-script-graph" step="?">If el is
          // potentially render-blocking, then block rendering on el and set
          // options's  render-blocking  to true.</spec>
          element_document.GetRenderBlockingResourceManager()->AddPendingScript(
              *element_);
        }

        // <spec label="fetch-an-inline-module-script-graph" step="3">Fetch the
        // descendants of and link script, given settings object, the
        // destination "script", and visited set. When this asynchronously
        // completes with final result, asynchronously complete this algorithm
        // with final result.</spec>
        auto* module_tree_client =
            MakeGarbageCollected<ModulePendingScriptTreeClient>();
        modulator->FetchDescendantsForInlineScript(
            module_script, fetch_client_settings_object_fetcher,
            mojom::blink::RequestContextType::SCRIPT,
            network::mojom::RequestDestination::kScript, module_tree_client);
        prepared_pending_script_ = MakeGarbageCollected<ModulePendingScript>(
            element_, module_tree_client, is_external_script_,
            GetRunningTask(script_state));
        break;
      }
    }
  }

  prepared_pending_script_->SetParserInserted(parser_inserted_);
  prepared_pending_script_->SetIsInDocumentWrite(is_in_document_write);

  ScriptSchedulingType script_scheduling_type = GetScriptSchedulingTypePerSpec(
      element_document, parser_blocking_inline_option);

  // [Intervention, SelectiveInOrderScript, crbug.com/1356396]
  // Check for external script that
  // should be in-order. This simply marks the parser blocking scripts as
  // kInOrder if it's eligible. We use ScriptSchedulingType::kInOrder
  // rather than kForceInOrder here since we don't preserve evaluation order
  // between intervened scripts and ordinary parser-blocking/inline scripts.
  if (is_eligible_for_selective_in_order) {
    switch (script_scheduling_type) {
      case ScriptSchedulingType::kParserBlocking:
        UseCounter::Count(context_window->document()->TopDocument(),
                          WebFeature::kSelectiveInOrderScript);
        if (base::FeatureList::IsEnabled(features::kSelectiveInOrderScript)) {
          script_scheduling_type = ScriptSchedulingType::kInOrder;
        }
        break;
      default:
        break;
    }
  }

  // [Intervention, ForceInOrderScript, crbug.com/1344772]
  // Check for external script that
  // should be force in-order. Not only the pending scripts that would be marked
  // (without the intervention) as ScriptSchedulingType::kParserBlocking or
  // kInOrder, but also the scripts that would be marked as kAsync are put into
  // the force in-order queue in ScriptRunner because we have to guarantee the
  // execution order of the scripts.
  if (IsEligibleForForceInOrder(element_document)) {
    switch (script_scheduling_type) {
      case ScriptSchedulingType::kAsync:
      case ScriptSchedulingType::kInOrder:
      case ScriptSchedulingType::kParserBlocking:
        script_scheduling_type = ScriptSchedulingType::kForceInOrder;
        break;
      default:
        break;
    }
  }

  // [Intervention, ForceInOrderScript, crbug.com/1344772]
  // If ScriptRunner still has
  // ForceInOrder scripts not executed yet, attempt to mark the inline script as
  // parser blocking so that the inline script is evaluated after the
  // ForceInOrder scripts are evaluated.
  if (script_scheduling_type == ScriptSchedulingType::kImmediate &&
      parser_inserted_ &&
      parser_blocking_inline_option == ParserBlockingInlineOption::kAllow &&
      context_window->document()->GetScriptRunner()->HasForceInOrderScripts()) {
    DCHECK(base::FeatureList::IsEnabled(features::kForceInOrderScript));
    script_scheduling_type = ScriptSchedulingType::kParserBlockingInline;
  }

  // <spec step="31">If el's type is "classic" and el has a src attribute, or
  // el's type is "module":</spec>
  switch (script_scheduling_type) {
    case ScriptSchedulingType::kAsync:
      // <spec step="31.2.1">Let scripts be el's preparation-time document's set
      // of scripts that will execute as soon as possible.</spec>
      //
      // <spec step="31.2.2">Append el to scripts.</spec>
    case ScriptSchedulingType::kInOrder:
      // <spec step="31.3.1">Let scripts be el's preparation-time document's
      // list of scripts that will execute in order as soon as possible.</spec>
      //
      // <spec step="31.3.2">Append el to scripts.</spec>
    case ScriptSchedulingType::kForceInOrder:
      // [intervention, https://crbug.com/1344772] Append el to el's
      // preparation-time document's list of force-in-order scripts.

      {
        // [Intervention, DelayAsyncScriptExecution, crbug.com/1340837]
        // If the target is kCrossSiteWithAllowList or
        // kCrossSiteWithAllowListReportOnly, record the metrics and override
        // is_eligible_for_delay to be always false when
        // kCrossSiteWithAllowListReportOnly.
        if (is_eligible_for_delay &&
            script_scheduling_type == ScriptSchedulingType::kAsync) {
          const features::DelayAsyncScriptTarget delay_async_script_target =
              features::kDelayAsyncScriptTargetParam.Get();
          if (delay_async_script_target ==
              features::DelayAsyncScriptTarget::
                  kCrossSiteWithAllowListReportOnly) {
            is_eligible_for_delay = false;
          }
        }
        // TODO(hiroshige): Here the context document is used as "node document"
        // while Step 14 uses |elementDocument| as "node document". Fix this.
        ScriptRunner* script_runner =
            context_window->document()->GetScriptRunner();
        script_runner->QueueScriptForExecution(
            TakePendingScript(script_scheduling_type),
            DetermineDelayReasonsToWait(script_runner, is_eligible_for_delay));
        // The #mark-as-ready part is implemented in ScriptRunner.
      }

      // [no-spec] Do not keep alive ScriptResource controlled by ScriptRunner
      // after loaded.
      if (resource_keep_alive_) {
        resource_keep_alive_->AddFinishObserver(
            this, element_document.GetTaskRunner(TaskType::kNetworking).get());
      }

      return nullptr;

    case ScriptSchedulingType::kDefer:
    case ScriptSchedulingType::kParserBlocking:
    case ScriptSchedulingType::kParserBlockingInline:
      // The remaining part is implemented by the caller-side of
      // PrepareScript().
      DCHECK(parser_inserted_);
      if (script_scheduling_type ==
          ScriptSchedulingType::kParserBlockingInline) {
        DCHECK_EQ(parser_blocking_inline_option,
                  ParserBlockingInlineOption::kAllow);
      }

      return TakePendingScript(script_scheduling_type);

    case ScriptSchedulingType::kImmediate: {
      // <spec step="32.3">Otherwise, immediately execute the script element el,
      // even if other scripts are already executing.</spec>
      TakePendingScript(ScriptSchedulingType::kImmediate)->ExecuteScriptBlock();
      return nullptr;
    }

    case ScriptSchedulingType::kNotSet:
    case ScriptSchedulingType::kDeprecatedForceDefer:
      NOTREACHED();
  }
}

ScriptSchedulingType ScriptLoader::GetScriptSchedulingTypePerSpec(
    Document& element_document,
    ParserBlockingInlineOption parser_blocking_inline_option) const {
  DCHECK_NE(GetScriptType(), ScriptLoader::ScriptTypeAtPrepare::kImportMap);
  DCHECK(prepared_pending_script_);

  // <spec step="31">If el's type is "classic" and el has a src attribute, or
  // el's type is "module":</spec>
  if ((GetScriptType() == ScriptTypeAtPrepare::kClassic &&
       element_->HasSourceAttribute()) ||
      GetScriptType() == ScriptTypeAtPrepare::kModule) {
    // <spec step="31.2">If el has an async attribute or el's force async is
    // true:</spec>
    if (element_->AsyncAttributeValue() || force_async_) {
      return ScriptSchedulingType::kAsync;
    }

    // <spec step="31.3">Otherwise, if el is not parser-inserted:</spec>
    if (!parser_inserted_) {
      return ScriptSchedulingType::kInOrder;
    }

    // <spec step="31.4">Otherwise, if el has a defer attribute or el's type is
    // "module":</spec>
    if (element_->DeferAttributeValue() ||
        GetScriptType() == ScriptTypeAtPrepare::kModule) {
      return ScriptSchedulingType::kDefer;
    }

    // <spec step="31.5">Otherwise:</spec>
    return ScriptSchedulingType::kParserBlocking;
  } else {
    // <spec step="32">Otherwise:</spec>
    DCHECK_EQ(GetScriptType(), ScriptTypeAtPrepare::kClassic);
    DCHECK(!element_->HasSourceAttribute());
    DCHECK(!is_external_script_);

    // <spec step="32.2">If el is parser-inserted, and either the parser that
    // created el is an XML parser or it's an HTML parser whose script nesting
    // level is not greater than one, and el's parser document has a style sheet
    // that is blocking scripts:</spec>
    if (parser_inserted_ &&
        parser_blocking_inline_option == ParserBlockingInlineOption::kAllow &&
        !element_document.IsScriptExecutionReady()) {
      return ScriptSchedulingType::kParserBlockingInline;
    }

    // <spec step="32.3">Otherwise, immediately execute the script element el,
    // even if other scripts are already executing.</spec>
    return ScriptSchedulingType::kImmediate;
  }
}

void ScriptLoader::FetchModuleScriptTree(
    const KURL& url,
    ResourceFetcher* fetch_client_settings_object_fetcher,
    Modulator* modulator,
    const ScriptFetchOptions& options) {
  auto* module_tree_client =
      MakeGarbageCollected<ModulePendingScriptTreeClient>();
  modulator->FetchTree(url, ModuleType::kJavaScript,
                       fetch_client_settings_object_fetcher,
                       mojom::blink::RequestContextType::SCRIPT,
                       network::mojom::RequestDestination::kScript, options,
                       ModuleScriptCustomFetchType::kNone, module_tree_client);
  prepared_pending_script_ = MakeGarbageCollected<ModulePendingScript>(
      element_, module_tree_client, is_external_script_,
      GetRunningTask(modulator->GetScriptState()));
}

PendingScript* ScriptLoader::TakePendingScript(
    ScriptSchedulingType scheduling_type) {
  CHECK(prepared_pending_script_);

  // Record usage histograms per script tag.
  if (element_->GetDocument().Url().ProtocolIsInHTTPFamily()) {
    base::UmaHistogramEnumeration("Blink.Script.SchedulingType",
                                  scheduling_type);
  }

  // Record usage histograms per page.
  switch (scheduling_type) {
    case ScriptSchedulingType::kDefer:
      UseCounter::Count(element_->GetDocument(),
                        WebFeature::kScriptSchedulingType_Defer);
      break;
    case ScriptSchedulingType::kParserBlocking:
      UseCounter::Count(element_->GetDocument(),
                        WebFeature::kScriptSchedulingType_ParserBlocking);
      break;
    case ScriptSchedulingType::kParserBlockingInline:
      UseCounter::Count(element_->GetDocument(),
                        WebFeature::kScriptSchedulingType_ParserBlockingInline);
      break;
    case ScriptSchedulingType::kInOrder:
      UseCounter::Count(element_->GetDocument(),
                        WebFeature::kScriptSchedulingType_InOrder);
      break;
    case ScriptSchedulingType::kAsync:
      UseCounter::Count(element_->GetDocument(),
                        WebFeature::kScriptSchedulingType_Async);
      break;
    default:
      break;
  }

  PendingScript* pending_script = prepared_pending_script_;
  prepared_pending_script_ = nullptr;
  pending_script->SetSchedulingType(scheduling_type);
  return pending_script;
}

void ScriptLoader::NotifyFinished() {
  // Historically we clear |resource_keep_alive_| when the scheduling type is
  // kAsync or kInOrder (crbug.com/778799). But if the script resource was
  // served via signed exchange, the script may not be in the HTTPCache, and
  // therefore will need to be refetched over network if it's evicted from the
  // memory cache. So we keep |resource_keep_alive_| to keep the resource in the
  // memory cache.
  if (resource_keep_alive_ &&
      !resource_keep_alive_->GetResponse().IsSignedExchangeInnerResponse()) {
    resource_keep_alive_ = nullptr;
  }
}

// <specdef href="https://html.spec.whatwg.org/C/#prepare-the-script-element">
bool ScriptLoader::IsScriptForEventSupported() const {
  // <spec step="19.1">Let for be the value of el's' for attribute.</spec>
  String event_attribute = element_->EventAttributeValue();
  // <spec step="19.2">Let event be the value of el's event attribute.</spec>
  String for_attribute = element_->ForAttributeValue();

  // <spec step="19">If el has an event attribute and a for attribute, and el's
  // type is "classic", then:</spec>
  if (GetScriptType() != ScriptTypeAtPrepare::kClassic ||
      event_attribute.IsNull() || for_attribute.IsNull()) {
    return true;
  }

  // <spec step="19.3">Strip leading and trailing ASCII whitespace from event
  // and for.</spec>
  for_attribute = for_attribute.StripWhiteSpace();
  // <spec step="19.4">If for is not an ASCII case-insensitive match for the
  // string "window", then return.</spec>
  if (!EqualIgnoringASCIICase(for_attribute, "window")) {
    return false;
  }
  event_attribute = event_attribute.StripWhiteSpace();
  // <spec step="19.5">If event is not an ASCII case-insensitive match for
  // either the string "onload" or the string "onload()", then return.</spec>
  return EqualIgnoringASCIICase(event_attribute, "onload") ||
         EqualIgnoringASCIICase(event_attribute, "onload()");
}

String ScriptLoader::GetScriptText() const {
  // Step 3 of
  // https://w3c.github.io/trusted-types/dist/spec/#abstract-opdef-prepare-the-script-url-and-text
  // called from § 4.1.3.3, step 4 of
  // https://w3c.github.io/trusted-types/dist/spec/#slot-value-verification
  // This will return the [[ScriptText]] internal slot value after that step,
  // or a null string if the the Trusted Type algorithm threw an error.
  String child_text_content = element_->ChildTextContent();
  DCHECK(!child_text_content.IsNull());
  String script_text_internal_slot = element_->ScriptTextInternalSlot();
  if (child_text_content == script_text_internal_slot) {
    return child_text_content;
  }
  return GetStringForScriptExecution(child_text_content,
                                     element_->GetScriptElementType(),
                                     element_->GetExecutionContext());
}

void ScriptLoader::AddSpeculationRuleSet(SpeculationRuleSet::Source* source) {
  // https://wicg.github.io/nav-speculation/speculation-rules.html
  // Let result be the result of parsing speculation rules given source
  // text and base URL.
  // Set the script’s result to result.
  // If the script’s result is not null, append it to the element’s node
  // document's list of speculation rule sets.
  Document& element_document = element_->GetDocument();
  LocalDOMWindow* context_window = element_document.domWindow();
  if (!context_window) {
    return;
  }

  speculation_rule_set_ = SpeculationRuleSet::Parse(source, context_window);
  CHECK(speculation_rule_set_);
  DocumentSpeculationRules::From(element_document)
      .AddRuleSet(speculation_rule_set_);
  speculation_rule_set_->AddConsoleMessageForValidation(*element_);
}

SpeculationRuleSet* ScriptLoader::RemoveSpeculationRuleSet() {
  if (SpeculationRuleSet* rule_set =
          std::exchange(speculation_rule_set_, nullptr)) {
    // Speculation rules in this script no longer apply.
    // Candidate speculations must be re-evaluated.
    DCHECK_EQ(GetScriptType(), ScriptTypeAtPrepare::kSpeculationRules);
    DocumentSpeculationRules::From(element_->GetDocument())
        .RemoveRuleSet(rule_set);
    return rule_set;
  }
  return nullptr;
}

}  // namespace blink
```