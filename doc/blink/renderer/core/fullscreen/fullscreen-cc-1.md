Response:
Let's break down the thought process for analyzing the provided `fullscreen.cc` code snippet.

**1. Initial Understanding of the Context:**

The first step is to recognize the context. The prompt clearly states it's part of the Chromium Blink engine, specifically the `fullscreen.cc` file within the `blink/renderer/core/fullscreen` directory. This immediately suggests the file is responsible for handling the Fullscreen API within the browser.

**2. Identifying Key Data Structures and Methods:**

Next, I would scan the code for prominent data structures and method names. Keywords like `PendingRequest`, `PendingExits`, `FullscreenOptions`, `ScriptPromiseResolver`, `EnterFullscreen`, `ExitFullscreen`, `ContinueRequestFullscreen`, `ContinueExitFullscreen`, `EnqueueEvent`, `GoFullscreen`, `Unfullscreen`, and `FullscreenElementFrom` stand out. These provide clues about the core functionalities.

**3. Focusing on the Core Logic - Requesting Fullscreen:**

I'd start by analyzing the `RequestFullscreen` method. The comments within the code itself are extremely helpful, often directly referencing the WHATWG Fullscreen specification. I would follow the numbered steps in the comments:

* **Step 1-7 (Implicit):**  The initial checks for user gestures and document state are handled. The crucial part is the error handling and the message about user gestures. This directly links to JavaScript interactions.
* **Step 8:** Resizing the viewport is a key action, linking to visual changes on the screen. The handling of pending requests and the `EnterFullscreen` call to the `ChromeClient` indicate interaction with the browser's UI.
* **Step 6 (Out of Order):** Consuming user activation is another essential security measure, preventing arbitrary fullscreen requests.

**4. Analyzing the Resolution of Fullscreen Requests:**

The `DidResolveEnterFullscreenRequest` method is triggered after the browser (via `ChromeClient`) decides whether to grant the fullscreen request. The asynchronous nature of this resolution (using `EnqueueMicrotask`) is important. The loop through `pending_requests_` and the call to `ContinueRequestFullscreen` connect the initial request with its final processing.

**5. Deconstructing `ContinueRequestFullscreen`:**

This method performs the final steps of processing a fullscreen request:

* **Step 9:**  Verifying document and element state ensures consistency.
* **Step 10:** Handling errors by enqueueing a `fullscreenerror` event and rejecting the promise is vital for API correctness. This directly ties into JavaScript error handling.
* **Step 11-13:** The loop through ancestor frames to ensure all relevant elements enter fullscreen is critical for nested iframes. This highlights the interaction with the DOM structure. The handling of WebXR overlay mode shows the flexibility of the API.
* **Step 14:** Resolving the promise signals success back to the JavaScript code.

**6. Understanding the Exit Fullscreen Flow:**

The `ExitFullscreen` method initiates the process of leaving fullscreen. Key aspects are:

* **Promise Handling:**  Like `RequestFullscreen`, it uses promises for asynchronous completion.
* **Error Checking:**  Verifying the document's active state and the presence of a fullscreen element.
* **Collecting Documents to Unfullscreen:** The `CollectDocumentsToUnfullscreen` function (not shown but referenced) suggests the handling of nested fullscreen scenarios.
* **`DidExitFullscreen` and `ContinueExitFullscreen`:**  These methods handle the asynchronous response from the browser and the subsequent steps of unfullscreening elements.

**7. Identifying Connections to JavaScript, HTML, and CSS:**

Throughout the analysis, I would actively look for links to web technologies:

* **JavaScript:**  The use of promises (`ScriptPromiseResolver`), event names (`fullscreenerror`, `fullscreenchange`), API calls (`requestFullscreen`, `exitFullscreen`), and the handling of user gestures.
* **HTML:** The mention of `Element`, `Document`, `iframe`, and the `allowfullscreen` attribute.
* **CSS:**  The comment about WebXR overlay mode changing the background to transparent and adding the `:xr-overlay` pseudo-class. The resizing of the viewport also implies changes that would affect CSS layout.

**8. Inferring Logic and Scenarios:**

Based on the code and comments, I would infer common scenarios and potential issues:

* **User Gesture Requirement:**  The error message about "API can only be initiated by a user gesture" immediately suggests a common user error – trying to trigger fullscreen without direct user interaction.
* **Pending Requests:** The `pending_requests_` queue implies that requests might be processed asynchronously and in order.
* **Nested Fullscreen:** The code explicitly handles nested browsing contexts and iframes.
* **Error Handling:** The various `RequestFullscreenError` enum values and the rejection of promises demonstrate the error handling mechanisms.

**9. Structuring the Output:**

Finally, I would organize the findings into the requested categories:

* **Functionality:**  Provide a high-level summary and then detail the main functions (`RequestFullscreen`, `ExitFullscreen`, etc.).
* **Relationship to Web Technologies:**  Give concrete examples for JavaScript, HTML, and CSS.
* **Logic and Assumptions:**  Describe scenarios and the assumed inputs and outputs.
* **User/Programming Errors:** Provide examples of common mistakes.
* **Summary:**  A concise recap of the overall purpose of the code.

**Self-Correction/Refinement:**

During the process, I would double-check my understanding and refine my explanations. For example, initially, I might focus too much on the low-level details. I would then step back and ensure the high-level functionality is clearly explained first. I'd also ensure that the examples provided are clear and directly related to the code snippet. Recognizing the "PART 2" instruction helps to focus on summarizing the already presented information.
好的，让我们归纳一下这段 `fullscreen.cc` 代码的功能。

**代码功能归纳**

这段代码是 Chromium Blink 引擎中负责处理全屏 API 的核心逻辑部分。它主要负责以下功能：

1. **处理 `requestFullscreen()` 请求:**
   - 接收来自 JavaScript 的 `element.requestFullscreen()` 调用。
   - 进行一系列权限检查，例如是否需要用户手势。
   - 如果权限允许，则准备将指定的元素或其祖先元素进入全屏模式。
   - 管理待处理的全屏请求队列 (`pending_requests_`)。
   - 调用浏览器的底层接口 (`ChromeClient`) 来实际执行全屏操作。
   - 处理全屏请求成功或失败后的 Promise 解析 (`ScriptPromiseResolver`)。

2. **处理 `exitFullscreen()` 请求:**
   - 接收来自 JavaScript 的 `document.exitFullscreen()` 调用。
   - 确定需要退出全屏的文档和元素。
   - 管理待处理的退出全屏请求队列 (`pending_exits_`)。
   - 调用浏览器的底层接口来退出全屏模式。
   - 处理退出全屏操作成功或失败后的 Promise 解析。

3. **管理全屏状态:**
   - 跟踪哪些元素当前处于全屏模式 (虽然这段代码没有直接展示如何跟踪，但它与管理进入和退出全屏的流程密切相关)。
   - 维护文档的全屏状态（例如，通过 `document.fullscreenElement` 属性，虽然代码中没有直接设置该属性，但其行为影响了该属性的值）。

4. **触发全屏事件:**
   - 在全屏状态改变时（进入或退出），触发 `fullscreenchange` 事件。
   - 在全屏请求失败时，触发 `fullscreenerror` 事件。

5. **处理跨域和嵌套浏览上下文的全屏请求:**
   - 涉及到对 iframe 元素的全屏处理。
   - 确保在嵌套的浏览上下文中正确处理全屏请求和退出。

6. **WebXR 集成 (部分):**
   - 支持 WebXR DOM Overlay 模式的全屏请求，并更新文档的样式和伪类 (`:xr-overlay`)。

**与 JavaScript, HTML, CSS 的关系举例说明**

* **JavaScript:**
    - **调用 `requestFullscreen()`:**  当 JavaScript 代码调用 `element.requestFullscreen(options)` 时，这段 `RequestFullscreen` 函数会被触发。
        ```javascript
        const element = document.getElementById('myElement');
        element.requestFullscreen(); // 触发 RequestFullscreen
        ```
    - **调用 `exitFullscreen()`:**  当 JavaScript 代码调用 `document.exitFullscreen()` 时，这段 `ExitFullscreen` 函数会被触发。
        ```javascript
        document.exitFullscreen(); // 触发 ExitFullscreen
        ```
    - **处理 Promise:** `requestFullscreen()` 和 `exitFullscreen()` 返回 Promise，这段代码使用 `ScriptPromiseResolver` 来解析这些 Promise，通知 JavaScript 全屏操作的结果。
    - **监听事件:** JavaScript 代码可以监听 `fullscreenchange` 和 `fullscreenerror` 事件，这些事件是由这段代码在全屏状态改变时触发的。
        ```javascript
        document.addEventListener('fullscreenchange', () => {
          if (document.fullscreenElement) {
            console.log('进入全屏');
          } else {
            console.log('退出全屏');
          }
        });

        document.addEventListener('fullscreenerror', (event) => {
          console.error('全屏错误:', event);
        });
        ```

* **HTML:**
    - **`allowfullscreen` 属性:** `Fullscreen::FullscreenEnabled` 函数会检查元素或其祖先是否具有 `allowfullscreen` 属性，以确定是否允许进入全屏。
        ```html
        <iframe src="other.html" allowfullscreen></iframe>
        ```
    - **全屏元素:**  `document.fullscreenElement` 属性（虽然这段代码没有直接设置，但其行为影响了该属性的值）反映了当前处于全屏状态的 HTML 元素。

* **CSS:**
    - **`:fullscreen` 伪类:** 当元素进入全屏时，浏览器会自动应用 `:fullscreen` 伪类，允许开发者针对全屏状态设置特定的样式。这段代码虽然没有直接操作 CSS，但其功能是 `:fullscreen` 伪类生效的基础。
        ```css
        :fullscreen {
          background-color: black;
          /* 全屏状态下的样式 */
        }
        ```
    - **WebXR Overlay 伪类:**  当以 WebXR Overlay 模式请求全屏时，代码会设置文档的 `IsXrOverlay` 标志，这会导致浏览器应用 `:xr-overlay` 伪类。

**逻辑推理的假设输入与输出**

**假设输入 (对于 `RequestFullscreen`):**

1. **用户在页面上点击了一个按钮。**
2. **JavaScript 代码调用了 `document.getElementById('myVideo').requestFullscreen();`**
3. **该 `myVideo` 元素允许全屏（例如，没有祖先元素设置了 `allowfullscreen="false"`）。**

**假设输出:**

1. **`RequestFullscreen` 函数被调用。**
2. **权限检查通过（因为是用户手势）。**
3. **`myVideo` 元素被添加到待处理的全屏请求队列。**
4. **浏览器底层接口被调用，尝试将 `myVideo` 进入全屏。**
5. **如果浏览器成功进入全屏：**
   - `DidResolveEnterFullscreenRequest` 被调用，`granted` 为 `true`。
   - `ContinueRequestFullscreen` 被调用，Promise 被 resolve。
   - `fullscreenchange` 事件在 `document` 上触发，`document.fullscreenElement` 将是 `myVideo`。
6. **如果浏览器未能进入全屏（例如，用户取消）：**
   - `DidResolveEnterFullscreenRequest` 被调用，`granted` 为 `false`。
   - `ContinueRequestFullscreen` 被调用，Promise 被 reject。
   - `fullscreenerror` 事件在 `document` 上触发。

**假设输入 (对于 `ExitFullscreen`):**

1. **当前有一个元素处于全屏状态。**
2. **JavaScript 代码调用了 `document.exitFullscreen();`**

**假设输出:**

1. **`ExitFullscreen` 函数被调用。**
2. **浏览器底层接口被调用，尝试退出全屏。**
3. **`DidExitFullscreen` 被调用。**
4. **`ContinueExitFullscreen` 被调用，Promise 被 resolve。**
5. **`fullscreenchange` 事件在之前的全屏元素的文档上触发，`document.fullscreenElement` 将为 `null`。**

**用户或编程常见的使用错误举例说明**

1. **尝试在非用户手势触发的情况下请求全屏:**
   - **错误代码:**
     ```javascript
     setTimeout(() => {
       document.body.requestFullscreen(); // 可能会失败
     }, 5000);
     ```
   - **说明:**  大多数浏览器要求全屏请求必须由用户直接操作（例如点击、按键）触发，以防止恶意网站滥用全屏 API。这段代码尝试在 5 秒后请求全屏，很可能会被浏览器阻止，并会在控制台输出类似 "API can only be initiated by a user gesture." 的警告信息。

2. **忘记在 iframe 上使用 `allowfullscreen` 属性:**
   - **错误代码 (HTML):**
     ```html
     <iframe src="fullscreen_content.html"></iframe>
     ```
   - **错误代码 (JavaScript - 在 `fullscreen_content.html` 中):**
     ```javascript
     document.documentElement.requestFullscreen();
     ```
   - **说明:**  如果 iframe 想要进入全屏，其父级 HTML 必须显式地使用 `allowfullscreen` 属性。否则，即使 iframe 内部的代码调用了 `requestFullscreen()`，也会被浏览器阻止。

3. **在文档未激活时尝试退出全屏:**
   - **场景:**  在页面卸载或切换到另一个标签页的过程中尝试调用 `document.exitFullscreen()`。
   - **说明:**  `ExitFullscreen` 函数会检查文档是否处于激活状态。如果文档未激活，Promise 将会被 reject 并抛出一个 `TypeError`。

**归纳总结（针对第 2 部分）**

这段 `fullscreen.cc` 代码是 Blink 引擎中处理全屏 API 请求和状态管理的核心组件。它负责接收来自 JavaScript 的全屏请求和退出请求，进行必要的权限检查，与浏览器的底层接口交互以执行全屏操作，并在操作完成后通过 Promise 将结果返回给 JavaScript。此外，它还负责在全屏状态改变时触发相应的事件，并处理跨域和嵌套浏览上下文下的全屏
### 提示词
```
这是目录为blink/renderer/core/fullscreen/fullscreen.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
pending->GetDocument();
  if (error != RequestFullscreenError::kNone) {
    // TODO: Surface more errors in the console with added precision.
    if (error == RequestFullscreenError::kPermissionCheckFailed) {
      String message = ExceptionMessages::FailedToExecute(
          "requestFullscreen", "Element",
          "API can only be initiated by a user gesture.");
      document.AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
          mojom::blink::ConsoleMessageSource::kJavaScript,
          mojom::blink::ConsoleMessageLevel::kWarning, message));
    }
    // Note: Although we are past the "in parallel" point, it's OK to continue
    // synchronously because when `error` is true, `ContinueRequestFullscreen()`
    // will only queue a task and return. This is indistinguishable from, e.g.,
    // enqueueing a microtask to continue at step 9.
    ContinueRequestFullscreen(document, *pending, request_type, options,
                              resolver, error);
    return;
  }

  LocalDOMWindow& window = *document.domWindow();

  // 8. If `error` is false: then resize `pendingDoc`’s node navigable’s
  // top-level traversable’s active document’s viewport’s dimensions, optionally
  // taking into account options["navigationUI"].
  // Optionally display a message how the end user can revert this.
  if (From(window).pending_requests_.size()) {
    UseCounter::Count(window, WebFeature::kFullscreenRequestWithPendingElement);
  }

  From(window).pending_requests_.push_back(MakeGarbageCollected<PendingRequest>(
      pending, request_type, options, resolver));
  LocalFrame& frame = *window.GetFrame();
  frame.GetChromeClient().EnterFullscreen(frame, options, request_type);

  // 6. If `error` is false, then consume user activation given `pendingDoc`’s
  // relevant global object.
  // TODO: Reorder implementation to match the specified algorithm steps.
  // This does, at least, correctly consume activation before RequestFullscreen
  // returns its promise. This callback is run synchronously before the promise
  // is returned when conditions are met and the frame has transient activation.
  // This callback is only run asynchronously when a frame requests fullscreen
  // without transient activation, which requires a permission service check.
  if ((request_type & FullscreenRequestType::kForCrossProcessDescendant) == 0) {
    LocalFrame::ConsumeTransientUserActivation(window.GetFrame());
    window.ConsumeFullscreenRequestToken();
  }
}

void Fullscreen::DidResolveEnterFullscreenRequest(Document& document,
                                                  bool granted) {
  if (!document.domWindow())
    return;

  // We may be called synchronously from within
  // |FullscreenController::EnterFullscreen()| if we were already fullscreen,
  // but must still not synchronously change the fullscreen element. Instead
  // enqueue a microtask to continue.
  if (RequestFullscreenScope::RunningRequestFullscreen()) {
    document.GetAgent().event_loop()->EnqueueMicrotask(WTF::BindOnce(
        [](Document* document, bool granted) {
          DCHECK(document);
          DidResolveEnterFullscreenRequest(*document, granted);
        },
        WrapPersistent(&document), granted));
    return;
  }

  PendingRequests requests;
  requests.swap(From(*document.domWindow()).pending_requests_);
  const RequestFullscreenError error =
      granted ? RequestFullscreenError::kNone
              : RequestFullscreenError::kNotGranted;
  for (const Member<PendingRequest>& request : requests) {
    ContinueRequestFullscreen(document, *request->element(), request->type(),
                              request->options(), request->resolver(), error);
  }
}

void Fullscreen::ContinueRequestFullscreen(
    Document& document,
    Element& pending,
    FullscreenRequestType request_type,
    const FullscreenOptions* options,
    ScriptPromiseResolver<IDLUndefined>* resolver,
    RequestFullscreenError error) {
  DCHECK(document.IsActive());
  DCHECK(document.GetFrame());

  // 9. If any of the following conditions are false, then set `error` to true:
  //     * `pending`'s node document is `pendingDoc`.
  //     * The fullscreen element ready check for `pending` returns true.
  if (error == RequestFullscreenError::kNone) {
    if (pending.GetDocument() != document) {
      error = RequestFullscreenError::kDocumentIncorrect;
    } else {
      error = FullscreenElementReadyCheck(pending, ReportOptions::kDoNotReport);
    }
  }

  // 10. If `error` is true:
  if (error != RequestFullscreenError::kNone) {
    // 10.1. Append (fullscreenerror, `pending`) to `pendingDoc`'s list of
    // pending fullscreen events.
    EnqueueEvent(event_type_names::kFullscreenerror, pending, document,
                 request_type);

    // 10.2. Reject `promise` with a TypeError exception and terminate these
    // steps.
    if (resolver && resolver->GetScriptState()->ContextIsValid()) {
      ScriptState::Scope scope(resolver->GetScriptState());
      resolver->Reject(V8ThrowException::CreateTypeError(
          resolver->GetScriptState()->GetIsolate(), GetErrorString(error)));
    }
    return;
  }

  // 11. Let |fullscreenElements| be an ordered set initially consisting of
  // |pending|.
  HeapVector<Member<Element>> fullscreen_elements;
  fullscreen_elements.push_back(pending);

  // 12. While the first element in |fullscreenElements| is in a nested browsing
  // context: append its browsing context container to |fullscreenElements|.
  //
  // OOPIF: |fullscreenElements| will only contain elements for local ancestors,
  // and remote ancestors will be processed in their respective processes. This
  // preserves the spec's event firing order for local ancestors, but not for
  // remote ancestors. However, that difference shouldn't be observable in
  // practice: a fullscreenchange event handler would need to postMessage a
  // frame in another renderer process, where the message should be queued up
  // and processed after the IPC that dispatches fullscreenchange.
  for (Frame* frame = pending.GetDocument().GetFrame(); frame;
       frame = frame->Tree().Parent()) {
    Element* element = DynamicTo<HTMLFrameOwnerElement>(frame->Owner());
    if (!element)
      continue;
    fullscreen_elements.push_back(element);
  }

  // 13. For each |element| in |fullscreenElements|:
  for (Element* element : fullscreen_elements) {
    // 13.1. Let |doc| be |element|'s node document.
    Document& doc = element->GetDocument();

    // If this fullscreen request is for WebXR DOM Overlay mode, apply that
    // property to the document. This updates styling (setting the background
    // transparent) and adds the :xr-overlay pseudoclass.
    if (request_type & FullscreenRequestType::kForXrOverlay) {
      // There's never more than one overlay element per document. (It's either
      // the actual overlay element, or a containing iframe element if the
      // actual element is in a different document.) It can't be changed during
      // the session, that's enforced by AllowedToRequestFullscreen().
      DCHECK(!doc.IsXrOverlay());
      doc.SetIsXrOverlay(true, element);
    }

    // 13.2. If |element| is |doc|'s fullscreen element, continue.
    if (element == FullscreenElementFrom(doc))
      continue;

    // 13.3. If |element| is |pending| and |pending| is an iframe element, set
    // |element|'s iframe fullscreen flag.
    // TODO(foolip): Support the iframe fullscreen flag.
    // https://crbug.com/644695

    // 13.4. Fullscreen |element| within |doc|.
    GoFullscreen(*element, request_type, options);

    // 13.5. Append (fullscreenchange, |element|) to |doc|'s list of pending
    // fullscreen events.
    EnqueueEvent(event_type_names::kFullscreenchange, *element, doc,
                 request_type);
  }

  // 14. Resolve |promise| with undefined.
  if (resolver) {
    ScriptState::Scope scope(resolver->GetScriptState());
    resolver->Resolve();
  }
}

// https://fullscreen.spec.whatwg.org/#fully-exit-fullscreen
void Fullscreen::FullyExitFullscreen(Document& document, bool ua_originated) {
  // TODO(foolip): The spec used to have a first step saying "Let |doc| be the
  // top-level browsing context's document" which was removed in
  // https://github.com/whatwg/fullscreen/commit/3243119d027a8ff5b80998eb1f17f8eba148a346.
  // Remove it here as well.
  Document& doc = TopmostLocalAncestor(document);

  // 1. If |document|'s fullscreen element is null, terminate these steps.
  Element* fullscreen_element = FullscreenElementFrom(doc);
  if (!fullscreen_element)
    return;

  // 2. Unfullscreen elements whose fullscreen flag is set, within
  // |document|'s top layer, except for |document|'s fullscreen element.
  HeapVector<Member<Element>> unfullscreen_elements;
  for (Element* element : doc.TopLayerElements()) {
    if (HasFullscreenFlag(*element) && element != fullscreen_element)
      unfullscreen_elements.push_back(element);
  }
  for (Element* element : unfullscreen_elements)
    Unfullscreen(*element);
  DCHECK(IsSimpleFullscreenDocument(doc));

  // 3. Exit fullscreen |document|.
  ExitFullscreen(doc, nullptr, nullptr, ua_originated);
}

// https://fullscreen.spec.whatwg.org/#exit-fullscreen
ScriptPromise<IDLUndefined> Fullscreen::ExitFullscreen(
    Document& doc,
    ScriptState* script_state,
    ExceptionState* exception_state,
    bool ua_originated) {
  // 1. Let |promise| be a new promise.
  // For optimization allocate the ScriptPromiseResolver later.
  ScriptPromiseResolver<IDLUndefined>* resolver = nullptr;

  // 2. If |doc| is not fully active or |doc|'s fullscreen element is null, then
  // reject |promise| with a TypeError exception and return |promise|.
  if (!doc.IsActive() || !doc.GetFrame() || !FullscreenElementFrom(doc)) {
    if (!exception_state)
      return EmptyPromise();
    exception_state->ThrowTypeError("Document not active");
    return EmptyPromise();
  }

  if (script_state) {
    resolver =
        MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(script_state);
  }

  // 3. Let |resize| be false.
  bool resize = false;

  // 4. Let |docs| be the result of collecting documents to unfullscreen given
  // |doc|.
  HeapVector<Member<Document>> docs = CollectDocumentsToUnfullscreen(doc);

  // 5. Let |topLevelDoc| be |doc|'s top-level browsing context's active
  // document.
  //
  // OOPIF: Let |topLevelDoc| be the topmost local ancestor instead. If the main
  // frame is in another process, we will still fully exit fullscreen even
  // though that's wrong if the main frame was in nested fullscreen.
  // TODO(alexmos): Deal with nested fullscreen cases, see
  // https://crbug.com/617369.
  Document& top_level_doc = TopmostLocalAncestor(doc);

  // 6. If |topLevelDoc| is in |docs|, and it is a simple fullscreen document,
  // then set |doc| to |topLevelDoc| and |resize| to true.
  //
  // Note: |doc| is not set here, but |doc| will be the topmost local ancestor
  // in |Fullscreen::ContinueExitFullscreen| if |resize| is true.
  if (!docs.empty() && docs.back() == &top_level_doc &&
      IsSimpleFullscreenDocument(top_level_doc)) {
    resize = true;
  }

  Element* element = FullscreenElementFrom(doc);

  // Log fullscreen session duration UMA for certain request types.
  const MetaParams* element_params = GetParams(*element);
  FullscreenRequestType request_type = element_params
                                           ? element_params->request_type()
                                           : FullscreenRequestType::kUnprefixed;
  if (element_params) {
    // Track traditional HTML requests without any other flags (e.g. XR).
    // ForCrossProcessDescendant is excluded here to ensure the counter is only
    // incremented when this function is invoked for the top frame.
    if (request_type == FullscreenRequestType::kUnprefixed ||
        request_type == FullscreenRequestType::kPrefixed) {
      UMA_HISTOGRAM_LONG_TIMES(
          kFullscreenDurationMetricKeyRequestFullscreen,
          base::TimeTicks::Now() - element_params->fullscreen_enter_time());
    }
  }

  // 7. If |doc|'s fullscreen element is not connected.
  if (!element->isConnected()) {
    // 7.1. Append (fullscreenchange, |doc|'s fullscreen element) to
    // |doc|'s list of pending fullscreen events.
    EnqueueEvent(event_type_names::kFullscreenchange, *element, doc,
                 request_type);

    // 7.2. Unfullscreen |element|.
    Unfullscreen(*element);
  }

  // 7. Return |promise|, and run the remaining steps in parallel.
  auto promise = resolver ? resolver->Promise() : ScriptPromise<IDLUndefined>();

  // 8. If |resize| is true, resize |doc|'s viewport to its "normal" dimensions.
  if (resize) {
    if (ua_originated) {
      ContinueExitFullscreen(&doc, resolver, true /* resize */);
    } else {
      From(*top_level_doc.domWindow()).pending_exits_.push_back(resolver);
      LocalFrame& frame = *doc.GetFrame();
      frame.GetChromeClient().ExitFullscreen(frame);
    }
  } else {
    DCHECK(!ua_originated);
    // Note: We are past the "in parallel" point, and |ContinueExitFullscreen()|
    // will change script-observable state (document.fullscreenElement)
    // synchronously, so we have to continue asynchronously.
    doc.GetAgent().event_loop()->EnqueueMicrotask(
        WTF::BindOnce(ContinueExitFullscreen, WrapPersistent(&doc),
                      WrapPersistent(resolver), false /* resize */));
  }
  return promise;
}

void Fullscreen::DidExitFullscreen(Document& document) {
  Fullscreen& fullscreen = From(*document.domWindow());

  // Block automatic fullscreen temporarily, e.g. match kActivationLifespan.
  fullscreen.block_automatic_fullscreen_until_ =
      base::TimeTicks::Now() + base::Seconds(5);

  // If this is a response to an ExitFullscreen call then
  // continue exiting. Otherwise call FullyExitFullscreen.
  PendingExits exits;
  exits.swap(fullscreen.pending_exits_);
  if (exits.empty()) {
    FullyExitFullscreen(document, true /* ua_originated */);
  } else {
    for (const Member<PendingExit>& exit : exits) {
      ContinueExitFullscreen(&document, exit, true /* resize */);
    }
  }
}

void Fullscreen::ContinueExitFullscreen(
    Document* doc,
    ScriptPromiseResolver<IDLUndefined>* resolver,
    bool resize) {
  if (!doc || !doc->IsActive() || !doc->GetFrame()) {
    if (resolver) {
      ScriptState::Scope scope(resolver->GetScriptState());
      resolver->Reject(V8ThrowException::CreateTypeError(
          resolver->GetScriptState()->GetIsolate(), "Document is not active"));
    }
    return;
  }

  if (resize) {
    // See comment for step 6.
    DCHECK_EQ(nullptr, NextLocalAncestor(*doc));
  }

  // 9. If |doc|'s fullscreen element is null, then resolve |promise| with
  // undefined and terminate these steps.
  if (!FullscreenElementFrom(*doc)) {
    if (resolver) {
      ScriptState::Scope scope(resolver->GetScriptState());
      resolver->Resolve();
    }
    return;
  }

  // 10. Let |exitDocs| be the result of collecting documents to unfullscreen
  // given |doc|.
  HeapVector<Member<Document>> exit_docs = CollectDocumentsToUnfullscreen(*doc);

  // 11. Let |descendantDocs| be an ordered set consisting of |doc|'s
  // descendant browsing contexts' documents whose fullscreen element is
  // non-null, if any, in tree order.
  HeapVector<Member<Document>> descendant_docs;
  for (Frame* descendant = doc->GetFrame()->Tree().FirstChild(); descendant;
       descendant = descendant->Tree().TraverseNext(doc->GetFrame())) {
    auto* descendant_local_frame = DynamicTo<LocalFrame>(descendant);
    if (!descendant_local_frame)
      continue;
    DCHECK(descendant_local_frame->GetDocument());
    if (FullscreenElementFrom(*descendant_local_frame->GetDocument()))
      descendant_docs.push_back(descendant_local_frame->GetDocument());
  }

  // 12. For each |exitDoc| in |exitDocs|:
  for (Document* exit_doc : exit_docs) {
    Element* exit_element = FullscreenElementFrom(*exit_doc);
    DCHECK(exit_element);
    FullscreenRequestType request_type = GetRequestType(*exit_element);

    // 12.1. Append (fullscreenchange, |exitDoc|'s fullscreen element) to
    // |exitDoc|'s list of pending fullscreen events.
    EnqueueEvent(event_type_names::kFullscreenchange, *exit_element, *exit_doc,
                 request_type);

    // 12.2. If |resize| is true, unfullscreen |exitDoc|.
    // 12.3. Otherwise, unfullscreen |exitDoc|'s fullscreen element.
    if (resize)
      Unfullscreen(*exit_doc);
    else
      Unfullscreen(*exit_element);
  }

  // 13. For each |descendantDoc| in |descendantDocs|:
  for (Document* descendant_doc : descendant_docs) {
    Element* descendant_element = FullscreenElementFrom(*descendant_doc);
    DCHECK(descendant_element);
    FullscreenRequestType request_type = GetRequestType(*descendant_element);

    // 13.1. Append (fullscreenchange, |descendantDoc|'s fullscreen element) to
    // |descendantDoc|'s list of pending fullscreen events.
    EnqueueEvent(event_type_names::kFullscreenchange, *descendant_element,
                 *descendant_doc, request_type);

    // 13.2. Unfullscreen |descendantDoc|.
    Unfullscreen(*descendant_doc);
  }

  // 14. Resolve |promise| with undefined.
  if (resolver) {
    ScriptState::Scope scope(resolver->GetScriptState());
    resolver->Resolve();
  }
}

// https://fullscreen.spec.whatwg.org/#dom-document-fullscreenenabled
bool Fullscreen::FullscreenEnabled(Document& document,
                                   ReportOptions report_on_failure) {
  // The fullscreenEnabled attribute's getter must return true if the context
  // object is allowed to use the feature indicated by attribute name
  // allowfullscreen and fullscreen is supported, and false otherwise.
  return AllowedToUseFullscreen(document, report_on_failure) &&
         FullscreenIsSupported(document);
}

void Fullscreen::DidUpdateSize(Element& element) {
  // StyleAdjuster will set the size so we need to do a style recalc.
  // Normally changing size means layout so just doing a style recalc is a
  // bit surprising.
  element.SetNeedsStyleRecalc(
      kLocalStyleChange,
      StyleChangeReasonForTracing::Create(style_change_reason::kFullscreen));
}

void Fullscreen::ElementRemoved(Element& node) {
  DCHECK(node.IsInTopLayer());
  if (!HasFullscreenFlag(node))
    return;

  // 1. Let |document| be removedNode's node document.
  Document& document = node.GetDocument();

  // |Fullscreen::ElementRemoved()| is called for each removed element, so only
  // the body of the spec "removing steps" loop appears here:

  // 3.1. If |node| is its node document's fullscreen element, exit fullscreen
  // that document.
  if (IsFullscreenElement(node)) {
    ExitFullscreen(document);
  } else {
    // 3.2. Otherwise, unfullscreen |node| within its node document.
    Unfullscreen(node);
  }

  // 3.3 If document's top layer contains node, remove node from document's top
  // layer. This is done in Element::RemovedFrom.
}

bool Fullscreen::IsFullscreenFlagSetFor(const Element& element) {
  return HasFullscreenFlag(element);
}

void Fullscreen::Trace(Visitor* visitor) const {
  visitor->Trace(pending_requests_);
  visitor->Trace(pending_exits_);
  Supplement<LocalDOMWindow>::Trace(visitor);
  ExecutionContextLifecycleObserver::Trace(visitor);
}

Fullscreen::PendingRequest::PendingRequest(
    Element* element,
    FullscreenRequestType type,
    const FullscreenOptions* options,
    ScriptPromiseResolver<IDLUndefined>* resolver)
    : element_(element), type_(type), options_(options), resolver_(resolver) {}

Fullscreen::PendingRequest::~PendingRequest() = default;

void Fullscreen::PendingRequest::Trace(Visitor* visitor) const {
  visitor->Trace(element_);
  visitor->Trace(options_);
  visitor->Trace(resolver_);
}

}  // namespace blink
```