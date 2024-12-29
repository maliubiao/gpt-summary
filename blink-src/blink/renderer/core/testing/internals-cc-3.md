Response:
The user wants me to summarize the functionality of the provided C++ code snippet from `blink/renderer/core/testing/internals.cc`. This is part 4 of 5. I need to focus on the functionalities present in this specific block of code.

Based on the code, the functions in this section seem to deal with:

1. **CSS Properties:** Retrieving lists of longhand and shorthand CSS properties.

Therefore, the main function of this part is to provide access to information about CSS properties within the Blink rendering engine, likely for testing purposes.
这是 `blink/renderer/core/testing/internals.cc` 文件的第四部分，主要功能是提供用于测试和检查 Blink 渲染引擎内部状态的接口。 这一部分的代码着重于 **CSS 属性**相关的内部功能。

**功能归纳：**

*   **获取 CSS 属性列表:** 提供了两个函数 `getCSSPropertyLonghands()` 和 `getCSSPropertyShorthands()`，用于获取当前上下文中所有暴露给 Web 且分别是长属性和短属性的 CSS 属性名称列表。

**与 javascript, html, css 的关系及举例说明：**

*   **CSS:** 这部分代码直接操作和暴露了 CSS 属性的相关信息。
    *   **例子:** 在 JavaScript 中，开发者可以通过 `internals.getCSSPropertyLonghands()` 方法获取到一个包含所有 CSS 长属性名称的数组，例如 `["background-color", "font-size", "margin-top", ...]`。 同样，`internals.getCSSPropertyShorthands()` 可以获取到短属性名称的数组，例如 `["background", "font", "margin", ...]`。

**逻辑推理、假设输入与输出：**

*   **假设输入:** 当前渲染的文档中使用了多种 CSS 属性，包括长属性和短属性。
*   **getCSSPropertyLonghands() 输出:**  返回一个 `Vector<String>`，其中包含类似 `"color"`, `"font-weight"`, `"padding-left"` 等表示 CSS 长属性的字符串。
*   **getCSSPropertyShorthands() 输出:** 返回一个 `Vector<String>`，其中包含类似 `"background"`, `"border"`, `"margin"` 等表示 CSS 短属性的字符串。

**用户或编程常见的使用错误：**

*   由于 `Internals` 接口主要用于测试目的，普通开发者不应该在生产环境中使用这些方法。 如果错误地在生产代码中使用这些接口，可能会导致代码在不同的 Chromium 版本之间表现不一致，或者在非 Chromium 浏览器中运行出错。

**用户操作如何一步步到达这里（调试线索）：**

1. **编写测试用例:** 开发人员为了测试 Blink 渲染引擎对 CSS 属性的处理逻辑，可能会编写 JavaScript 测试代码来调用 `internals.getCSSPropertyLonghands()` 或 `internals.getCSSPropertyShorthands()`。
2. **运行测试:** 该测试用例在 Chromium 的测试环境中运行。
3. **Blink 内部调用:** 当 JavaScript 调用 `internals.getCSSPropertyLonghands()` 时，Blink 内部会将这个调用路由到 `blink/renderer/core/testing/internals.cc` 文件中的 `Internals::getCSSPropertyLonghands()` 方法。
4. **遍历 CSS 属性:**  `getCSSPropertyLonghands()` 方法会遍历 Blink 内部维护的 CSS 属性列表。
5. **过滤和返回:**  它会筛选出那些被标记为 "WebExposed" 且是 "longhand" 的属性，并将它们的名称添加到结果列表中并返回给 JavaScript。

**总结一下这部分的功能：**

这部分 `Internals` 接口的核心功能是为测试提供了一种方式，来获取当前渲染上下文中暴露给 Web 的 CSS 长属性和短属性的名称列表。这对于验证 CSS 属性处理的正确性非常有用。

Prompt: 
```
这是目录为blink/renderer/core/testing/internals.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第4部分，共5部分，请归纳一下它的功能

"""
Vector<String> Internals::allIconURLs(Document* document) const {
  int icon_types_mask =
      1 << static_cast<int>(mojom::blink::FaviconIconType::kFavicon) |
      1 << static_cast<int>(mojom::blink::FaviconIconType::kTouchIcon) |
      1 << static_cast<int>(
          mojom::blink::FaviconIconType::kTouchPrecomposedIcon);
  return IconURLs(document, icon_types_mask);
}

int Internals::numberOfPages(float page_width,
                             float page_height,
                             ExceptionState& exception_state) {
  if (!GetFrame())
    return -1;

  if (page_width <= 0 || page_height <= 0) {
    exception_state.ThrowTypeError(
        "Page width and height must be larger than 0.");
    return -1;
  }

  return PrintContext::NumberOfPages(GetFrame(),
                                     gfx::SizeF(page_width, page_height));
}

float Internals::pageScaleFactor(ExceptionState& exception_state) {
  if (!document_->GetPage()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidAccessError,
        "The document's page cannot be retrieved.");
    return 0;
  }
  Page* page = document_->GetPage();
  return page->GetVisualViewport().Scale();
}

void Internals::setPageScaleFactor(float scale_factor,
                                   ExceptionState& exception_state) {
  if (scale_factor <= 0)
    return;
  if (!document_->GetPage()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidAccessError,
        "The document's page cannot be retrieved.");
    return;
  }
  Page* page = document_->GetPage();
  page->GetVisualViewport().SetScale(scale_factor);
}

void Internals::setPageScaleFactorLimits(float min_scale_factor,
                                         float max_scale_factor,
                                         ExceptionState& exception_state) {
  if (!document_->GetPage()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidAccessError,
        "The document's page cannot be retrieved.");
    return;
  }

  Page* page = document_->GetPage();
  page->SetDefaultPageScaleLimits(min_scale_factor, max_scale_factor);
}

float Internals::layoutZoomFactor(ExceptionState& exception_state) {
  if (!document_->GetPage()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidAccessError,
        "The document's page cannot be retrieved.");
    return 0;
  }
  // Layout zoom without Device Scale Factor.
  return document_->GetPage()->GetChromeClient().UserZoomFactor(
      document_->GetFrame());
}

void Internals::setIsCursorVisible(Document* document,
                                   bool is_visible,
                                   ExceptionState& exception_state) {
  DCHECK(document);
  if (!document->GetPage()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidAccessError,
                                      "No context document can be obtained.");
    return;
  }
  document->GetPage()->SetIsCursorVisible(is_visible);
}

void Internals::setMaxNumberOfFramesToTen(bool enabled) {
  // This gets reset by Internals::ResetToConsistentState
  Page::SetMaxNumberOfFramesToTenForTesting(enabled);
}

String Internals::effectivePreload(HTMLMediaElement* media_element) {
  DCHECK(media_element);
  return media_element->EffectivePreload();
}

void Internals::mediaPlayerRemoteRouteAvailabilityChanged(
    HTMLMediaElement* media_element,
    bool available) {
  DCHECK(media_element);

  RemotePlaybackController::From(*media_element)
      ->AvailabilityChangedForTesting(available);
}

void Internals::mediaPlayerPlayingRemotelyChanged(
    HTMLMediaElement* media_element,
    bool remote) {
  DCHECK(media_element);

  RemotePlaybackController::From(*media_element)
      ->StateChangedForTesting(remote);
}

void Internals::setPersistent(HTMLVideoElement* video_element,
                              bool persistent) {
  DCHECK(video_element);
  video_element->SetPersistentState(persistent);
}

void Internals::forceStaleStateForMediaElement(HTMLMediaElement* media_element,
                                               int target_state) {
  DCHECK(media_element);
  // Even though this is an internals method, the checks are necessary to
  // prevent fuzzers from taking this path and generating useless noise.
  if (target_state < static_cast<int>(WebMediaPlayer::kReadyStateHaveNothing) ||
      target_state >
          static_cast<int>(WebMediaPlayer::kReadyStateHaveEnoughData)) {
    return;
  }

  if (auto* wmp = media_element->GetWebMediaPlayer()) {
    wmp->ForceStaleStateForTesting(
        static_cast<WebMediaPlayer::ReadyState>(target_state));
  }
}

bool Internals::isMediaElementSuspended(HTMLMediaElement* media_element) {
  DCHECK(media_element);
  if (auto* wmp = media_element->GetWebMediaPlayer())
    return wmp->IsSuspendedForTesting();
  return false;
}

void Internals::setMediaControlsTestMode(HTMLMediaElement* media_element,
                                         bool enable) {
  DCHECK(media_element);
  MediaControls* media_controls = media_element->GetMediaControls();
  DCHECK(media_controls);
  media_controls->SetTestMode(enable);
}

void Internals::registerURLSchemeAsBypassingContentSecurityPolicy(
    const String& scheme) {
#if DCHECK_IS_ON()
  WTF::SetIsBeforeThreadCreatedForTest();  // Required for next operation:
#endif
  SchemeRegistry::RegisterURLSchemeAsBypassingContentSecurityPolicy(scheme);
}

void Internals::registerURLSchemeAsBypassingContentSecurityPolicy(
    const String& scheme,
    const Vector<String>& policy_areas) {
  uint32_t policy_areas_enum = SchemeRegistry::kPolicyAreaNone;
  for (const auto& policy_area : policy_areas) {
    if (policy_area == "img")
      policy_areas_enum |= SchemeRegistry::kPolicyAreaImage;
    else if (policy_area == "style")
      policy_areas_enum |= SchemeRegistry::kPolicyAreaStyle;
  }
#if DCHECK_IS_ON()
  WTF::SetIsBeforeThreadCreatedForTest();  // Required for next operation:
#endif
  SchemeRegistry::RegisterURLSchemeAsBypassingContentSecurityPolicy(
      scheme, static_cast<SchemeRegistry::PolicyAreas>(policy_areas_enum));
}

void Internals::removeURLSchemeRegisteredAsBypassingContentSecurityPolicy(
    const String& scheme) {
#if DCHECK_IS_ON()
  WTF::SetIsBeforeThreadCreatedForTest();  // Required for next operation:
#endif
  SchemeRegistry::RemoveURLSchemeRegisteredAsBypassingContentSecurityPolicy(
      scheme);
}

TypeConversions* Internals::typeConversions() const {
  return MakeGarbageCollected<TypeConversions>();
}

DictionaryTest* Internals::dictionaryTest() const {
  return MakeGarbageCollected<DictionaryTest>();
}

RecordTest* Internals::recordTest() const {
  return MakeGarbageCollected<RecordTest>();
}

SequenceTest* Internals::sequenceTest() const {
  return MakeGarbageCollected<SequenceTest>();
}

UnionTypesTest* Internals::unionTypesTest() const {
  return MakeGarbageCollected<UnionTypesTest>();
}

InternalsUkmRecorder* Internals::initializeUKMRecorder() {
  return MakeGarbageCollected<InternalsUkmRecorder>(document_);
}

OriginTrialsTest* Internals::originTrialsTest() const {
  return MakeGarbageCollected<OriginTrialsTest>();
}

CallbackFunctionTest* Internals::callbackFunctionTest() const {
  return MakeGarbageCollected<CallbackFunctionTest>();
}

Vector<String> Internals::getReferencedFilePaths() const {
  if (!GetFrame())
    return Vector<String>();

  return GetFrame()
      ->Loader()
      .GetDocumentLoader()
      ->GetHistoryItem()
      ->GetReferencedFilePaths();
}

void Internals::disableReferencedFilePathsVerification() const {
  if (!GetFrame())
    return;
  GetFrame()
      ->GetDocument()
      ->GetFormController()
      .SetDropReferencedFilePathsForTesting();
}

void Internals::startTrackingRepaints(Document* document,
                                      ExceptionState& exception_state) {
  DCHECK(document);
  if (!document->View()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidAccessError,
                                      "The document provided is invalid.");
    return;
  }

  LocalFrameView* frame_view = document->View();
  frame_view->UpdateAllLifecyclePhasesForTest();
  frame_view->SetTracksRasterInvalidations(true);
}

void Internals::stopTrackingRepaints(Document* document,
                                     ExceptionState& exception_state) {
  DCHECK(document);
  if (!document->View()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidAccessError,
                                      "The document provided is invalid.");
    return;
  }

  LocalFrameView* frame_view = document->View();
  frame_view->UpdateAllLifecyclePhasesForTest();
  frame_view->SetTracksRasterInvalidations(false);
}

void Internals::updateLayoutAndRunPostLayoutTasks(
    Node* node,
    ExceptionState& exception_state) {
  Document* document = nullptr;
  if (!node) {
    document = document_;
  } else if (auto* node_document = DynamicTo<Document>(node)) {
    document = node_document;
  } else if (auto* iframe = DynamicTo<HTMLIFrameElement>(*node)) {
    document = iframe->contentDocument();
  }

  if (!document) {
    exception_state.ThrowTypeError(
        "The node provided is neither a document nor an IFrame.");
    return;
  }
  document->UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  if (auto* view = document->View())
    view->FlushAnyPendingPostLayoutTasks();
}

void Internals::forceFullRepaint(Document* document,
                                 ExceptionState& exception_state) {
  DCHECK(document);
  if (!document->View()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidAccessError,
                                      "The document provided is invalid.");
    return;
  }

  if (auto* layout_view = document->GetLayoutView())
    layout_view->InvalidatePaintForViewAndDescendants();
}

DOMRectList* Internals::draggableRegions(Document* document,
                                         ExceptionState& exception_state) {
  return DraggableRegions(document, true, exception_state);
}

DOMRectList* Internals::nonDraggableRegions(Document* document,
                                            ExceptionState& exception_state) {
  return DraggableRegions(document, false, exception_state);
}

void Internals::SetSupportsDraggableRegions(bool supports_draggable_regions) {
  document_->GetPage()
      ->GetChromeClient()
      .GetWebView()
      ->SetSupportsDraggableRegions(supports_draggable_regions);
}

DOMRectList* Internals::DraggableRegions(Document* document,
                                         bool draggable,
                                         ExceptionState& exception_state) {
  DCHECK(document);
  if (!document->View()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidAccessError,
                                      "The document provided is invalid.");
    return MakeGarbageCollected<DOMRectList>();
  }

  document->UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  document->View()->UpdateDocumentDraggableRegions();
  Vector<DraggableRegionValue> regions = document->DraggableRegions();

  Vector<gfx::QuadF> quads;
  for (const DraggableRegionValue& region : regions) {
    if (region.draggable == draggable)
      quads.push_back(gfx::QuadF(gfx::RectF(region.bounds)));
  }
  return MakeGarbageCollected<DOMRectList>(quads);
}

static const char* CursorTypeToString(
    ui::mojom::blink::CursorType cursor_type) {
  switch (cursor_type) {
    case ui::mojom::blink::CursorType::kPointer:
      return "Pointer";
    case ui::mojom::blink::CursorType::kCross:
      return "Cross";
    case ui::mojom::blink::CursorType::kHand:
      return "Hand";
    case ui::mojom::blink::CursorType::kIBeam:
      return "IBeam";
    case ui::mojom::blink::CursorType::kWait:
      return "Wait";
    case ui::mojom::blink::CursorType::kHelp:
      return "Help";
    case ui::mojom::blink::CursorType::kEastResize:
      return "EastResize";
    case ui::mojom::blink::CursorType::kNorthResize:
      return "NorthResize";
    case ui::mojom::blink::CursorType::kNorthEastResize:
      return "NorthEastResize";
    case ui::mojom::blink::CursorType::kNorthWestResize:
      return "NorthWestResize";
    case ui::mojom::blink::CursorType::kSouthResize:
      return "SouthResize";
    case ui::mojom::blink::CursorType::kSouthEastResize:
      return "SouthEastResize";
    case ui::mojom::blink::CursorType::kSouthWestResize:
      return "SouthWestResize";
    case ui::mojom::blink::CursorType::kWestResize:
      return "WestResize";
    case ui::mojom::blink::CursorType::kNorthSouthResize:
      return "NorthSouthResize";
    case ui::mojom::blink::CursorType::kEastWestResize:
      return "EastWestResize";
    case ui::mojom::blink::CursorType::kNorthEastSouthWestResize:
      return "NorthEastSouthWestResize";
    case ui::mojom::blink::CursorType::kNorthWestSouthEastResize:
      return "NorthWestSouthEastResize";
    case ui::mojom::blink::CursorType::kColumnResize:
      return "ColumnResize";
    case ui::mojom::blink::CursorType::kRowResize:
      return "RowResize";
    case ui::mojom::blink::CursorType::kMiddlePanning:
      return "MiddlePanning";
    case ui::mojom::blink::CursorType::kMiddlePanningVertical:
      return "MiddlePanningVertical";
    case ui::mojom::blink::CursorType::kMiddlePanningHorizontal:
      return "MiddlePanningHorizontal";
    case ui::mojom::blink::CursorType::kEastPanning:
      return "EastPanning";
    case ui::mojom::blink::CursorType::kNorthPanning:
      return "NorthPanning";
    case ui::mojom::blink::CursorType::kNorthEastPanning:
      return "NorthEastPanning";
    case ui::mojom::blink::CursorType::kNorthWestPanning:
      return "NorthWestPanning";
    case ui::mojom::blink::CursorType::kSouthPanning:
      return "SouthPanning";
    case ui::mojom::blink::CursorType::kSouthEastPanning:
      return "SouthEastPanning";
    case ui::mojom::blink::CursorType::kSouthWestPanning:
      return "SouthWestPanning";
    case ui::mojom::blink::CursorType::kWestPanning:
      return "WestPanning";
    case ui::mojom::blink::CursorType::kMove:
      return "Move";
    case ui::mojom::blink::CursorType::kVerticalText:
      return "VerticalText";
    case ui::mojom::blink::CursorType::kCell:
      return "Cell";
    case ui::mojom::blink::CursorType::kContextMenu:
      return "ContextMenu";
    case ui::mojom::blink::CursorType::kAlias:
      return "Alias";
    case ui::mojom::blink::CursorType::kProgress:
      return "Progress";
    case ui::mojom::blink::CursorType::kNoDrop:
      return "NoDrop";
    case ui::mojom::blink::CursorType::kCopy:
      return "Copy";
    case ui::mojom::blink::CursorType::kNone:
      return "None";
    case ui::mojom::blink::CursorType::kNotAllowed:
      return "NotAllowed";
    case ui::mojom::blink::CursorType::kZoomIn:
      return "ZoomIn";
    case ui::mojom::blink::CursorType::kZoomOut:
      return "ZoomOut";
    case ui::mojom::blink::CursorType::kGrab:
      return "Grab";
    case ui::mojom::blink::CursorType::kGrabbing:
      return "Grabbing";
    case ui::mojom::blink::CursorType::kCustom:
      return "Custom";
    case ui::mojom::blink::CursorType::kNull:
      return "Null";
    case ui::mojom::blink::CursorType::kDndNone:
      return "DragAndDropNone";
    case ui::mojom::blink::CursorType::kDndMove:
      return "DragAndDropMove";
    case ui::mojom::blink::CursorType::kDndCopy:
      return "DragAndDropCopy";
    case ui::mojom::blink::CursorType::kDndLink:
      return "DragAndDropLink";
    case ui::mojom::blink::CursorType::kNorthSouthNoResize:
      return "NorthSouthNoResize";
    case ui::mojom::blink::CursorType::kEastWestNoResize:
      return "EastWestNoResize";
    case ui::mojom::blink::CursorType::kNorthEastSouthWestNoResize:
      return "NorthEastSouthWestNoResize";
    case ui::mojom::blink::CursorType::kNorthWestSouthEastNoResize:
      return "NorthWestSouthEastNoResize";
  }

  NOTREACHED();
}

String Internals::getCurrentCursorInfo() {
  if (!GetFrame())
    return String();

  ui::Cursor cursor =
      GetFrame()->GetPage()->GetChromeClient().LastSetCursorForTesting();

  StringBuilder result;
  result.Append("type=");
  result.Append(CursorTypeToString(cursor.type()));
  if (cursor.type() == ui::mojom::blink::CursorType::kCustom) {
    result.Append(" hotSpot=");
    result.AppendNumber(cursor.custom_hotspot().x());
    result.Append(',');
    result.AppendNumber(cursor.custom_hotspot().y());

    SkBitmap bitmap = cursor.custom_bitmap();
    DCHECK(!bitmap.isNull());
    result.Append(" image=");
    result.AppendNumber(bitmap.width());
    result.Append('x');
    result.AppendNumber(bitmap.height());

    if (cursor.image_scale_factor() != 1.0f) {
      result.Append(" scale=");
      result.AppendNumber(cursor.image_scale_factor(), 8);
    }
  }

  return result.ToString();
}

bool Internals::cursorUpdatePending() const {
  if (!GetFrame())
    return false;

  return GetFrame()->GetEventHandler().CursorUpdatePending();
}

DOMArrayBuffer* Internals::serializeObject(
    v8::Isolate* isolate,
    const ScriptValue& value,
    ExceptionState& exception_state) const {
  scoped_refptr<SerializedScriptValue> serialized_value =
      SerializedScriptValue::Serialize(
          isolate, value.V8Value(),
          SerializedScriptValue::SerializeOptions(
              SerializedScriptValue::kNotForStorage),
          exception_state);
  if (exception_state.HadException())
    return nullptr;

  base::span<const uint8_t> span = serialized_value->GetWireData();
  DOMArrayBuffer* buffer = DOMArrayBuffer::CreateUninitializedOrNull(
      base::checked_cast<uint32_t>(span.size()), sizeof(uint8_t));
  if (buffer)
    memcpy(buffer->Data(), span.data(), span.size());
  return buffer;
}

ScriptValue Internals::deserializeBuffer(v8::Isolate* isolate,
                                         DOMArrayBuffer* buffer) const {
  scoped_refptr<SerializedScriptValue> serialized_value =
      SerializedScriptValue::Create(base::make_span(
          static_cast<const uint8_t*>(buffer->Data()), buffer->ByteLength()));
  return ScriptValue(isolate, serialized_value->Deserialize(isolate));
}

void Internals::forceReload(bool bypass_cache) {
  if (!GetFrame())
    return;

  GetFrame()->Reload(bypass_cache ? WebFrameLoadType::kReloadBypassingCache
                                  : WebFrameLoadType::kReload);
}

StaticSelection* Internals::getDragCaret() {
  SelectionInDOMTree::Builder builder;
  if (GetFrame()) {
    const DragCaret& caret = GetFrame()->GetPage()->GetDragCaret();
    const PositionWithAffinity& position = caret.CaretPosition();
    if (position.GetDocument() == GetFrame()->GetDocument())
      builder.Collapse(caret.CaretPosition());
  }
  return StaticSelection::FromSelectionInDOMTree(builder.Build());
}

StaticSelection* Internals::getSelectionInFlatTree(
    DOMWindow* window,
    ExceptionState& exception_state) {
  Frame* const frame = window->GetFrame();
  auto* local_frame = DynamicTo<LocalFrame>(frame);
  if (!local_frame) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidAccessError,
                                      "Must supply local window");
    return nullptr;
  }
  return StaticSelection::FromSelectionInFlatTree(ConvertToSelectionInFlatTree(
      local_frame->Selection().GetSelectionInDOMTree()));
}

Node* Internals::visibleSelectionAnchorNode() {
  if (!GetFrame())
    return nullptr;
  GetFrame()->GetDocument()->UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  Position position =
      GetFrame()->Selection().ComputeVisibleSelectionInDOMTree().Anchor();
  return position.IsNull() ? nullptr : position.ComputeContainerNode();
}

unsigned Internals::visibleSelectionAnchorOffset() {
  if (!GetFrame())
    return 0;
  GetFrame()->GetDocument()->UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  Position position =
      GetFrame()->Selection().ComputeVisibleSelectionInDOMTree().Anchor();
  return position.IsNull() ? 0 : position.ComputeOffsetInContainerNode();
}

Node* Internals::visibleSelectionFocusNode() {
  if (!GetFrame())
    return nullptr;
  GetFrame()->GetDocument()->UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  Position position =
      GetFrame()->Selection().ComputeVisibleSelectionInDOMTree().Focus();
  return position.IsNull() ? nullptr : position.ComputeContainerNode();
}

unsigned Internals::visibleSelectionFocusOffset() {
  if (!GetFrame())
    return 0;
  GetFrame()->GetDocument()->UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  Position position =
      GetFrame()->Selection().ComputeVisibleSelectionInDOMTree().Focus();
  return position.IsNull() ? 0 : position.ComputeOffsetInContainerNode();
}

DOMRect* Internals::selectionBounds(ExceptionState& exception_state) {
  if (!GetFrame()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidAccessError,
        "The document's frame cannot be retrieved.");
    return nullptr;
  }

  GetFrame()->View()->UpdateLifecycleToLayoutClean(
      DocumentUpdateReason::kSelection);
  return DOMRect::FromRectF(
      gfx::RectF(GetFrame()->Selection().AbsoluteUnclippedBounds()));
}

String Internals::markerTextForListItem(Element* element) {
  DCHECK(element);
  return blink::MarkerTextForListItem(element);
}

String Internals::getImageSourceURL(Element* element) {
  DCHECK(element);
  return element->ImageSourceURL();
}

void Internals::forceImageReload(Element* element,
                                 ExceptionState& exception_state) {
  auto* html_image_element = DynamicTo<HTMLImageElement>(element);
  if (!html_image_element) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidAccessError,
        "The element should be HTMLImageElement.");
  }

  html_image_element->ForceReload();
}

String Internals::selectMenuListText(HTMLSelectElement* select) {
  DCHECK(select);
  if (!select->UsesMenuList())
    return String();
  return select->InnerElement().innerText();
}

bool Internals::isSelectPopupVisible(Node* node) {
  DCHECK(node);
  if (auto* select = DynamicTo<HTMLSelectElement>(*node))
    return select->PopupIsVisible();
  return false;
}

bool Internals::selectPopupItemStyleIsRtl(Node* node, int item_index) {
  auto* select = DynamicTo<HTMLSelectElement>(node);
  if (!select)
    return false;

  if (item_index < 0 ||
      static_cast<wtf_size_t>(item_index) >= select->GetListItems().size())
    return false;
  const ComputedStyle* item_style =
      select->ItemComputedStyle(*select->GetListItems()[item_index]);
  return item_style && item_style->Direction() == TextDirection::kRtl;
}

int Internals::selectPopupItemStyleFontHeight(Node* node, int item_index) {
  auto* select = DynamicTo<HTMLSelectElement>(node);
  if (!select)
    return false;

  if (item_index < 0 ||
      static_cast<wtf_size_t>(item_index) >= select->GetListItems().size())
    return false;
  const ComputedStyle* item_style =
      select->ItemComputedStyle(*select->GetListItems()[item_index]);

  if (item_style) {
    const SimpleFontData* font_data = item_style->GetFont().PrimaryFont();
    DCHECK(font_data);
    return font_data ? font_data->GetFontMetrics().Height() : 0;
  }
  return 0;
}

void Internals::resetTypeAheadSession(HTMLSelectElement* select) {
  DCHECK(select);
  select->ResetTypeAheadSessionForTesting();
}

void Internals::forceCompositingUpdate(Document* document,
                                       ExceptionState& exception_state) {
  DCHECK(document);
  if (!document->GetLayoutView()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidAccessError,
                                      "The document provided is invalid.");
    return;
  }

  document->GetFrame()->View()->UpdateAllLifecyclePhasesForTest();
}

void Internals::setForcedColorsAndDarkPreferredColorScheme(Document* document) {
  DCHECK(document);
  color_scheme_helper_.emplace(*document);
  color_scheme_helper_->SetPreferredColorScheme(
      mojom::blink::PreferredColorScheme::kDark);
  color_scheme_helper_->SetInForcedColors(*document, /*in_forced_colors=*/true);
  color_scheme_helper_->SetEmulatedForcedColors(*document,
                                                /*is_dark_theme=*/false);
}

void Internals::setDarkPreferredColorScheme(Document* document) {
  DCHECK(document);
  Settings* settings = document->GetSettings();
  settings->SetPreferredColorScheme(mojom::blink::PreferredColorScheme::kDark);
}

void Internals::setDarkPreferredRootScrollbarColorScheme(Document* document) {
  DCHECK(document);
  color_scheme_helper_.emplace(*document);
  color_scheme_helper_->SetPreferredRootScrollbarColorScheme(
      mojom::blink::PreferredColorScheme::kDark);
}

void Internals::setShouldRevealPassword(Element* element,
                                        bool reveal,
                                        ExceptionState& exception_state) {
  DCHECK(element);
  auto* html_input_element = DynamicTo<HTMLInputElement>(element);
  if (!html_input_element) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidNodeTypeError,
                                      "The element provided is not an INPUT.");
    return;
  }

  return html_input_element->SetShouldRevealPassword(reveal);
}

namespace {

class AddOneFunction : public ThenCallable<IDLLong, AddOneFunction, IDLLong> {
 public:
  int32_t React(ScriptState*, int32_t value) { return value + 1; }
};

class AddOneTypeMismatch
    : public ThenCallable<IDLAny, AddOneTypeMismatch, IDLAny> {
 public:
  ScriptValue React(ScriptState*, ScriptValue value) { return value; }
};

}  // namespace

ScriptPromise<IDLAny> Internals::createResolvedPromise(
    ScriptState* script_state,
    ScriptValue value) {
  return ToResolvedPromise<IDLAny>(script_state, value);
}

ScriptPromise<IDLAny> Internals::createRejectedPromise(
    ScriptState* script_state,
    ScriptValue value) {
  return ScriptPromise<IDLAny>::Reject(script_state, value);
}

ScriptPromise<IDLLong> Internals::addOneToPromise(
    ScriptState* script_state,
    ScriptPromise<IDLLong> promise) {
  return promise.Then(script_state, MakeGarbageCollected<AddOneFunction>(),
                      MakeGarbageCollected<AddOneTypeMismatch>());
}

ScriptPromise<IDLAny> Internals::promiseCheck(ScriptState* script_state,
                                              int32_t arg1,
                                              bool arg2,
                                              const ScriptValue& arg3,
                                              const String& arg4,
                                              const Vector<String>& arg5,
                                              ExceptionState& exception_state) {
  if (arg2) {
    return ToResolvedPromise<IDLAny>(
        script_state, V8String(script_state->GetIsolate(), "done"));
  }
  exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                    "Thrown from the native implementation.");
  return EmptyPromise();
}

ScriptPromise<IDLAny> Internals::promiseCheckWithoutExceptionState(
    ScriptState* script_state,
    const ScriptValue& arg1,
    const String& arg2,
    const Vector<String>& arg3) {
  return ToResolvedPromise<IDLAny>(
      script_state, V8String(script_state->GetIsolate(), "done"));
}

ScriptPromise<IDLAny> Internals::promiseCheckRange(ScriptState* script_state,
                                                   int32_t arg1) {
  return ToResolvedPromise<IDLAny>(
      script_state, V8String(script_state->GetIsolate(), "done"));
}

ScriptPromise<IDLAny> Internals::promiseCheckOverload(ScriptState* script_state,
                                                      Location*) {
  return ToResolvedPromise<IDLAny>(
      script_state, V8String(script_state->GetIsolate(), "done"));
}

ScriptPromise<IDLAny> Internals::promiseCheckOverload(ScriptState* script_state,
                                                      Document*) {
  return ToResolvedPromise<IDLAny>(
      script_state, V8String(script_state->GetIsolate(), "done"));
}

ScriptPromise<IDLAny> Internals::promiseCheckOverload(ScriptState* script_state,
                                                      Location*,
                                                      int32_t,
                                                      int32_t) {
  return ToResolvedPromise<IDLAny>(
      script_state, V8String(script_state->GetIsolate(), "done"));
}

void Internals::Trace(Visitor* visitor) const {
  visitor->Trace(runtime_flags_);
  visitor->Trace(document_);
  ScriptWrappable::Trace(visitor);
}

void Internals::setValueForUser(HTMLInputElement* element,
                                const String& value) {
  element->SetValueForUser(value);
}

void Internals::setFocused(bool focused) {
  if (!GetFrame())
    return;

  GetFrame()->GetPage()->GetFocusController().SetFocused(focused);
}

void Internals::setInitialFocus(bool reverse) {
  if (!GetFrame())
    return;

  GetFrame()->GetDocument()->ClearFocusedElement();
  GetFrame()->GetPage()->GetFocusController().SetInitialFocus(
      reverse ? mojom::blink::FocusType::kBackward
              : mojom::blink::FocusType::kForward);
}

bool Internals::isActivated() {
  if (!GetFrame())
    return false;

  return GetFrame()->GetPage()->GetFocusController().IsActive();
}

bool Internals::isInCanvasFontCache(Document* document,
                                    const String& font_string) {
  return document->GetCanvasFontCache()->IsInCache(font_string);
}

unsigned Internals::canvasFontCacheMaxFonts() {
  return CanvasFontCache::MaxFonts();
}

void Internals::forceLoseCanvasContext(CanvasRenderingContext* context) {
  context->LoseContext(CanvasRenderingContext::kSyntheticLostContext);
}

void Internals::disableCanvasAcceleration(HTMLCanvasElement* canvas) {
  canvas->DisableAcceleration();
}

String Internals::selectedHTMLForClipboard() {
  if (!GetFrame())
    return String();

  // Selection normalization and markup generation require clean layout.
  GetFrame()->GetDocument()->UpdateStyleAndLayout(DocumentUpdateReason::kTest);

  return GetFrame()->Selection().SelectedHTMLForClipboard();
}

String Internals::selectedTextForClipboard() {
  if (!GetFrame() || !GetFrame()->GetDocument())
    return String();

  // Clean layout is required for extracting plain text from selection.
  GetFrame()->GetDocument()->UpdateStyleAndLayout(DocumentUpdateReason::kTest);

  return GetFrame()->Selection().SelectedTextForClipboard();
}

void Internals::setVisualViewportOffset(int css_x, int css_y) {
  if (!GetFrame())
    return;
  float zoom = GetFrame()->LayoutZoomFactor();
  gfx::PointF offset(css_x * zoom, css_y * zoom);
  GetFrame()->GetPage()->GetVisualViewport().SetLocation(offset);
}

bool Internals::isUseCounted(Document* document, uint32_t feature) {
  if (feature > static_cast<int32_t>(WebFeature::kMaxValue)) {
    return false;
  }
  return document->IsUseCounted(static_cast<WebFeature>(feature));
}

bool Internals::isWebDXFeatureUseCounted(Document* document, uint32_t feature) {
  if (feature > static_cast<int32_t>(WebDXFeature::kMaxValue)) {
    return false;
  }
  return document->IsWebDXFeatureCounted(static_cast<WebDXFeature>(feature));
}

bool Internals::isCSSPropertyUseCounted(Document* document,
                                        const String& property_name) {
  return document->IsPropertyCounted(
      UnresolvedCSSPropertyID(document->GetExecutionContext(), property_name));
}

bool Internals::isAnimatedCSSPropertyUseCounted(Document* document,
                                                const String& property_name) {
  return document->IsAnimatedPropertyCounted(
      UnresolvedCSSPropertyID(document->GetExecutionContext(), property_name));
}

void Internals::clearUseCounter(Document* document, uint32_t feature) {
  if (feature > static_cast<int32_t>(WebFeature::kMaxValue)) {
    return;
  }
  document->ClearUseCounterForTesting(static_cast<WebFeature>(feature));
}

Vector<String> Internals::getCSSPropertyLonghands() const {
  Vector<String> result;
  for (CSSPropertyID property : CSSPropertyIDList()) {
    const CSSProperty& property_class = CSSProperty::Get(property);
    if (property_class.IsWebExposed(document_->GetExecutionContext()) &&
        property_class.IsLonghand()) {
      result.push_back(property_class.GetPropertyNameString());
    }
  }
  return result;
}

Vector<String> Internals::getCSSPropertyShorthands() const {
  Vector<String> result;
  for (CSSPropertyID property : CSSPropertyIDList()) {
    const CSSProperty& property_class = CSSProperty::Get(property);
    if (property_class.IsWebExposed(document_->GetExecutionContext()) &&
        property_class.IsShorthand()) {
  
"""


```