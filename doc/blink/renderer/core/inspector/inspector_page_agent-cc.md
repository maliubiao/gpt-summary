Response:
The user wants me to analyze a C++ source code file (`inspector_page_agent.cc`) from the Chromium Blink rendering engine.

Here's a plan to address the request:

1. **Identify the primary function of `InspectorPageAgent` based on its name and included headers.**
2. **Analyze how this component interacts with JavaScript, HTML, and CSS.** Provide specific examples based on the code.
3. **Look for logical reasoning within the code.**  Construct hypothetical inputs and outputs for such logic.
4. **Identify potential user or programming errors related to this component.**
5. **Summarize the functionality of the code based on the analysis.**
```c++
    search_query,
    bool case_sensitive,
    bool is_regex,
    std::unique_ptr<SearchContentCallback> callback) {
  LocalFrame* frame =
      IdentifiersFactory::FrameById(inspected_frames_, frame_id);
  if (!frame) {
    callback->sendFailure(
        protocol::Response::ServerError("No frame for given id found"));
    return;
  }

  const auto& resources = CachedResourcesForFrame(frame, false);
  int matches_count = 0;
  for (const auto& resource : resources) {
    String content;
    bool base64_encoded;
    if (!InspectorPageAgent::CachedResourceContent(resource.Get(), &content,
                                                    &base64_encoded))
      continue;

    if (is_regex) {
      ScriptRegexp regexp(search_query, case_sensitive ? kNoFlags : kIgnoreCase);
      if (regexp.IsValid()) {
        matches_count += regexp.MatchCount(content);
      }
    } else {
      String::FindIgnoringCaseMethod method =
          case_sensitive ? &String::find : &String::findIgnoringCase;
      size_t position = String::kNotFound;
      size_t start_position = 0;
      while ((position = (content.*method)(search_query, start_position)) !=
             String::kNotFound) {
        matches_count++;
        start_position = position + 1;
      }
    }
  }

  callback->sendSuccess(matches_count);
}

void InspectorPageAgent::searchInResource(
    const String& frame_id,
    const String& url,
    const String& search_query,
    bool case_sensitive,
    bool is_regex,
    std::unique_ptr<SearchInResourceCallback> callback) {
  LocalFrame* frame =
      IdentifiersFactory::FrameById(inspected_frames_, frame_id);
  if (!frame) {
    callback->sendFailure(
        protocol::Response::ServerError("No frame for given id found"));
    return;
  }

  String content;
  bool base64_encoded;
  if (!InspectorPageAgent::CachedResourceContent(
          CachedResource(frame, KURL(url), inspector_resource_content_loader_),
          &content, &base64_encoded)) {
    callback->sendFailure(
        protocol::Response::ServerError("No resource with given URL found"));
    return;
  }

  std::unique_ptr<protocol::Array<protocol::Page::SearchMatch>> result =
      std::make_unique<protocol::Array<protocol::Page::SearchMatch>>();
  if (is_regex) {
    ScriptRegexp regexp(search_query, case_sensitive ? kNoFlags : kIgnoreCase);
    if (regexp.IsValid()) {
      for (auto& match : regexp.Matches(content)) {
        result->emplace_back(protocol::Page::SearchMatch::create()
                                 .setLineNumber(0)
                                 .setLineContent(match)
                                 .build());
      }
    }
  } else {
    String::FindIgnoringCaseMethod method =
        case_sensitive ? &String::find : &String::findIgnoringCase;
    size_t position = String::kNotFound;
    size_t start_position = 0;
    while ((position = (content.*method)(search_query, start_position)) !=
           String::kNotFound) {
      result->emplace_back(protocol::Page::SearchMatch::create()
                               .setLineNumber(0)
                               .setLineContent(
                                   content.Substring(position, search_query.length()))
                               .build());
      start_position = position + 1;
    }
  }

  callback->sendSuccess(std::move(result));
}

void InspectorPageAgent::searchContent(
    const String& frame_id,
    const String& search_query,
    bool case_sensitive,
    bool is_regex,
    std::unique_ptr<SearchContentCallback> callback) {
  if (!enabled_.Get()) {
    callback->sendFailure(
        protocol::Response::ServerError("Agent is not enabled."));
    return;
  }
  inspector_resource_content_loader_->EnsureResourcesContentLoaded(
      resource_content_loader_client_id_,
      WTF::BindOnce(&InspectorPageAgent::SearchContentAfterResourcesContentLoaded,
                     WrapPersistent(this), frame_id, search_query,
                     case_sensitive, is_regex, std::move(callback)));
}

protocol::Response InspectorPageAgent::setBypassCSP(bool enabled) {
  bypass_csp_enabled_.Set(enabled);
  return protocol::Response::Success();
}

protocol::Response InspectorPageAgent::getNavigationHistory(
    std::unique_ptr<protocol::Page::NavigationHistory>* result,
    int* current_index) {
  Frame* frame = inspected_frames_->Root();
  if (!frame)
    return protocol::Response::InternalError();

  FrameLoader& loader = frame->Loader();
  *current_index = loader.GetHistory()->CurrentEntryIndex();

  auto entries = std::make_unique<protocol::Array<
      protocol::Page::NavigationEntry>>();

  for (int i = 0; i < loader.GetHistory()->Count(); ++i) {
    HistoryItem* item = loader.GetHistory()->GetEntryAtIndex(i);
    entries->emplace_back(
        protocol::Page::NavigationEntry::create()
            .setId(item->ItemSequenceNumber())
            .setUrl(item->Url().GetString())
            .setOriginalUrl(item->OriginalUrl().GetString())
            .setTitle(item->Title())
            .setState(item->StateObject())
            .build());
  }

  *result = protocol::Page::NavigationHistory::create()
                .setEntries(std::move(entries))
                .setCurrentIndex(*current_index)
                .build();

  return protocol::Response::Success();
}

protocol::Response InspectorPageAgent::navigateToHistoryEntry(int entry_id) {
  Frame* frame = inspected_frames_->Root();
  if (!frame)
    return protocol::Response::InternalError();

  FrameLoader& loader = frame->Loader();
  HistoryItem* item = HistoryItem::FindByItemSequenceNumber(entry_id);
  if (!item)
    return protocol::Response::ServerError("No history item with given id");

  loader.Load التاريخ(item);
  return protocol::Response::Success();
}

protocol::Response InspectorPageAgent::getCookies(
    Maybe<protocol::Array<String>> browser_cookie_names,
    std::unique_ptr<protocol::Array<protocol::Network::Cookie>>* cookies) {
  Document* document = inspected_frames_->Root()->GetDocument();
  if (!document)
    return protocol::Response::InternalError();

  *cookies = protocol::Network::Cookie::CreateArray();
  if (browser_cookie_names.has_value()) {
    for (const auto& cookie_name : browser_cookie_names.value()) {
      // TODO(crbug.com/1483466): implement getting platform cookies.
    }
  } else {
    for (const auto& cookie : document->Cookies(DoNotUpdateLastAccess)) {
      (*cookies)->emplace_back(InspectorNetworkAgent::BuildObjectForCookie(
          cookie, protocol::Network::CookieSource::COOKIES));
    }
  }

  return protocol::Response::Success();
}

protocol::Response InspectorPageAgent::deleteCookie(const String& cookie_name,
                                                   const String& url) {
  Document* document = inspected_frames_->Root()->GetDocument();
  if (!document)
    return protocol::Response::InternalError();

  document->DeleteCookie(cookie_name, KURL(url));
  return protocol::Response::Success();
}

protocol::Response InspectorPageAgent::getResourceContentForLoad(
    const String& frame_id,
    const String& url,
    std::unique_ptr<protocol::Page::ResourceContent>* content) {
  LocalFrame* frame =
      IdentifiersFactory::FrameById(inspected_frames_, frame_id);
  if (!frame) {
    return protocol::Response::ServerError("No frame for given id found");
  }

  String resource_content;
  bool base64_encoded;
  if (!InspectorPageAgent::CachedResourceContent(
          CachedResource(frame, KURL(url), inspector_resource_content_loader_),
          &resource_content, &base64_encoded)) {
    return protocol::Response::ServerError("No resource with given URL found");
  }

  *content = protocol::Page::ResourceContent::create()
                 .setContent(resource_content)
                 .setBase64Encoded(base64_encoded)
                 .build();

  return protocol::Response::Success();
}

protocol::Response InspectorPageAgent::layoutMetrics(
    std::unique_ptr<protocol::Page::LayoutViewport>* layout_viewport,
    std::unique_ptr<protocol::Page::VisualViewport>* visual_viewport,
    Maybe<float>* content_width,
    Maybe<float>* content_height,
    Maybe<float>* device_width,
    Maybe<float>* device_height) {
  LocalFrameView* frame_view = inspected_frames_->Root()->View();
  if (!frame_view)
    return protocol::Response::InternalError();

  *layout_viewport = protocol::Page::LayoutViewport::create()
                         .setPageX(0)
                         .setPageY(0)
                         .setWidth(adjustForAbsoluteZoom(
                             frame_view->LayoutWidth(), frame_view->Frame()))
                         .setHeight(adjustForAbsoluteZoom(
                             frame_view->LayoutHeight(), frame_view->Frame()))
                         .build();

  const VisualViewport& vp = inspected_frames_->Root()->VisualViewport();
  *visual_viewport =
      protocol::Page::VisualViewport::create()
          .setOffsetX(vp.ScrollLeft())
          .setOffsetY(vp.ScrollTop())
          .setPageX(vp.offsetLeft())
          .setPageY(vp.offsetTop())
          .setWidth(vp.offsetWidth())
          .setHeight(vp.offsetHeight())
          .setZoom(vp.ZoomFactor())
          .build();

  *content_width = adjustForAbsoluteZoom(
      frame_view->ContentsWidth(), frame_view->Frame());
  *content_height = adjustForAbsoluteZoom(
      frame_view->ContentsHeight(), frame_view->Frame());

  const display::ScreenInfo& screen_info =
      inspected_frames_->Root()->GetPage()->GetScreenInfo();
  *device_width = screen_info.GetWidth();
  *device_height = screen_info.GetHeight();

  return protocol::Response::Success();
}

protocol::Response InspectorPageAgent::createIsolatedWorld(
    Maybe<String> optional_frame_id,
    Maybe<String> optional_name,
    Maybe<bool> optional_use_globals_cache_from_main_world,
    int* execution_context_id) {
  LocalFrame* frame = inspected_frames_->Root();
  if (optional_frame_id.has_value()) {
    frame = IdentifiersFactory::FrameById(inspected_frames_,
                                           optional_frame_id.value());
    if (!frame)
      return protocol::Response::ServerError("No frame for given id found");
  }

  String world_name = optional_name.value_or("");
  bool use_globals_cache_from_main_world =
      optional_use_globals_cache_from_main_world.value_or(false);

  DomWrapperWorld& isolated_world =
      frame->Script().CreateIsolatedWorld(use_globals_cache_from_main_world);
  if (!world_name.IsNull())
    pending_isolated_worlds_.Set(&isolated_world, world_name);
  *execution_context_id = isolated_world.Context()->GetAgent()->ContextId();
  return protocol::Response::Success();
}

protocol::Response InspectorPageAgent::evaluateOnIsolatedWorld(
    const String& isolated_world_id,
    const String& script,
    Maybe<String> optional_url,
    Maybe<int> optional_line_number,
    Maybe<int> optional_column_number,
    Maybe<String> optional_object_group,
    Maybe<bool> optional_include_command_line_api,
    Maybe<bool> optional_silent,
    Maybe<int> optional_timeout,
    Maybe<bool> optional_return_by_value,
    Maybe<bool> optional_generate_preview,
    Maybe<bool> optional_await_promise,
    std::unique_ptr<protocol::Runtime::RemoteObject>* result,
    Maybe<protocol::Runtime::ExceptionDetails>* exception_details) {
  for (LocalFrame* frame : *inspected_frames_) {
    for (v8::Local<v8::Context> context : frame->Script().Contexts()) {
      if (pending_isolated_worlds_.Contains(
              DomWrapperWorld::From(v8::Isolate::GetCurrent(), context))) {
        if (pending_isolated_worlds_.Get(
                DomWrapperWorld::From(v8::Isolate::GetCurrent(), context)) ==
            isolated_world_id) {
          return v8_session_->evaluate(
              script, context, optional_object_group.value_or(""),
              optional_include_command_line_api.value_or(false),
              optional_silent.value_or(false),
              /* report_unhandled_exceptions_only */ false,
              optional_return_by_value.value_or(false),
              optional_generate_preview.value_or(false),
              optional_await_promise.value_or(false), result,
              exception_details, optional_timeout.value_or(0));
        }
      }
    }
  }
  return protocol::Response::ServerError("No isolated world with given id found");
}

void InspectorPageAgent::frameAttached(LocalFrame* frame) {
  client_->frameAttached(BuildObjectForFrame(frame));
}

void InspectorPageAgent::frameDetached(LocalFrame* frame,
                                        FrameDetachType type) {
  client_->frameDetached(frame->DevToolsId().ToString(),
                         FrameDetachTypeToProtocol(type));
  ad_script_identifiers_.erase(frame->DevToolsId().ToString());
}

void InspectorPageAgent::frameNavigated(LocalFrame* frame,
                                         mojom::SameDocumentNavigationType
                                             same_document_navigation_type) {
  client_->frameNavigated(BuildObjectForFrame(frame));
  if (same_document_navigation_type ==
      mojom::SameDocumentNavigationType::kReplaceState) {
    client_->frameContentUpdated(frame->DevToolsId().ToString());
  }
}

void InspectorPageAgent::frameStoppedLoading(LocalFrame* frame) {
  client_->frameStoppedLoading(frame->DevToolsId().ToString());
}

void InspectorPageAgent::frameResized() {
  client_->frameResized();
}

void InspectorPageAgent::frameScheduledNavigation(LocalFrame* frame,
                                                   double delay_seconds,
                                                   const KURL& url) {
  client_->frameScheduledNavigation(frame->DevToolsId().ToString(),
                                    delay_seconds);
}

void InspectorPageAgent::frameClearedScheduledNavigation(LocalFrame* frame) {
  client_->frameClearedScheduledNavigation(frame->DevToolsId().ToString());
}

void InspectorPageAgent::frame খেয়াল(LocalFrame* frame,
                                     const KURL& url,
                                     ClientNavigationReason reason,
                                     NavigationPolicy policy,
                                     const WebString& referrer,
                                     bool from_api) {
  client_->frameNavigatedWithinDocument(frame->DevToolsId().ToString(),
                                         url.GetString());
  client_->frame খেয়াল(frame->DevToolsId().ToString(), url.GetString(),
                       ClientNavigationReasonToProtocol(reason),
                       NavigationPolicyToProtocol(policy));
}

void InspectorPageAgent::document ओपन(LocalFrame* frame) {
  client_->frame খেয়াল(frame->DevToolsId().ToString(),
                       frame->GetDocument()->Url().GetString(),
                       protocol::Page::ClientNavigationReasonEnum::ScriptInitiated,
                       protocol::Page::ClientNavigationDispositionEnum::CurrentTab);
}

void InspectorPageAgent::domContentEventFired(LocalFrame* frame,
                                               double timestamp) {
  client_->domContentEventFired(timestamp);
}

void InspectorPageAgent::loadEventFired(LocalFrame* frame, double timestamp) {
  client_->loadEventFired(timestamp);
}

void InspectorPageAgent::LifecycleEvent(LocalFrame* frame,
                                          DocumentLoader* loader,
                                          const char* name,
                                          double timestamp) {
  if (!lifecycle_events_enabled_.Get())
    return;

  client_->lifecycleEvent(frame->DevToolsId().ToString(), name, timestamp);
}

void InspectorPageAgent::networkAlmostIdle(LocalFrame* frame, double timestamp) {
  LifecycleEvent(frame, frame->Loader().GetDocumentLoader(), "networkAlmostIdle",
                 timestamp);
}

void InspectorPageAgent::networkIdle(LocalFrame* frame, double timestamp) {
  LifecycleEvent(frame, frame->Loader().GetDocumentLoader(), "networkIdle",
                 timestamp);
}

void InspectorPageAgent::compilationCacheProduced(
    LocalFrame* frame,
    const String& url,
    base::span<const uint8_t> data) {
  String id = url + frame->DevToolsId().ToString();
  if (requested_compilation_cache_.Contains(id)) {
    compilation_cache_.Set(id, std::vector<uint8_t>(data.begin(), data.end()));
    requested_compilation_cache_.erase(id);
  }
}

void InspectorPageAgent::AdSubframeDetected(LocalFrame* frame,
                                            const FrameAdEvidence& ad_evidence) {
  std::unique_ptr<protocol::Page::AdFrameStatus> ad_frame_status =
      protocol::Page::AdFrameStatus::create()
          .setReporting(ad_evidence.reporting_status ==
                        mojom::AdEvidenceReportingStatus::kReported)
          .setThresholdState(
              static_cast<protocol::Page::AdFrameThresholdStateEnum>(
                  static_cast<int>(ad_evidence.threshold_state)))
          .build();

  std::unique_ptr<protocol::Page::AdFrameExplanation> ad_frame_explanation =
      protocol::Page::AdFrameExplanation::create()
          .setReason(protocol::Page::AdFrameExplanationReason::kCreated)
          .build();

  client_->frameAdChanged(frame->DevToolsId().ToString(), false,
                          std::move(ad_frame_status),
                          std::move(ad_frame_explanation));
}

void InspectorPageAgent::AdFrameোদিতChanged(
    LocalFrame* frame,
    mojom::AdFrameType ad_frame_type,
    const FrameAdEvidence& ad_evidence) {
  std::unique_ptr<protocol::Page::AdFrameStatus> ad_frame_status =
      protocol::Page::AdFrameStatus::create()
          .setReporting(ad_evidence.reporting_status ==
                        mojom::AdEvidenceReportingStatus::kReported)
          .setThresholdState(
              static_cast<protocol::Page::AdFrameThresholdStateEnum>(
                  static_cast<int>(ad_evidence.threshold_state)))
          .build();

  std::unique_ptr<protocol::Page::AdFrameExplanation> ad_frame_explanation;
  if (ad_frame_type == mojom::AdFrameType::kChildFrame) {
    ad_frame_explanation =
        protocol::Page::AdFrameExplanation::create()
            .setReason(
                protocol::Page::AdFrameExplanationReason::kChildFrameIsAd)
            .build();
  } else if (ad_frame_type == mojom::AdFrameType::kMatchedAncestor) {
    ad_frame_explanation =
        protocol::Page::AdFrameExplanation::create()
            .setReason(
                protocol::Page::AdFrameExplanationReason::kMatchedAncestorIsAd)
            .build();
  }

  client_->frameAdChanged(frame->DevToolsId().ToString(), true,
                          std::move(ad_frame_status),
                          std::move(ad_frame_explanation));
}

void InspectorPageAgent::AdScriptDetected(
    LocalFrame* frame,
    const ExecutionContextId& context_id) {
  int id = ad_script_identifiers_.size() + 1;
  ad_script_identifiers_.Set(frame->DevToolsId().ToString(),
                            AdScriptIdentifier(id, context_id));
}

std::unique_ptr<protocol::Page::FrameResourceTree>
InspectorPageAgent::BuildObjectForResourceTree(LocalFrame* frame) {
  auto resource_tree = protocol::Page::FrameResourceTree::create()
                           .setFrame(BuildObjectForFrame(frame))
                           .build();

  auto resources = protocol::Array<protocol::Page::FrameResource>::create();
  for (const auto& resource : CachedResourcesForFrame(frame, false)) {
    resources->emplace_back(BuildObjectForCachedResource(resource.Get(), frame));
  }
  resource_tree->setResources(std::move(resources));

  for (LocalFrame* child_frame = frame->Tree().FirstChild(); child_frame;
       child_frame = child_frame->Tree().NextSibling()) {
    resource_tree->addChildFrames(BuildObjectForResourceTree(child_frame));
  }

  return resource_tree;
}

std::unique_ptr<protocol::Page::FrameTree>
InspectorPageAgent::BuildObjectForFrameTree(LocalFrame* frame) {
  auto frame_tree = protocol::Page::FrameTree::create()
                        .setFrame(BuildObjectForFrame(frame))
                        .build();

  for (LocalFrame* child_frame = frame->Tree().FirstChild(); child_frame;
       child_frame = child_frame->Tree().NextSibling()) {
    frame_tree->addChildFrames(BuildObjectForFrameTree(child_frame));
  }

  return frame_tree;
}

std::unique_ptr<protocol::Page::Frame> InspectorPageAgent::BuildObjectForFrame(
    LocalFrame* frame) {
  auto frame_object = protocol::Page::Frame::create()
                          .setId(frame->DevToolsId().ToString())
                          .setUrl(frame->GetDocument()->Url().GetString())
                          .setSecurityOrigin(frame->GetSecurityOrigin().ToString())
                          .setMimeType(frame->Loader().GetDocumentLoader()->ResponseMimeType())
                          .build();
  if (frame->Opener())
    frame_object->setOpenerId(frame->Opener()->DevToolsId().ToString());
  if (frame->Parent())
    frame_object->setParentId(frame->Parent()->DevToolsId().ToString());
  if (frame->IsAdFrame()) {
    auto ad_frame_type = frame->Is корневаяAdFrame()
                            ? protocol::Page::AdFrameTypeEnum::Root
                            : protocol::Page::AdFrameTypeEnum::Child;
    frame_object->setAdFrameType(ad_frame_type);
  }
  return frame_object;
}

std::unique_ptr<protocol::Page::FrameResource>
InspectorPageAgent::BuildObjectForCachedResource(const Resource* resource,
                                                LocalFrame* frame) {
  auto resource_object =
      protocol::Page::FrameResource::create()
          .setUrl(UrlWithoutFragment(resource->GetURL()).GetString())
          .setType(CachedResourceTypeJson(*resource))
          .setMimeType(resource->GetResponse().MimeType())
          .setLastModified(
              static_cast<double>(resource->LastModified().ToTimeT()))
          .set সবুজ(resource->EncodedSize())
          .build();
  if (frame)
    resource_object->setFrameId(frame->DevToolsId().ToString());
  String content_encoding = resource->GetResponse().HttpHeaderField(
      HTTPNames::Content_Encoding);
  if (!content_encoding.IsNull())
    resource_object->setEncoding(content_encoding);
  return resource_object;
}

void InspectorPageAgent::EvaluateScriptOnNewDocument(LocalFrame& frame,
                                                      const String& identifier) {
  ScriptController& script_controller = frame.Script();
  if (v8::Local<v8::Context> context = script_controller.GetContext()) {
    v8_session_->add будущемScript(
        scripts_to_evaluate_on_load_.Get(identifier), context,
        worlds_to_evaluate_on_load_.Get(identifier),
        include_command_line_api_for_scripts_to_evaluate_on_load_.Get(
            identifier));
  }
}

void InspectorPageAgent::documentOpened(Document& document) {
  for (KeyValuePair<String, String> const& script :
       scripts_to_evaluate_on_load_) {
    EvaluateScriptOnNewDocument(*document.GetFrame(), script.key);
  }
}

void InspectorPageAgent::SetFontFamilies(
    GenericFontFamilySettings& family_settings,
    const protocol::Array<protocol::Page::FontFamilies>& font_families) {
  for (const auto& font_family : font_families) {
    UScriptCode script_code =
        UScript::forName(font_family->getScript().utf8().data());
    if (font_family->hasStandard())
      family_settings.SetStandard(script_code, font_family->getStandard());
    if (font_family->hasFixed())
      family_settings.SetFixed(script_code, font_family->getFixed());
    if (font_family->hasSerif())
      family_settings.SetSerif(script_code, font_family->getSerif());
    if (font_family->hasSansSerif())
      family_settings.SetSansSerif(script_code, font_family->getSansSerif());
    if (font_family->hasCursive())
      family_settings.SetCursive(script_code, font_family->getCursive());
    if (font_family->hasFantasy())
      family_settings.SetFantasy(script_code, font_family->getFantasy());
    if (font_family->hasPictorial())
      family_settings.SetPictorial(script_code, font_family->getPictorial());
  }
}

void InspectorPageAgent::setFontFamilies(
    const GenericFontFamilySettings& old_settings,
    const protocol::Array<protocol::Page::ScriptFontFamilies>&
        script_font_families) {
  GenericFontFamilySettings new_settings = old_settings;
  for (const auto& script_font_family : script_font_families) {
    UScriptCode script_code =
        UScript::forName(script_font_family->getScript().utf8().data());
    const auto& font_families = script_font_family->getFontFamilies();
    if (font_families->hasStandard())
      new_settings.SetStandard(script_code, font_families->getStandard());
    if (font_families->hasFixed())
      new_settings.SetFixed(script_code, font_families->getFixed());
    if (font_families->hasSerif())
      new_settings.SetSerif(script_code, font_families->getSerif());
    if (font_families->hasSansSerif())
      new_settings.SetSansSerif(script_code, font_families->getSansSerif());
    if (font_families->hasCursive())
      new_settings.SetCursive(script_code, font_families->getCursive());
    if (font_families->hasFantasy())
      new_settings.SetFantasy(script_code, font_families->getFantasy());
    if (font_families->hasPictorial())
      new_settings.SetPictorial(script_code, font_families->getPictorial());
  }

  Vector<uint8_t> serialized_settings;
  crdtp::Serializer serializer(&serialized_settings);
  bool result = crdtp::ProtocolTypeTraits<
      protocol::Array<protocol::Page::ScriptFontFamilies>>::Serialize(
      &serializer, script_font_families);
  DCHECK(result);
  script_font_families_cbor_.Set(serialized_settings);
  inspected_frames_->Root()->GetSettings()->SetGenericFontFamilySettings(
      new_settings);
}

protocol::Response InspectorPageAgent::setFontFamilies(
    const protocol::Array<protocol::Page::ScriptFontFamilies>&
        font_families) {
  auto* settings = inspected_frames_->Root()->GetSettings();
  if (!settings)
    return protocol::Response::InternalError();
  setFontFamilies(settings->GetGenericFontFamilySettings(), font_families);
  settings->NotifyGenericFontFamilyChange();
  return protocol::Response::Success();
}

protocol::Response InspectorPageAgent::setFontSizes(int standard_font_size,
                                                    int fixed_font_size) {
  auto* settings = inspected_frames_->Root()->GetSettings();
  if (!settings)
    return protocol::Response::InternalError();
  standard_font_size_.Set(standard_font_size);
  fixed_font_size_.Set(fixed_font_size);
  settings->SetDefaultFontSize(standard_font_size);
  settings->SetDefaultFixedFontSize(fixed_font_size);
  return protocol::Response::Success();
}

}  // namespace blink
```

### 功能列举

`InspectorPageAgent` 的主要功能是作为 Blink 渲染引擎与 Chrome DevTools 的 Page 域之间的桥梁。它允许开发者通过 DevTools 的 Page 面板与页面的各种方面进行交互和监控。 具体来说，它负责：

1. **管理和提供页面结构信息:**
    *   报告页面的帧树 (frame tree) 结构，包括 iframe。
    *   报告每个帧加载的资源 (资源树, resource tree)。
    *   提供帧的详细信息，如 ID、URL、安全源和 MIME 类型。
2. **处理页面加载和导航:**
    *   触发页面重新加载，可以选择绕过缓存。
    *   停止页面加载。
    *   获取和操作浏览历史记录。
    *   报告帧的导航事件，包括导航原因和策略。
    *   报告 DOMContentLoaded 和 load 事件。
    *   报告自定义的生命周期事件 (lifecycle events)。
3. **注入和执行 JavaScript 代码:**
    *   在新的文档加载时注入脚本。
    *   在隔离的 JavaScript 环境 (isolated world) 中执行脚本。
    *   在页面重新加载时执行脚本。
4. **检查和搜索资源内容:**
    *   获取指定帧和 URL 的资源内容。
    *   在指定帧的所有资源中搜索内容。
    *   在指定的资源中搜索内容。
5. **管理 Cookie:**
    *   获取页面的 Cookie。
    *   删除指定的 Cookie。
6. **提供布局和视口信息:**
    *   获取布局视口 (layout viewport) 和视觉视口 (visual viewport) 的指标。
    *   获取内容和设备的宽高。
7. **支持广告检测:**
    *   报告检测到的广告子帧 (ad subframe)。
    *   报告广告帧的类型变化。
    *   报告检测到的广告脚本 (ad script)。
8. **控制页面行为:**
    *   启用/禁用页面域的调试功能。
    *   绕过内容安全策略 (CSP)。
    *   设置是否启用广告拦截。
9. **处理字体设置:**
    *   设置不同脚本的字体族 (font families)。
    *   设置默认字体大小。
10. **支持截屏 (在提供的代码片段中未完整显示):**  虽然代码片段中 `stopScreencast()` 表明有截屏相关功能，但具体实现未包含在此部分。
11. **处理编译缓存 (compilation cache):**  接收并存储 JavaScript 编译缓存。
12. **创建隔离的 JavaScript 上下文 (isolated world):**  允许在与页面主上下文隔离的环境中执行 JavaScript。

### 与 JavaScript, HTML, CSS 的关系及举例说明

`InspectorPageAgent` 紧密地与 JavaScript, HTML, 和 CSS 功能相关，因为它负责提供 DevTools 与这些 Web 技术交互的能力。

*   **JavaScript:**
    *   **代码注入:** `addScriptToEvaluateOnNewDocument` 和 `addScriptToEvaluateOnLoad` 允许在页面加载时注入 JavaScript 代码。 这使得开发者可以在页面加载的早期阶段执行脚本，例如修改全局对象或设置断点。
        *   **假设输入:** 调用 `addScriptToEvaluateOnNewDocument`，`source` 参数为 `console.log('Hello from injected script!');`。
        *   **输出:**  在后续加载的页面中，浏览器的控制台会输出 "Hello from injected script!"。
    *   **代码执行:** `evaluateOnIsolatedWorld` 允许在特定的 JavaScript 上下文（例如，一个扩展的 content script 的上下文）中执行任意 JavaScript 代码。
        *   **假设输入:** 调用 `evaluateOnIsolatedWorld`，`script` 参数为 `document.body.style.backgroundColor = 'red';`。
        *   **输出:** 如果执行成功，目标隔离环境的 `document.body` 的背景色将变为红色。
    *   **获取资源内容:** 可以获取 JavaScript 文件的内容，用于查看和调试。 `getResourceContent` 可以获取 URL 指向的 JavaScript 文件的源代码。
    *   **广告脚本检测:** 识别页面中被认为是广告的脚本。

*   **HTML:**
    *   **页面结构检查:** `getResourceTree` 和 `getFrameTree` 可以检索页面的 DOM 结构（通过帧来组织），这直接反映了 HTML 的结构。
    *   **资源加载检查:**  可以查看页面加载的 HTML 文件以及其他资源（如图片、脚本、样式表）。
    *   **DOM 事件:** 报告 `domContentEventFired` 和 `loadEventFired`，这些事件是 HTML 文档加载过程中的关键时刻。
    *   **Frame 操作:** 报告帧的附加 (`frameAttached`) 和分离 (`frameDetached`)，这与 HTML 中 `<iframe>` 元素的创建和移除相关。
    *   **导航:** 跟踪页面的导航事件，这些事件可能由 HTML 中的链接点击或表单提交触发。

*   **CSS:**
    *   **样式表检查:** 可以获取 CSS 文件的内容，用于查看和调试样式规则。 `getResourceContent` 可以获取 URL 指向的 CSS 文件的源代码。

### 提示词
```
这是目录为blink/renderer/core/inspector/inspector_page_agent.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
/*
 * Copyright (C) 2011 Google Inc. All rights reserved.
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

#include "third_party/blink/renderer/core/inspector/inspector_page_agent.h"

#include <memory>
#include <optional>
#include <utility>

#include "base/containers/span.h"
#include "base/numerics/safe_conversions.h"
#include "build/build_config.h"
#include "third_party/blink/public/common/frame/frame_ad_evidence.h"
#include "third_party/blink/public/common/origin_trials/trial_token.h"
#include "third_party/blink/public/common/web_preferences/web_preferences.h"
#include "third_party/blink/public/mojom/ad_tagging/ad_evidence.mojom-blink.h"
#include "third_party/blink/public/mojom/loader/same_document_navigation_type.mojom-blink.h"
#include "third_party/blink/renderer/bindings/core/v8/local_window_proxy.h"
#include "third_party/blink/renderer/bindings/core/v8/script_controller.h"
#include "third_party/blink/renderer/bindings/core/v8/script_evaluation_result.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/document_timing.h"
#include "third_party/blink/renderer/core/dom/dom_node_ids.h"
#include "third_party/blink/renderer/core/execution_context/agent.h"
#include "third_party/blink/renderer/core/frame/ad_tracker.h"
#include "third_party/blink/renderer/core/frame/frame.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_client.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/report.h"
#include "third_party/blink/renderer/core/frame/reporting_context.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/frame/test_report_body.h"
#include "third_party/blink/renderer/core/frame/visual_viewport.h"
#include "third_party/blink/renderer/core/html/forms/html_input_element.h"
#include "third_party/blink/renderer/core/html/html_frame_owner_element.h"
#include "third_party/blink/renderer/core/html/parser/text_resource_decoder.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/inspector/identifiers_factory.h"
#include "third_party/blink/renderer/core/inspector/inspected_frames.h"
#include "third_party/blink/renderer/core/inspector/inspector_css_agent.h"
#include "third_party/blink/renderer/core/inspector/inspector_resource_content_loader.h"
#include "third_party/blink/renderer/core/inspector/v8_inspector_string.h"
#include "third_party/blink/renderer/core/layout/adjust_for_absolute_zoom.h"
#include "third_party/blink/renderer/core/loader/document_loader.h"
#include "third_party/blink/renderer/core/loader/frame_loader.h"
#include "third_party/blink/renderer/core/loader/idleness_detector.h"
#include "third_party/blink/renderer/core/loader/resource/css_style_sheet_resource.h"
#include "third_party/blink/renderer/core/loader/resource/script_resource.h"
#include "third_party/blink/renderer/core/origin_trials/origin_trial_context.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/paint/paint_layer_scrollable_area.h"
#include "third_party/blink/renderer/core/permissions_policy/permissions_policy_devtools_support.h"
#include "third_party/blink/renderer/core/probe/core_probes.h"
#include "third_party/blink/renderer/core/script/classic_script.h"
#include "third_party/blink/renderer/core/style/computed_style.h"
#include "third_party/blink/renderer/platform/bindings/dom_wrapper_world.h"
#include "third_party/blink/renderer/platform/bindings/script_regexp.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/loader/fetch/memory_cache.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_fetcher.h"
#include "third_party/blink/renderer/platform/loader/fetch/text_resource_decoder_options.h"
#include "third_party/blink/renderer/platform/network/mime/mime_type_registry.h"
#include "third_party/blink/renderer/platform/network/network_utils.h"
#include "third_party/blink/renderer/platform/text/locale_to_script_mapping.h"
#include "third_party/blink/renderer/platform/weborigin/security_origin.h"
#include "third_party/blink/renderer/platform/wtf/text/base64.h"
#include "third_party/blink/renderer/platform/wtf/text/string_utf8_adaptor.h"
#include "third_party/blink/renderer/platform/wtf/text/text_encoding.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"
#include "third_party/inspector_protocol/crdtp/protocol_core.h"
#include "ui/display/screen_info.h"
#include "v8/include/v8-inspector.h"

namespace blink {

namespace {

String ClientNavigationReasonToProtocol(ClientNavigationReason reason) {
  namespace ReasonEnum = protocol::Page::ClientNavigationReasonEnum;
  switch (reason) {
    case ClientNavigationReason::kAnchorClick:
      return ReasonEnum::AnchorClick;
    case ClientNavigationReason::kFormSubmissionGet:
      return ReasonEnum::FormSubmissionGet;
    case ClientNavigationReason::kFormSubmissionPost:
      return ReasonEnum::FormSubmissionPost;
    case ClientNavigationReason::kHttpHeaderRefresh:
      return ReasonEnum::HttpHeaderRefresh;
    case ClientNavigationReason::kFrameNavigation:
      return ReasonEnum::ScriptInitiated;
    case ClientNavigationReason::kInitialFrameNavigation:
      return ReasonEnum::InitialFrameNavigation;
    case ClientNavigationReason::kMetaTagRefresh:
      return ReasonEnum::MetaTagRefresh;
    case ClientNavigationReason::kPageBlock:
      return ReasonEnum::PageBlockInterstitial;
    case ClientNavigationReason::kReload:
      return ReasonEnum::Reload;
    case ClientNavigationReason::kNone:
      return ReasonEnum::Other;
  }
}

String NavigationPolicyToProtocol(NavigationPolicy policy) {
  namespace DispositionEnum = protocol::Page::ClientNavigationDispositionEnum;
  switch (policy) {
    case kNavigationPolicyDownload:
      return DispositionEnum::Download;
    case kNavigationPolicyCurrentTab:
      return DispositionEnum::CurrentTab;
    case kNavigationPolicyNewBackgroundTab:
      return DispositionEnum::NewTab;
    case kNavigationPolicyNewForegroundTab:
      return DispositionEnum::NewTab;
    case kNavigationPolicyNewWindow:
      return DispositionEnum::NewWindow;
    case kNavigationPolicyNewPopup:
      return DispositionEnum::NewWindow;
    case kNavigationPolicyPictureInPicture:
      return DispositionEnum::NewWindow;
    case kNavigationPolicyLinkPreview:
      NOTREACHED();
  }
  return DispositionEnum::CurrentTab;
}

String FrameDetachTypeToProtocol(FrameDetachType type) {
  namespace ReasonEnum = protocol::Page::FrameDetached::ReasonEnum;
  switch (type) {
    case FrameDetachType::kRemove:
      return ReasonEnum::Remove;
    case FrameDetachType::kSwap:
      return ReasonEnum::Swap;
  }
}

Resource* CachedResource(LocalFrame* frame,
                         const KURL& url,
                         InspectorResourceContentLoader* loader) {
  Document* document = frame->GetDocument();
  if (!document)
    return nullptr;
  Resource* cached_resource = document->Fetcher()->CachedResource(url);
  if (!cached_resource) {
    cached_resource = MemoryCache::Get()->ResourceForURL(
        url, document->Fetcher()->GetCacheIdentifier(
                 url, /*skip_service_worker=*/false));
  }
  if (!cached_resource)
    cached_resource = loader->ResourceForURL(url);
  return cached_resource;
}

std::unique_ptr<protocol::Array<String>> GetEnabledWindowFeatures(
    const WebWindowFeatures& window_features) {
  auto feature_strings = std::make_unique<protocol::Array<String>>();
  if (window_features.x_set) {
    feature_strings->emplace_back(
        String::Format("left=%d", static_cast<int>(window_features.x)));
  }
  if (window_features.y_set) {
    feature_strings->emplace_back(
        String::Format("top=%d", static_cast<int>(window_features.y)));
  }
  if (window_features.width_set) {
    feature_strings->emplace_back(
        String::Format("width=%d", static_cast<int>(window_features.width)));
  }
  if (window_features.height_set) {
    feature_strings->emplace_back(
        String::Format("height=%d", static_cast<int>(window_features.height)));
  }
  if (!window_features.is_popup) {
    feature_strings->emplace_back("menubar");
    feature_strings->emplace_back("toolbar");
    feature_strings->emplace_back("status");
    feature_strings->emplace_back("scrollbars");
  }
  if (window_features.resizable)
    feature_strings->emplace_back("resizable");
  if (window_features.noopener)
    feature_strings->emplace_back("noopener");
  if (window_features.explicit_opener) {
    feature_strings->emplace_back("opener");
  }
  if (window_features.background)
    feature_strings->emplace_back("background");
  if (window_features.persistent)
    feature_strings->emplace_back("persistent");
  return feature_strings;
}

}  // namespace

static bool PrepareResourceBuffer(const Resource* cached_resource,
                                  bool* has_zero_size) {
  if (!cached_resource)
    return false;

  if (cached_resource->GetDataBufferingPolicy() == kDoNotBufferData)
    return false;

  // Zero-sized resources don't have data at all -- so fake the empty buffer,
  // instead of indicating error by returning 0.
  if (!cached_resource->EncodedSize()) {
    *has_zero_size = true;
    return true;
  }

  *has_zero_size = false;
  return true;
}

static bool HasTextContent(const Resource* cached_resource) {
  ResourceType type = cached_resource->GetType();
  return type == ResourceType::kCSSStyleSheet ||
         type == ResourceType::kXSLStyleSheet ||
         type == ResourceType::kScript || type == ResourceType::kRaw;
}

static std::unique_ptr<TextResourceDecoder> CreateResourceTextDecoder(
    const String& mime_type,
    const String& text_encoding_name) {
  if (!text_encoding_name.empty()) {
    return std::make_unique<TextResourceDecoder>(TextResourceDecoderOptions(
        TextResourceDecoderOptions::kPlainTextContent,
        WTF::TextEncoding(text_encoding_name)));
  }
  if (MIMETypeRegistry::IsXMLMIMEType(mime_type)) {
    TextResourceDecoderOptions options(TextResourceDecoderOptions::kXMLContent);
    options.SetUseLenientXMLDecoding();
    return std::make_unique<TextResourceDecoder>(options);
  }
  if (EqualIgnoringASCIICase(mime_type, "text/html")) {
    return std::make_unique<TextResourceDecoder>(TextResourceDecoderOptions(
        TextResourceDecoderOptions::kHTMLContent, UTF8Encoding()));
  }
  if (MIMETypeRegistry::IsSupportedJavaScriptMIMEType(mime_type) ||
      MIMETypeRegistry::IsJSONMimeType(mime_type)) {
    return std::make_unique<TextResourceDecoder>(TextResourceDecoderOptions(
        TextResourceDecoderOptions::kPlainTextContent, UTF8Encoding()));
  }
  if (MIMETypeRegistry::IsPlainTextMIMEType(mime_type)) {
    return std::make_unique<TextResourceDecoder>(TextResourceDecoderOptions(
        TextResourceDecoderOptions::kPlainTextContent,
        WTF::TextEncoding("ISO-8859-1")));
  }
  return std::unique_ptr<TextResourceDecoder>();
}

static void MaybeEncodeTextContent(const String& text_content,
                                   base::span<const uint8_t> buffer,
                                   String* result,
                                   bool* base64_encoded) {
  if (!text_content.IsNull()) {
    *result = text_content;
    *base64_encoded = false;
  } else if (buffer.data()) {
    *result = Base64Encode(buffer);
    *base64_encoded = true;
  } else {
    *result = "";
    *base64_encoded = false;
  }
}

static void MaybeEncodeTextContent(const String& text_content,
                                   scoped_refptr<const SharedBuffer> buffer,
                                   String* result,
                                   bool* base64_encoded) {
  if (!buffer) {
    const base::span<const uint8_t> empty;
    return MaybeEncodeTextContent(text_content, empty, result, base64_encoded);
  }

  const SegmentedBuffer::DeprecatedFlatData flat_buffer(buffer.get());
  return MaybeEncodeTextContent(text_content, base::as_byte_span(flat_buffer),
                                result, base64_encoded);
}

// static
KURL InspectorPageAgent::UrlWithoutFragment(const KURL& url) {
  KURL result = url;
  result.RemoveFragmentIdentifier();
  return result;
}

// static
bool InspectorPageAgent::SegmentedBufferContent(
    const SegmentedBuffer* buffer,
    const String& mime_type,
    const String& text_encoding_name,
    String* result,
    bool* base64_encoded) {
  if (!buffer)
    return false;

  String text_content;
  std::unique_ptr<TextResourceDecoder> decoder =
      CreateResourceTextDecoder(mime_type, text_encoding_name);
  WTF::TextEncoding encoding(text_encoding_name);

  const SegmentedBuffer::DeprecatedFlatData flat_buffer(buffer);
  const auto byte_buffer = base::as_byte_span(flat_buffer);
  if (decoder) {
    text_content = decoder->Decode(byte_buffer);
    text_content = text_content + decoder->Flush();
  } else if (encoding.IsValid()) {
    text_content = encoding.Decode(byte_buffer);
  }

  MaybeEncodeTextContent(text_content, byte_buffer, result, base64_encoded);
  return true;
}

// static
bool InspectorPageAgent::CachedResourceContent(const Resource* cached_resource,
                                               String* result,
                                               bool* base64_encoded) {
  bool has_zero_size;
  if (!PrepareResourceBuffer(cached_resource, &has_zero_size))
    return false;

  if (!HasTextContent(cached_resource)) {
    scoped_refptr<const SharedBuffer> buffer =
        has_zero_size ? SharedBuffer::Create()
                      : cached_resource->ResourceBuffer();
    if (!buffer)
      return false;

    const SegmentedBuffer::DeprecatedFlatData flat_buffer(buffer.get());
    *result = Base64Encode(base::as_byte_span(flat_buffer));
    *base64_encoded = true;
    return true;
  }

  if (has_zero_size) {
    *result = "";
    *base64_encoded = false;
    return true;
  }

  DCHECK(cached_resource);
  switch (cached_resource->GetType()) {
    case blink::ResourceType::kCSSStyleSheet:
      MaybeEncodeTextContent(
          To<CSSStyleSheetResource>(cached_resource)
              ->SheetText(nullptr, CSSStyleSheetResource::MIMETypeCheck::kLax),
          cached_resource->ResourceBuffer(), result, base64_encoded);
      return true;
    case blink::ResourceType::kScript:
      MaybeEncodeTextContent(
          To<ScriptResource>(cached_resource)->TextForInspector(),
          cached_resource->ResourceBuffer(), result, base64_encoded);
      return true;
    default:
      String text_encoding_name =
          cached_resource->GetResponse().TextEncodingName();
      if (text_encoding_name.empty() &&
          cached_resource->GetType() != blink::ResourceType::kRaw)
        text_encoding_name = "WinLatin1";
      return InspectorPageAgent::SegmentedBufferContent(
          cached_resource->ResourceBuffer().get(),
          cached_resource->GetResponse().MimeType(), text_encoding_name, result,
          base64_encoded);
  }
}

String InspectorPageAgent::ResourceTypeJson(
    InspectorPageAgent::ResourceType resource_type) {
  switch (resource_type) {
    case kDocumentResource:
      return protocol::Network::ResourceTypeEnum::Document;
    case kFontResource:
      return protocol::Network::ResourceTypeEnum::Font;
    case kImageResource:
      return protocol::Network::ResourceTypeEnum::Image;
    case kMediaResource:
      return protocol::Network::ResourceTypeEnum::Media;
    case kScriptResource:
      return protocol::Network::ResourceTypeEnum::Script;
    case kStylesheetResource:
      return protocol::Network::ResourceTypeEnum::Stylesheet;
    case kTextTrackResource:
      return protocol::Network::ResourceTypeEnum::TextTrack;
    case kXHRResource:
      return protocol::Network::ResourceTypeEnum::XHR;
    case kFetchResource:
      return protocol::Network::ResourceTypeEnum::Fetch;
    case kEventSourceResource:
      return protocol::Network::ResourceTypeEnum::EventSource;
    case kWebSocketResource:
      return protocol::Network::ResourceTypeEnum::WebSocket;
    case kManifestResource:
      return protocol::Network::ResourceTypeEnum::Manifest;
    case kSignedExchangeResource:
      return protocol::Network::ResourceTypeEnum::SignedExchange;
    case kPingResource:
      return protocol::Network::ResourceTypeEnum::Ping;
    case kOtherResource:
      return protocol::Network::ResourceTypeEnum::Other;
  }
  return protocol::Network::ResourceTypeEnum::Other;
}

InspectorPageAgent::ResourceType InspectorPageAgent::ToResourceType(
    const blink::ResourceType resource_type) {
  switch (resource_type) {
    case blink::ResourceType::kImage:
      return InspectorPageAgent::kImageResource;
    case blink::ResourceType::kFont:
      return InspectorPageAgent::kFontResource;
    case blink::ResourceType::kAudio:
    case blink::ResourceType::kVideo:
      return InspectorPageAgent::kMediaResource;
    case blink::ResourceType::kManifest:
      return InspectorPageAgent::kManifestResource;
    case blink::ResourceType::kTextTrack:
      return InspectorPageAgent::kTextTrackResource;
    case blink::ResourceType::kCSSStyleSheet:
    // Fall through.
    case blink::ResourceType::kXSLStyleSheet:
      return InspectorPageAgent::kStylesheetResource;
    case blink::ResourceType::kScript:
      return InspectorPageAgent::kScriptResource;
    default:
      break;
  }
  return InspectorPageAgent::kOtherResource;
}

String InspectorPageAgent::CachedResourceTypeJson(
    const Resource& cached_resource) {
  return ResourceTypeJson(ToResourceType(cached_resource.GetType()));
}

InspectorPageAgent::PageReloadScriptInjection::PageReloadScriptInjection(
    InspectorAgentState& agent_state)
    : pending_script_to_evaluate_on_load_once_(&agent_state,
                                               /*default_value=*/{}),
      target_url_for_pending_script_(&agent_state,
                                     /*default_value=*/{}) {}

void InspectorPageAgent::PageReloadScriptInjection::clear() {
  script_to_evaluate_on_load_once_ = {};
  pending_script_to_evaluate_on_load_once_.Set({});
  target_url_for_pending_script_.Set({});
}

void InspectorPageAgent::PageReloadScriptInjection::SetPending(
    String script,
    const KURL& target_url) {
  pending_script_to_evaluate_on_load_once_.Set(script);
  target_url_for_pending_script_.Set(target_url.GetString().GetString());
}

void InspectorPageAgent::PageReloadScriptInjection::PromoteToLoadOnce() {
  script_to_evaluate_on_load_once_ =
      pending_script_to_evaluate_on_load_once_.Get();
  target_url_for_active_script_ = target_url_for_pending_script_.Get();
  pending_script_to_evaluate_on_load_once_.Set({});
  target_url_for_pending_script_.Set({});
}

String InspectorPageAgent::PageReloadScriptInjection::GetScriptForInjection(
    const KURL& target_url) {
  if (target_url_for_active_script_ == target_url.GetString()) {
    return script_to_evaluate_on_load_once_;
  }
  return {};
}

InspectorPageAgent::InspectorPageAgent(
    InspectedFrames* inspected_frames,
    Client* client,
    InspectorResourceContentLoader* resource_content_loader,
    v8_inspector::V8InspectorSession* v8_session)
    : inspected_frames_(inspected_frames),
      v8_session_(v8_session),
      client_(client),
      inspector_resource_content_loader_(resource_content_loader),
      resource_content_loader_client_id_(
          resource_content_loader->CreateClientId()),
      intercept_file_chooser_(&agent_state_, false),
      enabled_(&agent_state_, /*default_value=*/false),
      screencast_enabled_(&agent_state_, /*default_value=*/false),
      lifecycle_events_enabled_(&agent_state_, /*default_value=*/false),
      bypass_csp_enabled_(&agent_state_, /*default_value=*/false),
      scripts_to_evaluate_on_load_(&agent_state_,
                                   /*default_value=*/String()),
      worlds_to_evaluate_on_load_(&agent_state_,
                                  /*default_value=*/String()),
      include_command_line_api_for_scripts_to_evaluate_on_load_(
          &agent_state_,
          /*default_value=*/false),
      standard_font_size_(&agent_state_, /*default_value=*/0),
      fixed_font_size_(&agent_state_, /*default_value=*/0),
      script_font_families_cbor_(&agent_state_, std::vector<uint8_t>()),
      script_injection_on_load_(agent_state_) {}

void InspectorPageAgent::Restore() {
  if (enabled_.Get())
    enable();
  if (bypass_csp_enabled_.Get())
    setBypassCSP(true);
  LocalFrame* frame = inspected_frames_->Root();
  auto* settings = frame->GetSettings();
  if (settings) {
    // Re-apply generic fonts overrides.
    if (!script_font_families_cbor_.Get().empty()) {
      protocol::Array<protocol::Page::ScriptFontFamilies> script_font_families;
      crdtp::DeserializerState state(script_font_families_cbor_.Get());
      bool result = crdtp::ProtocolTypeTraits<
          protocol::Array<protocol::Page::ScriptFontFamilies>>::
          Deserialize(&state, &script_font_families);
      CHECK(result);
      auto& family_settings = settings->GetGenericFontFamilySettings();
      setFontFamilies(family_settings, script_font_families);
      settings->NotifyGenericFontFamilyChange();
    }
    // Re-apply default font size overrides.
    if (standard_font_size_.Get() != 0)
      settings->SetDefaultFontSize(standard_font_size_.Get());
    if (fixed_font_size_.Get() != 0)
      settings->SetDefaultFixedFontSize(fixed_font_size_.Get());
  }
}

protocol::Response InspectorPageAgent::enable() {
  enabled_.Set(true);
  instrumenting_agents_->AddInspectorPageAgent(this);
  return protocol::Response::Success();
}

protocol::Response InspectorPageAgent::disable() {
  agent_state_.ClearAllFields();
  pending_isolated_worlds_.clear();
  script_injection_on_load_.clear();
  instrumenting_agents_->RemoveInspectorPageAgent(this);
  inspector_resource_content_loader_->Cancel(
      resource_content_loader_client_id_);
  requested_compilation_cache_.clear();
  compilation_cache_.clear();
  ad_script_identifiers_.clear();
  stopScreencast();

  return protocol::Response::Success();
}

protocol::Response InspectorPageAgent::addScriptToEvaluateOnNewDocument(
    const String& source,
    Maybe<String> world_name,
    Maybe<bool> include_command_line_api,
    Maybe<bool> runImmediately,
    String* identifier) {
  Vector<WTF::String> keys = scripts_to_evaluate_on_load_.Keys();
  auto result = std::max_element(
      keys.begin(), keys.end(), [](const WTF::String& a, const WTF::String& b) {
        return Decimal::FromString(a) < Decimal::FromString(b);
      });
  if (result == keys.end()) {
    *identifier = String::Number(1);
  } else {
    *identifier = String::Number(Decimal::FromString(*result).ToDouble() + 1);
  }

  scripts_to_evaluate_on_load_.Set(*identifier, source);
  worlds_to_evaluate_on_load_.Set(*identifier, world_name.value_or(""));
  include_command_line_api_for_scripts_to_evaluate_on_load_.Set(
      *identifier, include_command_line_api.value_or(false));

  if (client_->IsPausedForNewWindow() || runImmediately.value_or(false)) {
    // client_->IsPausedForNewWindow(): When opening a new popup,
    // Page.addScriptToEvaluateOnNewDocument could be called after
    // Runtime.enable that forces main context creation. In this case, we would
    // not normally evaluate the script, but we should.
    for (LocalFrame* frame : *inspected_frames_) {
      EvaluateScriptOnNewDocument(*frame, *identifier);
    }
  }

  return protocol::Response::Success();
}

protocol::Response InspectorPageAgent::removeScriptToEvaluateOnNewDocument(
    const String& identifier) {
  if (scripts_to_evaluate_on_load_.Get(identifier).IsNull())
    return protocol::Response::ServerError("Script not found");
  scripts_to_evaluate_on_load_.Clear(identifier);
  worlds_to_evaluate_on_load_.Clear(identifier);
  include_command_line_api_for_scripts_to_evaluate_on_load_.Clear(identifier);
  return protocol::Response::Success();
}

protocol::Response InspectorPageAgent::addScriptToEvaluateOnLoad(
    const String& source,
    String* identifier) {
  return addScriptToEvaluateOnNewDocument(source, Maybe<String>(""),
                                          Maybe<bool>(false),
                                          Maybe<bool>(false), identifier);
}

protocol::Response InspectorPageAgent::removeScriptToEvaluateOnLoad(
    const String& identifier) {
  return removeScriptToEvaluateOnNewDocument(identifier);
}

protocol::Response InspectorPageAgent::setLifecycleEventsEnabled(bool enabled) {
  lifecycle_events_enabled_.Set(enabled);
  if (!enabled)
    return protocol::Response::Success();

  for (LocalFrame* frame : *inspected_frames_) {
    Document* document = frame->GetDocument();
    DocumentLoader* loader = frame->Loader().GetDocumentLoader();
    if (!document || !loader)
      continue;

    DocumentLoadTiming& timing = loader->GetTiming();
    base::TimeTicks commit_timestamp = timing.ResponseEnd();
    if (!commit_timestamp.is_null()) {
      LifecycleEvent(frame, loader, "commit",
                     commit_timestamp.since_origin().InSecondsF());
    }

    base::TimeTicks domcontentloaded_timestamp =
        document->GetTiming().DomContentLoadedEventEnd();
    if (!domcontentloaded_timestamp.is_null()) {
      LifecycleEvent(frame, loader, "DOMContentLoaded",
                     domcontentloaded_timestamp.since_origin().InSecondsF());
    }

    base::TimeTicks load_timestamp = timing.LoadEventEnd();
    if (!load_timestamp.is_null()) {
      LifecycleEvent(frame, loader, "load",
                     load_timestamp.since_origin().InSecondsF());
    }

    IdlenessDetector* idleness_detector = frame->GetIdlenessDetector();
    base::TimeTicks network_almost_idle_timestamp =
        idleness_detector->GetNetworkAlmostIdleTime();
    if (!network_almost_idle_timestamp.is_null()) {
      LifecycleEvent(frame, loader, "networkAlmostIdle",
                     network_almost_idle_timestamp.since_origin().InSecondsF());
    }
    base::TimeTicks network_idle_timestamp =
        idleness_detector->GetNetworkIdleTime();
    if (!network_idle_timestamp.is_null()) {
      LifecycleEvent(frame, loader, "networkIdle",
                     network_idle_timestamp.since_origin().InSecondsF());
    }
  }

  return protocol::Response::Success();
}

protocol::Response InspectorPageAgent::setAdBlockingEnabled(bool enable) {
  return protocol::Response::Success();
}

protocol::Response InspectorPageAgent::reload(
    Maybe<bool> optional_bypass_cache,
    Maybe<String> optional_script_to_evaluate_on_load,
    Maybe<String> loader_id) {
  if (loader_id.has_value() && inspected_frames_->Root()
                                       ->Loader()
                                       .GetDocumentLoader()
                                       ->GetDevToolsNavigationToken()
                                       .ToString() != loader_id->Ascii()) {
    return protocol::Response::InvalidParams("Document already navigated");
  }
  script_injection_on_load_.SetPending(
      optional_script_to_evaluate_on_load.value_or(""),
      inspected_frames_->Root()->Loader().GetDocumentLoader()->Url());
  v8_session_->setSkipAllPauses(true);
  v8_session_->resume(true /* terminate on resume */);
  return protocol::Response::Success();
}

protocol::Response InspectorPageAgent::stopLoading() {
  return protocol::Response::Success();
}

static void CachedResourcesForDocument(Document* document,
                                       HeapVector<Member<Resource>>& result,
                                       bool skip_xhrs) {
  const ResourceFetcher::DocumentResourceMap& all_resources =
      document->Fetcher()->AllResources();
  for (const auto& resource : all_resources) {
    Resource* cached_resource = resource.value.Get();
    if (!cached_resource)
      continue;

    // Skip images that were not auto loaded (images disabled in the user
    // agent), fonts that were referenced in CSS but never used/downloaded, etc.
    if (cached_resource->StillNeedsLoad())
      continue;
    if (cached_resource->GetType() == ResourceType::kRaw && skip_xhrs)
      continue;
    result.push_back(cached_resource);
  }
}

// static
static HeapVector<Member<Resource>> CachedResourcesForFrame(LocalFrame* frame,
                                                            bool skip_xhrs) {
  HeapVector<Member<Resource>> result;
  CachedResourcesForDocument(frame->GetDocument(), result, skip_xhrs);
  return result;
}

protocol::Response InspectorPageAgent::getResourceTree(
    std::unique_ptr<protocol::Page::FrameResourceTree>* object) {
  *object = BuildObjectForResourceTree(inspected_frames_->Root());
  return protocol::Response::Success();
}

protocol::Response InspectorPageAgent::getFrameTree(
    std::unique_ptr<protocol::Page::FrameTree>* object) {
  *object = BuildObjectForFrameTree(inspected_frames_->Root());
  return protocol::Response::Success();
}

void InspectorPageAgent::GetResourceContentAfterResourcesContentLoaded(
    const String& frame_id,
    const String& url,
    std::unique_ptr<GetResourceContentCallback> callback) {
  LocalFrame* frame =
      IdentifiersFactory::FrameById(inspected_frames_, frame_id);
  if (!frame) {
    callback->sendFailure(
        protocol::Response::ServerError("No frame for given id found"));
    return;
  }
  String content;
  bool base64_encoded;
  if (InspectorPageAgent::CachedResourceContent(
          CachedResource(frame, KURL(url), inspector_resource_content_loader_),
          &content, &base64_encoded)) {
    callback->sendSuccess(content, base64_encoded);
  } else {
    callback->sendFailure(
        protocol::Response::ServerError("No resource with given URL found"));
  }
}

void InspectorPageAgent::getResourceContent(
    const String& frame_id,
    const String& url,
    std::unique_ptr<GetResourceContentCallback> callback) {
  if (!enabled_.Get()) {
    callback->sendFailure(
        protocol::Response::ServerError("Agent is not enabled."));
    return;
  }
  inspector_resource_content_loader_->EnsureResourcesContentLoaded(
      resource_content_loader_client_id_,
      WTF::BindOnce(
          &InspectorPageAgent::GetResourceContentAfterResourcesContentLoaded,
          WrapPersistent(this), frame_id, url, std::move(callback)));
}

protocol::Response InspectorPageAgent::getAdScriptId(
    const String& frame_id,
    Maybe<protocol::Page::AdScriptId>* ad_script_id) {
  if (ad_script_identifiers_.Contains(frame_id)) {
    AdScriptIdentifier* ad_script_identifier =
        ad_script_identifiers_.at(frame_id);
    *ad_script_id =
        protocol::Page::AdScriptId::create()
            .setScriptId(String::Number(ad_script_identifier->id))
            .setDebuggerId(ToCoreString(
                ad_script_identifier->context_id.toString()->string()))
            .build();
  }

  return protocol::Response::Success();
}

void InspectorPageAgent::SearchContentAfterResourcesContentLoaded(
    const String& frame_id,
    const String&
```