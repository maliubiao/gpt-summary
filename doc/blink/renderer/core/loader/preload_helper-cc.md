Response:
The user wants a summary of the functionality of the `preload_helper.cc` file in the Chromium Blink engine. I need to analyze the provided code snippet to identify its core responsibilities. I should also look for connections to web technologies like JavaScript, HTML, and CSS, providing examples if any are found. Furthermore, I need to identify potential user or programming errors related to the code. Finally, I need to deduce how a user's actions might lead to this code being executed and summarize the findings in the first part of a two-part response.

Here's a breakdown of the code's functionality based on the includes and the functions defined:

1. **Resource Preloading:** The file heavily deals with preloading various types of resources like images, scripts, stylesheets, fonts, and modules. This is evident from functions like `PreloadIfNeeded`, `ModulePreloadIfNeeded`, and the inclusion of resource-specific headers (`CSSStyleSheetResource`, `FontResource`, etc.).

2. **Link Header Processing:**  The code seems to process `<link>` tags, including those specified in HTTP headers, for preloading, prefetching, and DNS prefetching/preconnecting. This is indicated by `LoadLinksFromHeaderMode` and the handling of `LinkLoadParameters`.

3. **`as` Attribute Handling:** It parses and validates the `as` attribute of `<link>` tags to determine the resource type being preloaded.

4. **Media Query Evaluation:** The code uses `MediaList` and `MediaQueryEvaluator` to check if a preload should be initiated based on media queries.

5. **Subresource Integrity (SRI):** It handles the `integrity` attribute for verifying the integrity of preloaded resources (scripts, stylesheets, fonts).

6. **Fetch Priority:** It considers the `fetchpriority` attribute to influence the priority of preloaded resources.

7. **Cross-Origin Handling:** The code processes the `crossorigin` attribute for cross-origin resource requests.

8. **Module Preloading:** It specifically handles module script preloading, involving `Modulator` and `ModuleScriptFetchRequest`.

9. **Prefetching:** The code includes logic for prefetching resources, particularly for document prefetching.

10. **DNS Prefetching and Preconnecting:** The file contains functions for initiating DNS prefetching and preconnecting to servers.

11. **Console Logging:**  It logs messages to the browser's developer console for debugging and informational purposes related to preloading.

12. **Use Counters:** It uses `UseCounter` to track the usage of various preload-related features.

13. **Dictionary Preloading:** The `LoadDictionaryWhenIdleTask` suggests support for preloading compression dictionaries.

Based on these observations, I can formulate the summary.
```cpp
// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/loader/preload_helper.h"

// ... other includes ...
```

This code snippet represents the header inclusion section of the `preload_helper.cc` file in the Chromium Blink rendering engine. While it doesn't perform any direct actions, these includes hint at the functionalities provided by the file.

**Functionalities of `preload_helper.cc` based on the includes:**

Based on the included headers, `preload_helper.cc` likely provides the following functionalities:

1. **Initiating Resource Preloads:**  Headers like `third_party/blink/renderer/core/loader/pending_link_preload.h`, `third_party/blink/renderer/core/loader/resource/css_style_sheet_resource.h`, `third_party/blink/renderer/core/loader/resource/script_resource.h`, etc., suggest that this file is responsible for triggering the loading of resources like stylesheets, scripts, images, and fonts before they are explicitly needed by the parser. This is often done based on `<link rel="preload">` hints.

2. **Handling `<link>` tag attributes:** Includes like `third_party/blink/renderer/core/html/parser/html_preload_scanner.h`, `third_party/blink/renderer/core/loader/link_load_parameters.h`, and `third_party/blink/renderer/core/html/blocking_attribute.h` indicate that the file parses and interprets attributes of `<link>` tags, particularly those related to preloading and their blocking behavior.

3. **Managing Fetch Priorities:** The inclusion of `third_party/blink/renderer/core/loader/fetch_priority_attribute.h` suggests it handles the `fetchpriority` attribute of `<link>` tags to influence the loading priority of resources.

4. **Evaluating Media Queries for Preloads:** Headers like `third_party/blink/renderer/core/css/media_list.h` and `third_party/blink/renderer/core/css/media_query_evaluator.h` indicate that the helper can evaluate media queries specified in `<link>` tags to conditionally initiate preloads.

5. **Supporting Module Preloading:** The presence of `third_party/blink/renderer/core/loader/modulescript/module_script_creation_params.h` and `third_party/blink/renderer/core/script/modulator.h` suggests it supports the preloading of JavaScript modules using `<link rel="modulepreload">`.

6. **Facilitating DNS Prefetching and Preconnecting:** The include `third_party/blink/public/platform/web_prescient_networking.h` indicates that the file can trigger DNS prefetching and preconnecting to improve page load performance.

7. **Handling Subresource Integrity (SRI):** The inclusion of `third_party/blink/renderer/core/loader/subresource_integrity_helper.h` and `third_party/blink/renderer/platform/loader/subresource_integrity.h` suggests it plays a role in verifying the integrity of preloaded resources using the `integrity` attribute.

8. **Interaction with the Network Layer:** Includes like `third_party/blink/public/mojom/fetch/fetch_api_request.mojom-blink.h` and `third_party/blink/renderer/platform/loader/fetch/resource_fetcher.h` show its interaction with the network fetching mechanism.

9. **Logging and Debugging:** The inclusion of `third_party/blink/renderer/core/frame/frame_console.h` and `third_party/blink/renderer/core/inspector/console_message.h` suggests it can log messages to the developer console, potentially for debugging preload behavior.

10. **Utilizing Idle Time:** The presence of `third_party/blink/renderer/bindings/core/v8/v8_idle_request_options.h` and `third_party/blink/renderer/core/scheduler/scripted_idle_task_controller.h` hints at the possibility of scheduling some preloading tasks during browser idle time.

**Relationship with JavaScript, HTML, and CSS:**

* **HTML:** This file is deeply intertwined with HTML. It processes `<link>` tags, which are fundamental HTML elements. The preloading mechanism itself is often triggered by `<link rel="preload">` and `<link rel="modulepreload">` tags in the HTML document. The parsing of `srcset` and `sizes` attributes for images, as hinted by `third_party/blink/renderer/core/html/parser/html_srcset_parser.h` and `third_party/blink/renderer/core/css/parser/sizes_attribute_parser.h`, directly relates to the `<img>` tag and responsive images in HTML.

* **CSS:** The file handles preloading of CSS stylesheets (`third_party/blink/renderer/core/loader/resource/css_style_sheet_resource.h`). It also evaluates media queries (`third_party/blink/renderer/core/css/media_list.h`) which are a core part of CSS. The preloading of fonts (`third_party/blink/renderer/core/loader/resource/font_resource.h`) is also relevant to CSS as fonts are typically applied through stylesheets.

* **JavaScript:** The file supports preloading JavaScript scripts (`third_party/blink/renderer/core/loader/resource/script_resource.h`) and, more specifically, JavaScript modules (`third_party/blink/renderer/core/loader/modulescript/*`). The `integrity` attribute, relevant to SRI, is crucial for ensuring the security of JavaScript code loaded from external sources.

**Hypothetical Input and Output (Logical Reasoning):**

**Hypothetical Input:**  The HTML parser encounters the following `<link>` tag:

```html
<link rel="preload" href="style.css" as="style" media="screen and (min-width: 600px)">
```

**Assumptions:** The browser window's width is currently less than 600px.

**Hypothetical Output:** The `preload_helper.cc` would likely evaluate the media query `"screen and (min-width: 600px)"`. Since the condition is false, the preload for `style.css` would *not* be initiated immediately. The preload might be registered, and if the viewport width later becomes 600px or more, the preload might then be triggered.

**User or Programming Common Usage Errors:**

1. **Incorrect `as` attribute:**  Using an incorrect or unsupported value for the `as` attribute in `<link rel="preload">` (e.g., `<link rel="preload" href="font.woff2" as="document">`). This would likely result in the resource not being preloaded and potentially a console warning.

2. **Mismatched `type` attribute:** Providing a `type` attribute that doesn't match the actual MIME type of the resource being preloaded (e.g., `<link rel="preload" href="image.png" as="image" type="image/webp">` if the server serves a PNG). While the preload might still happen, it could lead to inefficiencies or warnings.

3. **Forgetting the `as` attribute:** Omitting the `as` attribute in `<link rel="preload">` (e.g., `<link rel="preload" href="script.js">`). This is a common error, and the browser won't know the type of resource to preload, rendering the hint ineffective.

4. **Using relative URLs incorrectly in Link headers:** When preloading via HTTP Link headers, if relative URLs are not resolved correctly against the resource's URL, the browser might try to load from the wrong location.

**User Operations Leading to This Code:**

1. **Typing a URL in the address bar and pressing Enter:** This initiates the loading of a new web page. The HTML parser will encounter `<link>` tags, triggering the `preload_helper.cc` to process preload and other link-related hints.

2. **Clicking a link on a webpage:** Similar to the above, navigating to a new page will involve parsing the HTML of the destination page.

3. **The browser receiving HTTP headers for a resource:**  HTTP Link headers can specify preloads. When the browser fetches a resource (e.g., an HTML document or a CSS file), the `preload_helper.cc` can be invoked to process these headers and initiate preloads for other resources.

4. **JavaScript dynamically adding `<link>` elements to the DOM:**  Scripts can create and insert `<link>` tags. If these tags have `rel="preload"` or `rel="modulepreload"`, the `preload_helper.cc` will be involved.

**Summary of Functionalities (Part 1):**

In summary, based on the included headers, the `preload_helper.cc` file in Chromium Blink is responsible for **handling resource preloading and related network optimizations**. This involves parsing and interpreting `<link>` tags (both in HTML and HTTP headers), evaluating media queries, managing fetch priorities, supporting module preloading, facilitating DNS prefetching and preconnecting, handling subresource integrity, interacting with the network layer, logging preload activity, and potentially utilizing idle browser time for certain tasks. It plays a crucial role in improving page load performance by proactively fetching resources that the browser anticipates needing in the future.

### 提示词
```
这是目录为blink/renderer/core/loader/preload_helper.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/loader/preload_helper.h"

#include "base/metrics/histogram_functions.h"
#include "base/timer/elapsed_timer.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/mojom/fetch/fetch_api_request.mojom-blink.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/platform/web_prescient_networking.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_compile_hints_common.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_idle_request_options.h"
#include "third_party/blink/renderer/core/css/media_list.h"
#include "third_party/blink/renderer/core/css/media_query_evaluator.h"
#include "third_party/blink/renderer/core/css/parser/sizes_attribute_parser.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/execution_context/agent.h"
#include "third_party/blink/renderer/core/frame/frame_console.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/navigator.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/frame/viewport_data.h"
#include "third_party/blink/renderer/core/frame/web_local_frame_impl.h"
#include "third_party/blink/renderer/core/html/blocking_attribute.h"
#include "third_party/blink/renderer/core/html/parser/html_preload_scanner.h"
#include "third_party/blink/renderer/core/html/parser/html_srcset_parser.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/core/loader/alternate_signed_exchange_resource_info.h"
#include "third_party/blink/renderer/core/loader/document_loader.h"
#include "third_party/blink/renderer/core/loader/fetch_priority_attribute.h"
#include "third_party/blink/renderer/core/loader/link_load_parameters.h"
#include "third_party/blink/renderer/core/loader/modulescript/module_script_creation_params.h"
#include "third_party/blink/renderer/core/loader/modulescript/module_script_fetch_request.h"
#include "third_party/blink/renderer/core/loader/pending_link_preload.h"
#include "third_party/blink/renderer/core/loader/render_blocking_resource_manager.h"
#include "third_party/blink/renderer/core/loader/resource/css_style_sheet_resource.h"
#include "third_party/blink/renderer/core/loader/resource/font_resource.h"
#include "third_party/blink/renderer/core/loader/resource/image_resource.h"
#include "third_party/blink/renderer/core/loader/resource/link_dictionary_resource.h"
#include "third_party/blink/renderer/core/loader/resource/link_prefetch_resource.h"
#include "third_party/blink/renderer/core/loader/resource/script_resource.h"
#include "third_party/blink/renderer/core/loader/subresource_integrity_helper.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/page/viewport_description.h"
#include "third_party/blink/renderer/core/scheduler/scripted_idle_task_controller.h"
#include "third_party/blink/renderer/core/script/modulator.h"
#include "third_party/blink/renderer/core/script/script_loader.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/loader/fetch/fetch_initiator_type_names.h"
#include "third_party/blink/renderer/platform/loader/fetch/raw_resource.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_fetcher.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_loader_options.h"
#include "third_party/blink/renderer/platform/loader/link_header.h"
#include "third_party/blink/renderer/platform/loader/subresource_integrity.h"
#include "third_party/blink/renderer/platform/network/mime/mime_type_registry.h"

namespace blink {

namespace {

class LoadDictionaryWhenIdleTask final : public IdleTask {
 public:
  LoadDictionaryWhenIdleTask(FetchParameters fetch_params,
                             ResourceFetcher* fetcher,
                             PendingLinkPreload* pending_preload)
      : fetch_params_(std::move(fetch_params)),
        resource_fetcher_(fetcher),
        pending_preload_(pending_preload) {}

  void Trace(Visitor* visitor) const override {
    visitor->Trace(resource_fetcher_);
    visitor->Trace(pending_preload_);
    visitor->Trace(fetch_params_);
    IdleTask::Trace(visitor);
  }

 private:
  void invoke(IdleDeadline* deadline) override {
    Resource* resource =
        LinkDictionaryResource::Fetch(fetch_params_, resource_fetcher_);
    if (pending_preload_) {
      pending_preload_->AddResource(resource);
    }
  }

  FetchParameters fetch_params_;
  Member<ResourceFetcher> resource_fetcher_;
  Member<PendingLinkPreload> pending_preload_;
};

void SendMessageToConsoleForPossiblyNullDocument(
    ConsoleMessage* console_message,
    Document* document,
    LocalFrame* frame) {
  DCHECK(document || frame);
  DCHECK(!document || document->GetFrame() == frame);
  // Route the console message through Document if possible, so that script line
  // numbers can be included. Otherwise, route directly to the FrameConsole, to
  // ensure we never drop a message.
  if (document)
    document->AddConsoleMessage(console_message);
  else
    frame->Console().AddMessage(console_message);
}

bool IsSupportedType(ResourceType resource_type, const String& mime_type) {
  if (mime_type.empty())
    return true;
  switch (resource_type) {
    case ResourceType::kImage:
      return MIMETypeRegistry::IsSupportedImagePrefixedMIMEType(mime_type);
    case ResourceType::kScript:
      return MIMETypeRegistry::IsSupportedJavaScriptMIMEType(mime_type);
    case ResourceType::kCSSStyleSheet:
      return MIMETypeRegistry::IsSupportedStyleSheetMIMEType(mime_type);
    case ResourceType::kFont:
      return MIMETypeRegistry::IsSupportedFontMIMEType(mime_type);
    case ResourceType::kAudio:
    case ResourceType::kVideo:
      return MIMETypeRegistry::IsSupportedMediaMIMEType(mime_type, String());
    case ResourceType::kTextTrack:
      return MIMETypeRegistry::IsSupportedTextTrackMIMEType(mime_type);
    case ResourceType::kRaw:
      return true;
    default:
      NOTREACHED();
  }
}

MediaValuesCached* CreateMediaValues(
    Document& document,
    const ViewportDescription* viewport_description) {
  MediaValuesCached* media_values =
      MakeGarbageCollected<MediaValuesCached>(document);
  if (viewport_description) {
    gfx::SizeF initial_viewport(media_values->DeviceWidth(),
                                media_values->DeviceHeight());
    PageScaleConstraints constraints = viewport_description->Resolve(
        initial_viewport, document.GetViewportData().ViewportDefaultMinWidth());
    media_values->OverrideViewportDimensions(constraints.layout_size.width(),
                                             constraints.layout_size.height());
  }
  return media_values;
}

bool MediaMatches(const String& media,
                  MediaValues* media_values,
                  ExecutionContext* execution_context) {
  MediaQuerySet* media_queries =
      MediaQuerySet::Create(media, execution_context);
  MediaQueryEvaluator* evaluator =
      MakeGarbageCollected<MediaQueryEvaluator>(media_values);
  return evaluator->Eval(*media_queries);
}

KURL GetBestFitImageURL(const Document& document,
                        const KURL& base_url,
                        MediaValues* media_values,
                        const KURL& href,
                        const String& image_srcset,
                        const String& image_sizes) {
  float source_size = SizesAttributeParser(media_values, image_sizes,
                                           document.GetExecutionContext())
                          .Size();
  ImageCandidate candidate = BestFitSourceForImageAttributes(
      media_values->DevicePixelRatio(), source_size, href, image_srcset);
  return base_url.IsNull() ? document.CompleteURL(candidate.ToString())
                           : KURL(base_url, candidate.ToString());
}

// Check whether the `as` attribute is valid according to the spec, even if we
// don't currently support it yet.
bool IsValidButUnsupportedAsAttribute(const String& as) {
  DCHECK(as != "fetch" && as != "image" && as != "font" && as != "script" &&
         as != "style" && as != "track");
  return as == "audio" || as == "audioworklet" || as == "document" ||
         as == "embed" || as == "manifest" || as == "object" ||
         as == "paintworklet" || as == "report" || as == "sharedworker" ||
         as == "video" || as == "worker" || as == "xslt";
}

bool IsNetworkHintAllowed(PreloadHelper::LoadLinksFromHeaderMode mode) {
  switch (mode) {
    case PreloadHelper::LoadLinksFromHeaderMode::kDocumentBeforeCommit:
      return true;
    case PreloadHelper::LoadLinksFromHeaderMode::
        kDocumentAfterCommitWithoutViewport:
      return false;
    case PreloadHelper::LoadLinksFromHeaderMode::
        kDocumentAfterCommitWithViewport:
      return false;
    case PreloadHelper::LoadLinksFromHeaderMode::kDocumentAfterLoadCompleted:
      return false;
    case PreloadHelper::LoadLinksFromHeaderMode::kSubresourceFromMemoryCache:
      return true;
    case PreloadHelper::LoadLinksFromHeaderMode::kSubresourceNotFromMemoryCache:
      return true;
  }
}

bool IsResourceLoadAllowed(PreloadHelper::LoadLinksFromHeaderMode mode,
                           bool is_viewport_dependent) {
  switch (mode) {
    case PreloadHelper::LoadLinksFromHeaderMode::kDocumentBeforeCommit:
      return false;
    case PreloadHelper::LoadLinksFromHeaderMode::
        kDocumentAfterCommitWithoutViewport:
      return !is_viewport_dependent;
    case PreloadHelper::LoadLinksFromHeaderMode::
        kDocumentAfterCommitWithViewport:
      return is_viewport_dependent;
    case PreloadHelper::LoadLinksFromHeaderMode::kDocumentAfterLoadCompleted:
      return false;
    case PreloadHelper::LoadLinksFromHeaderMode::kSubresourceFromMemoryCache:
      return false;
    case PreloadHelper::LoadLinksFromHeaderMode::kSubresourceNotFromMemoryCache:
      return true;
  }
}

bool IsCompressionDictionaryLoadAllowed(
    PreloadHelper::LoadLinksFromHeaderMode mode) {
  // Document header can trigger dictionary load after the page load completes.
  // Subresources header can trigger dictionary load if it is not from the
  // memory cache.
  switch (mode) {
    case PreloadHelper::LoadLinksFromHeaderMode::kDocumentBeforeCommit:
      return false;
    case PreloadHelper::LoadLinksFromHeaderMode::
        kDocumentAfterCommitWithoutViewport:
      return false;
    case PreloadHelper::LoadLinksFromHeaderMode::
        kDocumentAfterCommitWithViewport:
      return false;
    case PreloadHelper::LoadLinksFromHeaderMode::kDocumentAfterLoadCompleted:
      return true;
    case PreloadHelper::LoadLinksFromHeaderMode::kSubresourceFromMemoryCache:
      return false;
    case PreloadHelper::LoadLinksFromHeaderMode::kSubresourceNotFromMemoryCache:
      return true;
  }
}

}  // namespace

void PreloadHelper::DnsPrefetchIfNeeded(
    const LinkLoadParameters& params,
    Document* document,
    LocalFrame* frame,
    LinkCaller caller) {
  if (document && document->Loader() && document->Loader()->Archive()) {
    return;
  }
  if (params.rel.IsDNSPrefetch()) {
    UseCounter::Count(document, WebFeature::kLinkRelDnsPrefetch);
    if (caller == kLinkCalledFromHeader)
      UseCounter::Count(document, WebFeature::kLinkHeaderDnsPrefetch);
    Settings* settings = frame ? frame->GetSettings() : nullptr;
    // FIXME: The href attribute of the link element can be in "//hostname"
    // form, and we shouldn't attempt to complete that as URL
    // <https://bugs.webkit.org/show_bug.cgi?id=48857>.
    if (settings && settings->GetDNSPrefetchingEnabled() &&
        params.href.IsValid() && !params.href.IsEmpty()) {
      if (settings->GetLogDnsPrefetchAndPreconnect()) {
        SendMessageToConsoleForPossiblyNullDocument(
            MakeGarbageCollected<ConsoleMessage>(
                mojom::blink::ConsoleMessageSource::kOther,
                mojom::blink::ConsoleMessageLevel::kVerbose,
                String("DNS prefetch triggered for " + params.href.Host())),
            document, frame);
      }
      WebPrescientNetworking* web_prescient_networking =
          frame ? frame->PrescientNetworking() : nullptr;
      if (web_prescient_networking) {
        web_prescient_networking->PrefetchDNS(params.href);
      }
    }
  }
}

void PreloadHelper::PreconnectIfNeeded(
    const LinkLoadParameters& params,
    Document* document,
    LocalFrame* frame,
    LinkCaller caller) {
  if (document && document->Loader() && document->Loader()->Archive()) {
    return;
  }
  if (params.rel.IsPreconnect() && params.href.IsValid() &&
      params.href.ProtocolIsInHTTPFamily()) {
    UseCounter::Count(document, WebFeature::kLinkRelPreconnect);
    if (caller == kLinkCalledFromHeader)
      UseCounter::Count(document, WebFeature::kLinkHeaderPreconnect);
    Settings* settings = frame ? frame->GetSettings() : nullptr;
    if (settings && settings->GetLogDnsPrefetchAndPreconnect()) {
      SendMessageToConsoleForPossiblyNullDocument(
          MakeGarbageCollected<ConsoleMessage>(
              mojom::blink::ConsoleMessageSource::kOther,
              mojom::blink::ConsoleMessageLevel::kVerbose,
              String("Preconnect triggered for ") + params.href.GetString()),
          document, frame);
      if (params.cross_origin != kCrossOriginAttributeNotSet) {
        SendMessageToConsoleForPossiblyNullDocument(
            MakeGarbageCollected<ConsoleMessage>(
                mojom::blink::ConsoleMessageSource::kOther,
                mojom::blink::ConsoleMessageLevel::kVerbose,
                String("Preconnect CORS setting is ") +
                    String(
                        (params.cross_origin == kCrossOriginAttributeAnonymous)
                            ? "anonymous"
                            : "use-credentials")),
            document, frame);
      }
    }
    WebPrescientNetworking* web_prescient_networking =
        frame ? frame->PrescientNetworking() : nullptr;
    if (web_prescient_networking) {
      web_prescient_networking->Preconnect(
          params.href, params.cross_origin != kCrossOriginAttributeAnonymous);
    }
  }
}

// Until the preload cache is defined in terms of range requests and media
// fetches we can't reliably preload audio/video content and expect it to be
// served from the cache correctly. Until
// https://github.com/w3c/preload/issues/97 is resolved and implemented we need
// to disable these preloads.
std::optional<ResourceType> PreloadHelper::GetResourceTypeFromAsAttribute(
    const String& as) {
  DCHECK_EQ(as.DeprecatedLower(), as);
  if (as == "image")
    return ResourceType::kImage;
  if (as == "script")
    return ResourceType::kScript;
  if (as == "style")
    return ResourceType::kCSSStyleSheet;
  if (as == "track")
    return ResourceType::kTextTrack;
  if (as == "font")
    return ResourceType::kFont;
  if (as == "fetch")
    return ResourceType::kRaw;
  return std::nullopt;
}

// |base_url| is used in Link HTTP Header based preloads to resolve relative
// URLs in srcset, which should be based on the resource's URL, not the
// document's base URL. If |base_url| is a null URL, relative URLs are resolved
// using |document.CompleteURL()|.
void PreloadHelper::PreloadIfNeeded(
    const LinkLoadParameters& params,
    Document& document,
    const KURL& base_url,
    LinkCaller caller,
    const ViewportDescription* viewport_description,
    ParserDisposition parser_disposition,
    PendingLinkPreload* pending_preload) {
  if (!document.Loader() || !params.rel.IsLinkPreload())
    return;

  std::optional<ResourceType> resource_type =
      PreloadHelper::GetResourceTypeFromAsAttribute(params.as);

  MediaValuesCached* media_values = nullptr;
  KURL url;
  if (resource_type == ResourceType::kImage && !params.image_srcset.empty()) {
    UseCounter::Count(document, WebFeature::kLinkRelPreloadImageSrcset);
    media_values = CreateMediaValues(document, viewport_description);
    url = GetBestFitImageURL(document, base_url, media_values, params.href,
                             params.image_srcset, params.image_sizes);
  } else {
    url = params.href;
  }

  UseCounter::Count(document, WebFeature::kLinkRelPreload);
  if (!url.IsValid() || url.IsEmpty()) {
    document.AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
        mojom::blink::ConsoleMessageSource::kOther,
        mojom::blink::ConsoleMessageLevel::kWarning,
        String("<link rel=preload> has an invalid `href` value")));
    return;
  }

  bool media_matches = true;

  if (!params.media.empty()) {
    if (!media_values)
      media_values = CreateMediaValues(document, viewport_description);
    media_matches = MediaMatches(params.media, media_values,
                                 document.GetExecutionContext());
  }

  DCHECK(pending_preload);

  if (params.reason == LinkLoadParameters::Reason::kMediaChange) {
    if (!media_matches) {
      // Media attribute does not match environment, abort existing preload.
      pending_preload->Dispose();
    } else if (pending_preload->MatchesMedia()) {
      // Media still matches, no need to re-fetch.
      return;
    }
  }

  pending_preload->SetMatchesMedia(media_matches);

  // Preload only if media matches
  if (!media_matches)
    return;

  if (caller == kLinkCalledFromHeader)
    UseCounter::Count(document, WebFeature::kLinkHeaderPreload);
  if (resource_type == std::nullopt) {
    String message;
    if (IsValidButUnsupportedAsAttribute(params.as)) {
      message = String("<link rel=preload> uses an unsupported `as` value");
    } else {
      message = String("<link rel=preload> must have a valid `as` value");
    }
    document.AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
        mojom::blink::ConsoleMessageSource::kOther,
        mojom::blink::ConsoleMessageLevel::kWarning, message));
    return;
  }
  if (!IsSupportedType(resource_type.value(), params.type)) {
    document.AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
        mojom::blink::ConsoleMessageSource::kOther,
        mojom::blink::ConsoleMessageLevel::kWarning,
        String("<link rel=preload> has an unsupported `type` value")));
    return;
  }
  ResourceRequest resource_request(url);
  resource_request.SetRequestContext(ResourceFetcher::DetermineRequestContext(
      resource_type.value(), ResourceFetcher::kImageNotImageSet));
  resource_request.SetRequestDestination(
      ResourceFetcher::DetermineRequestDestination(resource_type.value()));

  resource_request.SetReferrerPolicy(params.referrer_policy);

  resource_request.SetFetchPriorityHint(
      GetFetchPriorityAttributeValue(params.fetch_priority_hint));

  ResourceLoaderOptions options(
      document.GetExecutionContext()->GetCurrentWorld());

  options.initiator_info.name = fetch_initiator_type_names::kLink;
  options.parser_disposition = parser_disposition;
  FetchParameters link_fetch_params(std::move(resource_request), options);
  link_fetch_params.SetCharset(document.Encoding());

  if (params.cross_origin != kCrossOriginAttributeNotSet) {
    link_fetch_params.SetCrossOriginAccessControl(
        document.GetExecutionContext()->GetSecurityOrigin(),
        params.cross_origin);
  }

  const String& integrity_attr = params.integrity;
  // A corresponding check for the preload-scanner code path is in
  // TokenPreloadScanner::StartTagScanner::CreatePreloadRequest().
  // TODO(crbug.com/981419): Honor the integrity attribute value for all
  // supported preload destinations, not just the destinations that support SRI
  // in the first place.
  if (resource_type == ResourceType::kScript ||
      resource_type == ResourceType::kCSSStyleSheet ||
      resource_type == ResourceType::kFont) {
    if (!integrity_attr.empty()) {
      IntegrityMetadataSet metadata_set;
      SubresourceIntegrity::ParseIntegrityAttribute(
          integrity_attr,
          SubresourceIntegrityHelper::GetFeatures(
              document.GetExecutionContext()),
          metadata_set);
      link_fetch_params.SetIntegrityMetadata(metadata_set);
      link_fetch_params.MutableResourceRequest().SetFetchIntegrity(
          integrity_attr);
    }
  } else {
    if (!integrity_attr.empty()) {
      document.AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
          mojom::blink::ConsoleMessageSource::kOther,
          mojom::blink::ConsoleMessageLevel::kWarning,
          String("The `integrity` attribute is currently ignored for preload "
                 "destinations that do not support subresource integrity. See "
                 "https://crbug.com/981419 for more information")));
    }
  }

  link_fetch_params.SetContentSecurityPolicyNonce(params.nonce);
  Settings* settings = document.GetSettings();
  if (settings && settings->GetLogPreload()) {
    String message = "Preload triggered for " + url.Host() + url.GetPath();
    String fetch_priority_message;
    if (!params.fetch_priority_hint.empty()) {
      mojom::blink::FetchPriorityHint hint =
          GetFetchPriorityAttributeValue(params.fetch_priority_hint);
      switch (hint) {
        case mojom::blink::FetchPriorityHint::kLow:
          fetch_priority_message = " with fetchpriority hint 'low'";
          break;
        case mojom::blink::FetchPriorityHint::kHigh:
          fetch_priority_message = " with fetchpriority hint 'high'";
          break;
        case mojom::blink::FetchPriorityHint::kAuto:
          fetch_priority_message = " with fetchpriority hint 'auto'";
          break;
        default:
          NOTREACHED();
      }
    }
    document.AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
        mojom::blink::ConsoleMessageSource::kOther,
        mojom::blink::ConsoleMessageLevel::kVerbose,
        message + fetch_priority_message));
  }
  link_fetch_params.SetLinkPreload(true);
  link_fetch_params.SetRenderBlockingBehavior(
      RenderBlockingBehavior::kNonBlocking);
  if (pending_preload) {
    if (RenderBlockingResourceManager* manager =
            document.GetRenderBlockingResourceManager()) {
      if (EqualIgnoringASCIICase(params.as, "font")) {
        manager->AddPendingFontPreload(*pending_preload);
      }
    }
  }

  Resource* resource = PreloadHelper::StartPreload(resource_type.value(),
                                                   link_fetch_params, document);
  if (pending_preload)
    pending_preload->AddResource(resource);
}

// https://html.spec.whatwg.org/C/#link-type-modulepreload
void PreloadHelper::ModulePreloadIfNeeded(
    const LinkLoadParameters& params,
    Document& document,
    const ViewportDescription* viewport_description,
    PendingLinkPreload* client) {
  if (!document.Loader() || !params.rel.IsModulePreload())
    return;

  UseCounter::Count(document, WebFeature::kLinkRelModulePreload);

  // Step 1. "If the href attribute's value is the empty string, then return."
  // [spec text]
  if (params.href.IsEmpty()) {
    document.AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
        mojom::blink::ConsoleMessageSource::kOther,
        mojom::blink::ConsoleMessageLevel::kWarning,
        "<link rel=modulepreload> has no `href` value"));
    return;
  }

  // Step 5. "Let settings object be the link element's node document's relevant
  // settings object." [spec text]
  // |document| is the node document here, and its context document is the
  // relevant settings object.
  LocalDOMWindow* window = To<LocalDOMWindow>(document.GetExecutionContext());
  Modulator* modulator =
      Modulator::From(ToScriptStateForMainWorld(window->GetFrame()));
  DCHECK(modulator);
  if (!modulator)
    return;

  // Step 2. "Let destination be the current state of the as attribute (a
  // destination), or "script" if it is in no state." [spec text]
  // Step 3. "If destination is not script-like, then queue a task on the
  // networking task source to fire an event named error at the link element,
  // and return." [spec text]
  // Currently we only support as="script".
  if (!params.as.empty() && params.as != "script") {
    document.AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
        mojom::blink::ConsoleMessageSource::kOther,
        mojom::blink::ConsoleMessageLevel::kWarning,
        String("<link rel=modulepreload> has an invalid `as` value " +
               params.as)));
    // This triggers the same logic as Step 11 asynchronously, which will fire
    // the error event.
    if (client) {
      modulator->TaskRunner()->PostTask(
          FROM_HERE,
          WTF::BindOnce(&SingleModuleClient::NotifyModuleLoadFinished,
                        WrapPersistent(client), nullptr));
    }
    return;
  }
  mojom::blink::RequestContextType context_type =
      mojom::blink::RequestContextType::SCRIPT;
  network::mojom::RequestDestination destination =
      network::mojom::RequestDestination::kScript;

  // Step 4. "Parse the URL given by the href attribute, relative to the
  // element's node document. If that fails, then return. Otherwise, let url be
  // the resulting URL record." [spec text]
  // |href| is already resolved in caller side.
  if (!params.href.IsValid()) {
    document.AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
        mojom::blink::ConsoleMessageSource::kOther,
        mojom::blink::ConsoleMessageLevel::kWarning,
        "<link rel=modulepreload> has an invalid `href` value " +
            params.href.GetString()));
    return;
  }

  // Preload only if media matches.
  // https://html.spec.whatwg.org/C/#processing-the-media-attribute
  if (!params.media.empty()) {
    MediaValuesCached* media_values =
        CreateMediaValues(document, viewport_description);
    if (!MediaMatches(params.media, media_values,
                      document.GetExecutionContext()))
      return;
  }

  // Step 6. "Let credentials mode be the module script credentials mode for the
  // crossorigin attribute." [spec text]
  network::mojom::CredentialsMode credentials_mode =
      ScriptLoader::ModuleScriptCredentialsMode(params.cross_origin);

  // Step 7. "Let cryptographic nonce be the value of the nonce attribute, if it
  // is specified, or the empty string otherwise." [spec text]
  // |nonce| parameter is the value of the nonce attribute.

  // Step 9. "Let integrity metadata be the value of the integrity attribute, if
  // it is specified, or the empty string otherwise." [spec text]
  IntegrityMetadataSet integrity_metadata;
  String integrity_value = params.integrity;
  if (!integrity_value.empty()) {
    SubresourceIntegrity::IntegrityFeatures integrity_features =
        SubresourceIntegrityHelper::GetFeatures(document.GetExecutionContext());
    SubresourceIntegrity::ReportInfo report_info;
    SubresourceIntegrity::ParseIntegrityAttribute(
        params.integrity, integrity_features, integrity_metadata, &report_info);
    SubresourceIntegrityHelper::DoReport(*document.GetExecutionContext(),
                                         report_info);
  } else if (integrity_value.IsNull()) {
    // Step 10. "If el does not have an integrity attribute, then set integrity
    // metadata to the result of resolving a module integrity metadata with url
    // and settings object." [spec text]
    integrity_value = modulator->GetIntegrityMetadataString(params.href);
    integrity_metadata = modulator->GetIntegrityMetadata(params.href);
  }

  // Step 11. "Let referrer policy be the current state of the element's
  // referrerpolicy attribute." [spec text]
  // |referrer_policy| parameter is the value of the referrerpolicy attribute.

  // Step 12. "Let options be a script fetch options whose cryptographic nonce
  // is cryptographic nonce, integrity metadata is integrity metadata, parser
  // metadata is "not-parser-inserted", credentials mode is credentials mode,
  // and referrer policy is referrer policy." [spec text]
  ModuleScriptFetchRequest request(
      params.href, ModuleType::kJavaScript, context_type, destination,
      ScriptFetchOptions(params.nonce, integrity_metadata, integrity_value,
                         kNotParserInserted, credentials_mode,
                         params.referrer_policy,
                         mojom::blink::FetchPriorityHint::kAuto,
                         RenderBlockingBehavior::kNonBlocking),
      Referrer::NoReferrer(), TextPosition::MinimumPosition());

  // Step 13. "Fetch a modulepreload module script graph given url, destination,
  // settings object, and options. Wait until the algorithm asynchronously
  // completes with result." [spec text]
  //
  modulator->SetAcquiringImportMapsState(
      Modulator::AcquiringImportMapsState::kAfterModuleScriptLoad);
  // Step 2. Fetch a single module script given ...
  modulator->FetchSingle(request, window->Fetcher(),
                         ModuleGraphLevel::kDependentModuleFetch,
                         ModuleScriptCustomFetchType::kNone, client);

  Settings* settings = document.GetSettings();
  if (settings && settings->GetLogPreload()) {
    document.AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
        mojom::blink::ConsoleMessageSource::kOther,
        mojom::blink::ConsoleMessageLevel::kVerbose,
        "Module preload triggered for " + params.href.Host() +
            params.href.GetPath()));
  }

  // Asynchronously continue processing after
  // client->NotifyModuleLoadFinished() is called.
}

void PreloadHelper::PrefetchIfNeeded(const LinkLoadParameters& params,
                                     Document& document,
                                     PendingLinkPreload* pending_preload) {
  if (document.Loader() && document.Loader()->Archive())
    return;

  if (!params.rel.IsLinkPrefetch() || !params.href.IsValid() ||
      !document.GetFrame())
    return;
  UseCounter::Count(document, WebFeature::kLinkRelPrefetch);

  ResourceRequest resource_request(params.href);

  bool as_document = EqualIgnoringASCIICase(params.as, "document");

  // If this corresponds to a preload that we promoted to a prefetch, and the
  // preload had `as="document"`, don't proceed because the original preload
  // statement was invalid.
  if (as_document && params.recursive_prefetch_token) {
    document.AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
        mojom::blink::ConsoleMessageSource::kOther,
        mojom::blink::ConsoleMessageLevel::kWarning,
        String("Link header with rel=preload and as=document is unsupported")));
    return;
  }

  // Later a security check is done asserting that the initiator of a
  // cross-origin prefetch request is same-origin with the origin that the
  // browser process is aware of. However, since opaque request initiators are
  // always cross-origin with every other origin, we must not request
  // cross-origin prefetches from opaque requestors.
  if (as_document &&
      !document.GetExecutionContext()->GetSecurityOrigin()->IsOpaque()) {
    resource_request.SetPrefetchMaybeForTopLevelNavigation(true);

    bool is_same_origin =
        document.GetExecutionContext()->GetSecurityOrigin()->IsSameOriginWith(
            SecurityOrigin::Create(params.href).get());
    UseCounter::Count(document,
                      is_same_origin
                          ? WebFeature::kLinkRelPrefetchAsDocumentSameOrigin
                          : WebFeature::kLinkRelPrefetchAsDocumentCrossOrigin);
  }

  // This request could have originally been a preload header on a prefetch
  // response, that was promoted to a prefetch request by LoadLinksFromHeader.
  // In that case, it may have a recursive prefetch token used by the browser
  // process to ensure this request is cached correctly. Propagate it.
  resource_request.SetRecursivePrefetchToken(params.recursive_prefetch_token);

  resource_request.SetReferrerPolicy(params.referrer_policy);
  resource_request.SetFetchPriorityHint(
      GetFetchPriorityAttributeValue(params.fetch_priority_hint));

  if (base::FeatureList::IsEnabled(features::kPrefetchPrivacyChanges)) {
    resource_request.SetRedirectMode(network::mojom::RedirectMode::kError);
    resource_request.SetReferrerPolicy(network::mojom::ReferrerPolicy::kNever);
    // TODO(domfarolino): Implement more privacy-preserving prefetch changes.
    // See crbug.com/988956.
  }
```