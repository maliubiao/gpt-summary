Response:
Let's break down the thought process to analyze the `svg_resource.cc` file.

1. **Understand the Goal:** The primary goal is to analyze the provided C++ source code and explain its functionality, especially its relationships with web technologies like JavaScript, HTML, and CSS. We also need to consider debugging, user errors, and logical implications.

2. **Identify the Core Class:** The file name `svg_resource.cc` and the initial code block clearly point to the central class: `SVGResource`. This will be the focal point of our analysis.

3. **Initial Read-through and Keyword Spotting:**  A quick skim reveals important keywords and concepts:
    * `SVG`:  Confirms the file's purpose is related to Scalable Vector Graphics.
    * `Client`: The code mentions adding and removing clients (`AddClient`, `RemoveClient`). This suggests a publisher-subscriber pattern.
    * `Observer`:  Similar to `Client`,  `AddObserver`, `RemoveObserver` indicate an observer pattern, specifically related to `ImageResourceObserver`.
    * `Cycle`:  Methods like `FindCycle` and `InvalidateCycleCache` suggest the code handles potential circular dependencies.
    * `Target`: The `target_` member variable and methods like `TargetChanged` suggest the resource refers to a specific element within an SVG.
    * `Loading`:  Methods like `IsLoading` indicate handling of asynchronous loading of external resources.
    * `Document`, `Element`, `TreeScope`: These are fundamental DOM concepts, linking the code to the HTML structure.
    * `KURL`: Indicates handling of URLs, essential for external resources.
    * `Fetch`:  Points to network requests for external resources.
    * `Content Security Policy (CSP)`:  Mentioned in `Load` and `LoadWithoutCSP`, indicating security considerations.

4. **Analyze Key Methods and Data Structures:** Now, go through the code more systematically, focusing on the purpose and interaction of key components:

    * **`SVGResource` Class:**
        * `AddClient`, `RemoveClient`:  Manage a list of clients interested in changes to the resource.
        * `NotifyContentChanged`:  Iterates through clients and informs them of changes.
        * `ResourceContainer`:  Deals with `LayoutSVGResourceContainer`, suggesting a link to the rendering engine. The cycle detection logic is important here.
        * `AddObserver`, `RemoveObserver`: Manage observers for image changes, possibly for scenarios where the SVG is used as an image.
        * `InvalidateCycleCache`, `FindCycle`: Implement cycle detection to prevent infinite loops, crucial for complex SVG structures.

    * **`LocalSVGResource` Class:**
        * Inherits from `SVGResource`.
        * `TargetChanged`:  Handles changes to the target element within the same document, likely in response to ID changes.
        * `Unregister`:  Cleans up the observer for the target element.

    * **`ExternalSVGResourceDocumentContent` Class:**
        * Handles loading SVG resources from external URLs.
        * `Load`, `LoadWithoutCSP`:  Initiate the loading process, considering CORS and CSP.
        * `ResourceNotifyFinished`, `ResourceContentChanged`:  Handle events after the external resource is loaded or changes.
        * `ResolveTarget`: Finds the specific element within the loaded external SVG based on the fragment identifier.

    * **`ExternalSVGResourceImageContent` Class:**
        * Handles SVG resources that are loaded as images.
        * `ResolveTarget`: Finds the target element within the loaded SVG image.
        * `ImageNotifyFinished`: Handles the event when the image loading is complete.

5. **Relate to Web Technologies (HTML, CSS, JavaScript):**  Now, connect the code's functionality to the web development context:

    * **HTML:** SVG is embedded in HTML. The code deals with identifying target elements within that SVG structure (`getElementById`). The loading of external SVG files is also relevant to HTML's embedding capabilities (e.g., `<img>`, `<object>`, `<iframe>` with SVG content).

    * **CSS:** CSS can style SVG elements and trigger re-renders. The `NotifyContentChanged` method and the client mechanism are directly related to how changes in the SVG resource propagate to the rendering engine, which CSS styling influences. The loading of external SVG via CSS `url()` is also relevant.

    * **JavaScript:** JavaScript can manipulate the DOM, including SVG elements. Changes made via JavaScript (e.g., changing an element's ID) could trigger the `TargetChanged` logic in `LocalSVGResource`. JavaScript can also trigger re-renders which might involve this code. The observer pattern could also be triggered by JavaScript-initiated changes.

6. **Consider Logical Reasoning and Examples:**  Think about scenarios where this code would be executed. For example:

    * **Scenario:** An SVG with a `<use>` element referencing another element within the same SVG. This would involve `LocalSVGResource` and the cycle detection mechanisms.
    * **Scenario:** An `<img>` tag with an SVG `url(#fragment)` as its source. This would involve `ExternalSVGResourceImageContent`.
    * **Scenario:** A CSS `background-image: url("image.svg#element");`. This would involve `ExternalSVGResourceDocumentContent`.

7. **Identify User/Programming Errors:** Think about common mistakes developers might make:

    * **Circular References:**  Creating SVG structures that refer to themselves, leading to infinite loops. The cycle detection is designed to prevent this.
    * **Incorrect Fragment Identifiers:**  Using a fragment identifier that doesn't exist in the external SVG.
    * **CORS Issues:**  Trying to load external SVG resources from a different origin without proper CORS headers.

8. **Debugging and User Actions:**  Consider how a developer might end up looking at this code during debugging:

    * **Problem:** An SVG is not rendering correctly, or updates are not being reflected.
    * **Debugging Steps:**  A developer might trace the flow of how changes are propagated, leading them to `NotifyContentChanged` and the client notification mechanism. They might also investigate why a target element isn't being found, bringing them to the `ResolveTarget` methods. Network issues with external SVGs could lead to inspecting the loading logic.

9. **Structure and Refine:** Finally, organize the gathered information into a clear and logical explanation, using headings, bullet points, and examples as provided in the desired output format. Ensure the language is precise and avoids jargon where possible. Review for clarity and completeness.
This C++ source code file, `svg_resource.cc`, within the Chromium Blink rendering engine, is responsible for managing **SVG resources**. An SVG resource is a piece of an SVG document that can be referenced and reused within other parts of the SVG or even from other documents. Think of things like `<filter>`, `<symbol>`, `<marker>`, `<pattern>`, or even individual elements with IDs that can be targeted by a fragment identifier.

Here's a breakdown of its functionalities:

**Core Functionalities:**

1. **Tracking Clients:**  It keeps track of different "clients" (`SVGResourceClient`) that are using or depending on a particular SVG resource. These clients could be layout objects (how the SVG is rendered), other SVG elements referencing this resource, or even image observers. This tracking is crucial for knowing when the resource is in use and needs to be kept alive.

2. **Notifying Clients of Changes:** When the content of an SVG resource changes, this file is responsible for notifying all the registered clients about the change. This ensures that the rendering and other dependent parts of the page are updated accordingly.

3. **Cycle Detection:**  SVG resources can have circular dependencies (e.g., filter A uses filter B, and filter B uses filter A). This file implements logic to detect such cycles (`FindCycle`) to prevent infinite loops and rendering issues.

4. **Managing Local and External Resources:** It handles both:
    * **Local Resources:** Resources defined within the same SVG document.
    * **External Resources:** Resources loaded from external SVG files or even SVG images.

5. **Observing Target Elements:** For local resources, it observes the target element within the DOM. If the target element (identified by its ID) changes (e.g., due to JavaScript manipulation), the resource is updated.

6. **Loading External Resources:** It manages the loading of external SVG resources, handling network requests, Content Security Policy (CSP) checks, and notifying clients when the resource is loaded or if an error occurs.

7. **Resolving Target Elements in External Resources:** When an external SVG is loaded, it resolves the specific target element within that document based on the fragment identifier in the URL (e.g., `url("external.svg#my-element")`).

8. **Integration with Layout:** It interacts with the layout engine (`LayoutSVGResourceContainer`) to manage the rendering aspects of the SVG resource.

**Relationship with JavaScript, HTML, and CSS:**

* **HTML:**
    * **Example:** When an SVG element in HTML uses a `<use>` element to reference a `<symbol>` defined elsewhere in the SVG (identified by its ID), this file is involved in finding and managing that `<symbol>` as an `SVGResource`. The `LocalSVGResource` class is specifically designed for this scenario.
    * **Example:**  An `<img>` tag or an `<object>` tag with an SVG file as its source might contain resources referenced internally. This file handles the loading and management of those internal resources.
    * **Example:**  An `<iframe>` element loading an SVG document will have its own `SVGResource` management within that frame.

* **CSS:**
    * **Example:**  When a CSS property like `fill` uses a `url()` to reference an SVG `<pattern>` or `<linearGradient>`, this file is responsible for fetching and managing that external or inline SVG resource. The `ExternalSVGResourceDocumentContent` class handles the fetching and loading.
        * **Hypothetical Input:** `background-image: url("#my-pattern");` (referencing a local pattern). The `LocalSVGResource` would be involved.
        * **Hypothetical Input:** `background-image: url("external.svg#my-pattern");` (referencing an external pattern). The `ExternalSVGResourceDocumentContent` would be involved.
        * **Hypothetical Output:**  The `SVGResource` object would hold a pointer to the target element (`<pattern id="my-pattern">`) and notify the CSS rendering engine when the pattern's definition changes.
    * **Example:** CSS animations or transitions that affect SVG properties might trigger updates that involve notifying clients managed by this file.

* **JavaScript:**
    * **Example:** JavaScript can dynamically modify the attributes of SVG elements, including IDs. If a `<use>` element's `xlink:href` attribute is changed via JavaScript to point to a different resource, or if the ID of a target element is changed, the `LocalSVGResource::TargetChanged` method will be invoked to update the resource.
        * **Hypothetical Input:** JavaScript code: `document.getElementById('myUseElement').setAttribute('xlink:href', '#anotherSymbol');`
        * **Hypothetical Output:** The `SVGResource` associated with 'myUseElement' will update its target to the element with the ID 'anotherSymbol', and clients (like the layout object rendering the `<use>`) will be notified.
    * **Example:** JavaScript can trigger reflows or repaints, which might involve re-evaluating and re-rendering SVG resources.
    * **Example:**  JavaScript interacting with the DOM might indirectly cause external SVG resources to be loaded if a new element referencing them is added to the page.

**Logical Reasoning with Hypothetical Input and Output:**

Let's consider a scenario with an inline SVG and a `<use>` element:

**Hypothetical Input (HTML):**

```html
<svg>
  <defs>
    <symbol id="mySymbol" viewBox="0 0 10 10">
      <circle cx="5" cy="5" r="4" fill="red" />
    </symbol>
  </defs>
  <use xlink:href="#mySymbol" x="10" y="10" />
</svg>
```

**Processing within `svg_resource.cc`:**

1. When the `<use>` element is parsed, it creates an `SVGResourceClient`.
2. The `xlink:href="#mySymbol"` triggers the creation of a `LocalSVGResource` associated with the ID "mySymbol".
3. `SVGURIReference::ObserveTarget` is used to find the element with ID "mySymbol" within the current tree scope.
4. The `LocalSVGResource` stores a pointer to the `<symbol>` element.
5. The layout object for the `<use>` element registers as a client of the `LocalSVGResource`.

**Hypothetical Input (JavaScript Modification):**

```javascript
document.getElementById('mySymbol').querySelector('circle').setAttribute('fill', 'blue');
```

**Processing within `svg_resource.cc`:**

1. The change to the `<circle>` element's `fill` attribute triggers a mutation event.
2. This mutation event propagates, and the `LocalSVGResource` associated with "mySymbol" is notified of the content change.
3. `LocalSVGResource::NotifyContentChanged` is called.
4. The clients of this resource (including the layout object for the `<use>` element) are notified.
5. The layout object then re-renders the `<use>` element, now using the updated `<symbol>` with the blue circle.

**User or Programming Common Usage Errors:**

1. **Circular Dependencies:**  Creating SVG filters or other resources that depend on each other in a loop. This can lead to performance problems or even crashes. The cycle detection in `svg_resource.cc` aims to mitigate this.
    * **Example:** `<filter id="filterA"><feGaussianBlur in="SourceGraphic" stdDeviation="5" result="blurB"/></filter>` and `<filter id="filterB"><feGaussianBlur in="SourceGraphic" stdDeviation="5" filter="url(#filterA)"/></filter>`. This creates a cycle, and the `FindCycle` method would detect this.

2. **Incorrect Fragment Identifiers:**  Referring to non-existent IDs in `url()` references.
    * **Example:** `background-image: url("my.svg#nonExistentId");`. The `ExternalSVGResourceDocumentContent::ResolveTarget` method would return null, and the resource would likely fail to load or render correctly.

3. **CORS Issues with External Resources:**  Trying to load SVG resources from a different origin without proper CORS headers on the server.
    * **Example:** A CSS rule like `background-image: url("https://another-domain.com/image.svg");` might fail if the server at `another-domain.com` doesn't send the `Access-Control-Allow-Origin` header. The `ExternalSVGResourceDocumentContent::Load` method handles CORS checks.

4. **Modifying External SVG Files After Loading:**  If an external SVG file is loaded and then modified on the server, the browser might not automatically pick up the changes unless proper caching headers are set or the page is reloaded. This isn't directly an error in this code, but a common pitfall.

**User Operation Steps to Reach This Code (Debugging Scenario):**

Let's say a developer is debugging an issue where an SVG filter is not being applied correctly. Here's a possible sequence:

1. **User Action:** The user loads a web page containing an SVG with a filter applied.
2. **Problem:** The filter effect is missing or looks wrong.
3. **Developer Investigation (Browser DevTools):**
    * The developer inspects the SVG element in the browser's developer tools.
    * They see a `filter: url(#myFilter)` style applied.
    * They might check the "Network" tab to see if the SVG file (if external) was loaded correctly.
    * They might examine the `<filter>` element definition in the "Elements" tab.
4. **Debugging (Potentially Stepping into Blink Code):**
    * If the developer suspects a problem in how the browser is handling the SVG resource, they might try to step through the browser's rendering code (if they have a Chromium development environment set up).
    * They might set breakpoints in related code, such as the code that applies filters or handles `url()` references.
    * **Breakpoint in `svg_resource.cc`:**  A breakpoint could be set in `SVGResource::NotifyContentChanged` to see when and why the filter resource is being updated. They might also set a breakpoint in `LocalSVGResource::TargetChanged` if the filter definition is within the same SVG and its ID might be changing unexpectedly.
    * **Tracing the `url()` resolution:** If the filter is external, they might trace the execution flow within `ExternalSVGResourceDocumentContent::Load` and `ExternalSVGResourceDocumentContent::ResolveTarget` to see if the external resource is being fetched correctly and if the target filter element is being found.
    * **Investigating cycle detection:** If the filter involves complex dependencies, the developer might investigate the `SVGResource::FindCycle` method to see if a cycle is being detected and preventing the filter from being applied.

In essence, this file is a crucial part of the Blink rendering engine's SVG support, ensuring that SVG resources are correctly loaded, managed, updated, and that dependencies are handled appropriately to enable the proper rendering of SVG content on web pages.

Prompt: 
```
这是目录为blink/renderer/core/svg/svg_resource.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/svg/svg_resource.h"

#include "services/network/public/mojom/content_security_policy.mojom-blink.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/dom/id_target_observer.h"
#include "third_party/blink/renderer/core/dom/tree_scope.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/layout/svg/layout_svg_resource_container.h"
#include "third_party/blink/renderer/core/loader/resource/image_resource_content.h"
#include "third_party/blink/renderer/core/svg/graphics/svg_image.h"
#include "third_party/blink/renderer/core/svg/svg_resource_client.h"
#include "third_party/blink/renderer/core/svg/svg_resource_document_content.h"
#include "third_party/blink/renderer/core/svg/svg_uri_reference.h"
#include "third_party/blink/renderer/platform/bindings/script_forbidden_scope.h"
#include "third_party/blink/renderer/platform/loader/fetch/fetch_initiator_type_names.h"
#include "third_party/blink/renderer/platform/loader/fetch/fetch_parameters.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource.h"

namespace blink {

SVGResource::SVGResource() = default;

SVGResource::~SVGResource() = default;

void SVGResource::Trace(Visitor* visitor) const {
  visitor->Trace(target_);
  visitor->Trace(clients_);
  visitor->Trace(observer_wrappers_);
}

void SVGResource::AddClient(SVGResourceClient& client) {
  auto& entry = clients_.insert(&client, ClientEntry()).stored_value->value;
  entry.count++;
  entry.cached_cycle_check = kNeedCheck;
  if (LayoutSVGResourceContainer* container = ResourceContainerNoCycleCheck())
    container->ClearInvalidationMask();
}

void SVGResource::RemoveClient(SVGResourceClient& client) {
  auto it = clients_.find(&client);
  CHECK_NE(it, clients_.end());
  it->value.count--;
  if (it->value.count)
    return;
  clients_.erase(it);
  // The last instance of |client| was removed. Clear its entry in
  // resource's cache.
  if (LayoutSVGResourceContainer* container = ResourceContainerNoCycleCheck())
    container->RemoveClientFromCache(client);
}

class SVGResource::ImageResourceObserverWrapper
    : public GarbageCollected<SVGResource::ImageResourceObserverWrapper>,
      public SVGResourceClient {
 public:
  explicit ImageResourceObserverWrapper(ImageResourceObserver& observer)
      : observer_(observer) {}

  void IncRef() { count_++; }
  bool DecRef() {
    --count_;
    return count_ == 0;
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(observer_);
    SVGResourceClient::Trace(visitor);
  }

 private:
  void ResourceContentChanged(SVGResource* resource) override {
    observer_->ImageChanged(static_cast<WrappedImagePtr>(resource),
                            ImageResourceObserver::CanDeferInvalidation::kNo);
  }

  Member<ImageResourceObserver> observer_;
  int count_ = 0;
};

void SVGResource::AddObserver(ImageResourceObserver& observer) {
  auto& wrapper =
      observer_wrappers_.insert(&observer, nullptr).stored_value->value;
  if (!wrapper) {
    wrapper = MakeGarbageCollected<ImageResourceObserverWrapper>(observer);
    AddClient(*wrapper);
  }
  wrapper->IncRef();
}

void SVGResource::RemoveObserver(ImageResourceObserver& observer) {
  auto it = observer_wrappers_.find(&observer);
  CHECK_NE(it, observer_wrappers_.end());
  if (it->value->DecRef()) {
    RemoveClient(*it->value);
    observer_wrappers_.erase(it);
  }
}

SVGResourceClient* SVGResource::GetObserverResourceClient(
    ImageResourceObserver& observer) {
  auto it = observer_wrappers_.find(&observer);
  return it != observer_wrappers_.end() ? it->value : nullptr;
}

void SVGResource::InvalidateCycleCache() {
  for (auto& client_entry : clients_.Values())
    client_entry.cached_cycle_check = kNeedCheck;
}

void SVGResource::NotifyContentChanged() {
  InvalidateCycleCache();

  HeapVector<Member<SVGResourceClient>> clients;
  CopyKeysToVector(clients_, clients);

  for (SVGResourceClient* client : clients)
    client->ResourceContentChanged(this);
}

LayoutSVGResourceContainer* SVGResource::ResourceContainerNoCycleCheck() const {
  if (!target_)
    return nullptr;
  return DynamicTo<LayoutSVGResourceContainer>(target_->GetLayoutObject());
}

LayoutSVGResourceContainer* SVGResource::ResourceContainer(
    SVGResourceClient& client) const {
  auto it = clients_.find(&client);
  if (it == clients_.end())
    return nullptr;
  auto* container = ResourceContainerNoCycleCheck();
  if (!container)
    return nullptr;
  ClientEntry& entry = it->value;
  if (entry.cached_cycle_check == kNeedCheck) {
    entry.cached_cycle_check = kPerformingCheck;
    bool has_cycle = container->FindCycle();
    DCHECK_EQ(entry.cached_cycle_check, kPerformingCheck);
    entry.cached_cycle_check = has_cycle ? kHasCycle : kNoCycle;
  }
  if (entry.cached_cycle_check == kHasCycle)
    return nullptr;
  DCHECK_EQ(entry.cached_cycle_check, kNoCycle);
  return container;
}

bool SVGResource::FindCycle(SVGResourceClient& client) const {
  auto it = clients_.find(&client);
  if (it == clients_.end())
    return false;
  auto* container = ResourceContainerNoCycleCheck();
  if (!container)
    return false;
  ClientEntry& entry = it->value;
  switch (entry.cached_cycle_check) {
    case kNeedCheck: {
      entry.cached_cycle_check = kPerformingCheck;
      bool has_cycle = container->FindCycle();
      DCHECK_EQ(entry.cached_cycle_check, kPerformingCheck);
      // Update our cached state based on the result of FindCycle(), but don't
      // signal a cycle since ResourceContainer() will consider the resource
      // invalid if one is present, thus we break the cycle at this resource.
      entry.cached_cycle_check = has_cycle ? kHasCycle : kNoCycle;
      return false;
    }
    case kNoCycle: {
      entry.cached_cycle_check = kPerformingCheck;
      bool has_cycle = container->FindCycle();
      DCHECK_EQ(entry.cached_cycle_check, kPerformingCheck);
      entry.cached_cycle_check = kNoCycle;
      return has_cycle;
    }
    case kPerformingCheck:
      // If we're on the current checking path, signal a cycle.
      return true;
    case kHasCycle:
      // We have a cached result, but don't signal a cycle since
      // ResourceContainer() will consider the resource invalid if one is
      // present.
      return false;
  }
}

LocalSVGResource::LocalSVGResource(TreeScope& tree_scope,
                                   const AtomicString& id)
    : tree_scope_(tree_scope) {
  target_ = SVGURIReference::ObserveTarget(
      id_observer_, tree_scope, id,
      WTF::BindRepeating(&LocalSVGResource::TargetChanged,
                         WrapWeakPersistent(this), id));
}

void LocalSVGResource::Unregister() {
  SVGURIReference::UnobserveTarget(id_observer_);
}

void LocalSVGResource::NotifyFilterPrimitiveChanged(
    SVGFilterPrimitiveStandardAttributes& primitive,
    const QualifiedName& attribute) {
  HeapVector<Member<SVGResourceClient>> clients;
  CopyKeysToVector(clients_, clients);

  for (SVGResourceClient* client : clients)
    client->FilterPrimitiveChanged(this, primitive, attribute);
}

void LocalSVGResource::TargetChanged(const AtomicString& id) {
  Element* new_target = tree_scope_->getElementById(id);
  if (new_target == target_)
    return;
  // Clear out caches on the old resource, and then notify clients about the
  // change.
  LayoutSVGResourceContainer* old_resource = ResourceContainerNoCycleCheck();
  if (old_resource)
    old_resource->RemoveAllClientsFromCache();
  target_ = new_target;
  NotifyContentChanged();
}

void LocalSVGResource::Trace(Visitor* visitor) const {
  visitor->Trace(tree_scope_);
  visitor->Trace(id_observer_);
  SVGResource::Trace(visitor);
}

ExternalSVGResourceDocumentContent::ExternalSVGResourceDocumentContent(
    const KURL& url)
    : url_(url) {}

void ExternalSVGResourceDocumentContent::Load(
    Document& document,
    CrossOriginAttributeValue cross_origin) {
  if (document_content_)
    return;
  // Loading SVG resources should not trigger script, see
  // https://crbug.com/1196853 This could be allowed if DOMContentLoaded and
  // other checkpoints were asynchronous per https://crbug.com/961428
  ScriptForbiddenScope forbid_script;
  ExecutionContext* execution_context = document.GetExecutionContext();
  ResourceLoaderOptions options(execution_context->GetCurrentWorld());
  options.initiator_info.name = fetch_initiator_type_names::kCSS;
  FetchParameters params(ResourceRequest(url_), options);
  if (cross_origin == kCrossOriginAttributeNotSet) {
    params.MutableResourceRequest().SetMode(
        network::mojom::blink::RequestMode::kSameOrigin);
  } else {
    params.SetCrossOriginAccessControl(execution_context->GetSecurityOrigin(),
                                       cross_origin);
  }
  document_content_ = SVGResourceDocumentContent::Fetch(params, document);
  if (!document_content_) {
    return;
  }
  document_content_->AddObserver(this);
  target_ = ResolveTarget();
}

void ExternalSVGResourceDocumentContent::LoadWithoutCSP(Document& document) {
  if (document_content_)
    return;
  // Loading SVG resources should not trigger script, see
  // https://crbug.com/1196853 This could be allowed if DOMContentLoaded and
  // other checkpoints were asynchronous per https://crbug.com/961428
  ScriptForbiddenScope forbid_script;
  ExecutionContext* execution_context = document.GetExecutionContext();
  ResourceLoaderOptions options(execution_context->GetCurrentWorld());
  options.initiator_info.name = fetch_initiator_type_names::kCSS;
  FetchParameters params(ResourceRequest(url_), options);
  params.SetContentSecurityCheck(
      network::mojom::blink::CSPDisposition::DO_NOT_CHECK);
  params.MutableResourceRequest().SetMode(
      network::mojom::blink::RequestMode::kSameOrigin);
  document_content_ = SVGResourceDocumentContent::Fetch(params, document);
  if (!document_content_) {
    return;
  }
  document_content_->AddObserver(this);
  target_ = ResolveTarget();
}

void ExternalSVGResourceDocumentContent::ResourceNotifyFinished(
    SVGResourceDocumentContent* document_content) {
  DCHECK_EQ(document_content_, document_content);
  Element* new_target = ResolveTarget();
  // If no target was found when resolving in Load(), we want to notify clients
  // regardless of if a target was found or not, to be able to update rendering
  // based on loading state.
  if (target_ && new_target == target_) {
    return;
  }
  target_ = new_target;
  NotifyContentChanged();
}

void ExternalSVGResourceDocumentContent::ResourceContentChanged(
    SVGResourceDocumentContent* document_content) {
  DCHECK_EQ(document_content_, document_content);
  if (!target_) {
    return;
  }
  NotifyContentChanged();
}

bool ExternalSVGResourceDocumentContent::IsLoading() const {
  return !document_content_ || document_content_->IsLoading();
}

Element* ExternalSVGResourceDocumentContent::ResolveTarget() {
  if (!document_content_)
    return nullptr;
  if (!url_.HasFragmentIdentifier())
    return nullptr;
  Document* external_document = document_content_->GetDocument();
  if (!external_document)
    return nullptr;
  AtomicString decoded_fragment(DecodeURLEscapeSequences(
      url_.FragmentIdentifier(), DecodeURLMode::kUTF8OrIsomorphic));
  return external_document->getElementById(decoded_fragment);
}

void ExternalSVGResourceDocumentContent::Trace(Visitor* visitor) const {
  visitor->Trace(document_content_);
  SVGResource::Trace(visitor);
}

ExternalSVGResourceImageContent::ExternalSVGResourceImageContent(
    ImageResourceContent* image_content,
    const AtomicString& fragment)
    : image_content_(image_content), fragment_(fragment) {
  image_content_->AddObserver(this);
}

void ExternalSVGResourceImageContent::Prefinalize() {
  image_content_->DidRemoveObserver();
  image_content_ = nullptr;
}

bool ExternalSVGResourceImageContent::IsLoading() const {
  return image_content_->IsLoading();
}

Element* ExternalSVGResourceImageContent::ResolveTarget() {
  if (!image_content_->IsLoaded() || image_content_->ErrorOccurred()) {
    return nullptr;
  }
  if (!fragment_) {
    return nullptr;
  }
  auto* svg_image = DynamicTo<SVGImage>(image_content_->GetImage());
  if (!svg_image) {
    return nullptr;
  }
  AtomicString decoded_fragment(
      DecodeURLEscapeSequences(fragment_, DecodeURLMode::kUTF8OrIsomorphic));
  return svg_image->GetResourceElement(decoded_fragment);
}

void ExternalSVGResourceImageContent::ImageNotifyFinished(
    ImageResourceContent*) {
  Element* new_target = ResolveTarget();
  // If no target was found when resolving in Load(), we want to notify clients
  // regardless of if a target was found or not, to be able to update rendering
  // based on loading state.
  if (target_ && new_target == target_) {
    return;
  }
  target_ = new_target;
  NotifyContentChanged();
}

String ExternalSVGResourceImageContent::DebugName() const {
  return "ExternalSVGResourceImageContent";
}

void ExternalSVGResourceImageContent::Trace(Visitor* visitor) const {
  visitor->Trace(image_content_);
  SVGResource::Trace(visitor);
  ImageResourceObserver::Trace(visitor);
}

}  // namespace blink

"""

```