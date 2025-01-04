Response:
Let's break down the thought process for analyzing the provided C++ code and generating the comprehensive response.

**1. Understanding the Goal:**

The primary goal is to understand the functionality of `web_remote_frame_impl.cc` within the Chromium Blink rendering engine. This involves identifying its purpose, its relationship with web technologies (JavaScript, HTML, CSS), potential logical inferences, and common usage errors.

**2. Initial Code Scan and Keyword Identification:**

The first step is to quickly scan the code for relevant keywords and structures. This helps establish a high-level understanding. Key things I'd notice include:

* **`WebRemoteFrameImpl`:** This is the central class, so understanding its methods and interactions is crucial.
* **Includes:** The included headers provide hints about the class's dependencies and functionalities. I see references to:
    * `mojo`: Indicates inter-process communication (IPC).
    * `FrameReplicationState`: Suggests the class deals with synchronizing frame states across processes.
    * `WebDocument`, `WebElement`, `WebRange`:  Points to interactions with the DOM.
    * `LocalFrame`, `RemoteFrame`:  Indicates the existence of different frame types and the `WebRemoteFrameImpl` likely represents a remote one.
    * `WebView`:  Shows interaction with the overall browser view.
    * `PermissionsPolicy`: Hints at managing security policies.
    * `HTMLFrameOwnerElement`, `HTMLFencedFrameElement`: Indicates handling of `<iframe>` and `<fencedframe>` elements.
    * `v8/include/v8.h`: Direct interaction with the V8 JavaScript engine.
* **`Create`, `InitializeCoreFrame`, `SetReplicatedState`:** These methods appear to be core to the object's lifecycle and state management.
* **`IsWebLocalFrame`, `IsWebRemoteFrame`:**  Confirms the distinction between local and remote frames.

**3. Deconstructing the Functionality - Method by Method:**

Next, I'd systematically go through the key methods, trying to understand their individual roles and how they contribute to the overall functionality.

* **`Create...` methods:**  These methods are responsible for instantiating `WebRemoteFrameImpl` in different scenarios (main frame, fenced frames, regular remote children). They highlight the different contexts in which remote frames are created.
* **`InitializeCoreFrame`:** This seems like a crucial setup method. It takes many parameters related to frame hierarchy, ownership, and communication. The comment about `FrameVisualProperties` catches my attention, indicating a connection to rendering.
* **`SetReplicatedState`:** This method is clearly about synchronizing the state of the remote frame with the browser process. The fields in `FrameReplicationState` (origin, name, sandbox flags, permissions policy, etc.) are all vital pieces of frame information.
* **`GlobalProxy`:**  The inclusion of `v8::Local<v8::Object>` strongly suggests this method provides access to the JavaScript global object within the remote frame.
* **`View`, `GetCompositingRect`:** These suggest the class is involved in the visual representation and layout of the frame.
* **Other `Set...` methods:**  These are likely used to update specific properties of the remote frame.

**4. Identifying Relationships with Web Technologies:**

As I analyze the methods, I actively look for connections to JavaScript, HTML, and CSS.

* **JavaScript:** The `GlobalProxy` method directly links to JavaScript execution. The `opener` parameter in creation methods relates to `window.opener`. The concept of user gestures (`has_active_user_gesture`) is relevant to JavaScript event handling.
* **HTML:** The handling of `HTMLFrameOwnerElement` and `HTMLFencedFrameElement` establishes a direct relationship with the `<iframe>` and `<fencedframe>` HTML tags. The `name` parameter during frame creation corresponds to the `name` attribute of the `<iframe>`.
* **CSS:**  The mention of `FrameVisualProperties` (zoom level, CSS zoom factor, page scale factor) indicates involvement in the visual styling and layout controlled by CSS. `GetCompositingRect` is directly related to the rendering process.

**5. Logical Inference and Hypothetical Scenarios:**

Based on my understanding of the code, I can start inferring how different parts interact and construct hypothetical scenarios.

* **Inter-process Communication:**  The use of `mojo` is a clear indicator of IPC. I can infer that `WebRemoteFrameImpl` acts as a proxy or interface for a remote frame in another process. The `FrameReplicationState` is the data being passed back and forth.
* **Frame Hierarchy:**  The parameters like `parent`, `previous_sibling`, and the different `Create` methods demonstrate the handling of nested frames and the creation of the frame tree.
* **Security:** The presence of `PermissionsPolicy`, `SecurityOrigin`, and sandbox flags indicates that `WebRemoteFrameImpl` plays a role in enforcing security boundaries between different origins.

**6. Identifying Potential Usage Errors:**

Considering how the code is used and the complexity of web development, I can think of potential errors:

* **Incorrect Frame Hierarchy Management:** Creating child frames without properly setting the `opener` or sibling relationships could lead to unexpected behavior.
* **Security Policy Violations:**  Mismatched or incorrectly configured security policies on the parent and child frames could cause issues.
* **State Inconsistencies:**  If the `FrameReplicationState` is not properly synchronized, the remote frame might have an incorrect view of its properties.

**7. Structuring the Response:**

Finally, I organize the gathered information into a clear and structured response, covering the requested points:

* **Functionality Summary:** Provide a high-level overview of the class's purpose.
* **Relationship with Web Technologies:** Detail how the code interacts with JavaScript, HTML, and CSS, providing concrete examples.
* **Logical Inference:** Explain the underlying mechanisms and interactions, using hypothetical inputs and outputs where appropriate.
* **Common Usage Errors:**  List potential pitfalls for developers using this part of the Blink API.

**Self-Correction/Refinement:**

During the process, I might encounter areas where my understanding is incomplete or uncertain. For instance, I might not be entirely sure about the specific implications of `FrameVisualProperties`. In such cases, I would:

* **Re-examine the code and comments:** Look for more clues within the source file itself.
* **Consult related documentation or code:**  If available, I'd check the documentation for `FrameVisualProperties` or related classes. I might also look at how these classes are used in other parts of the Blink codebase.
* **Make educated assumptions and clearly state them:** If I can't find definitive answers, I'd make a reasonable assumption based on the available information and explicitly mention that it's an assumption.

By following this systematic approach, combining code analysis with domain knowledge about web technologies and browser architecture, I can generate a comprehensive and accurate response to the prompt.
This C++ source code file, `web_remote_frame_impl.cc`, within the Chromium Blink rendering engine defines the implementation for `WebRemoteFrameImpl`. `WebRemoteFrameImpl` represents a **remote frame** in the browser. A remote frame is an iframe or a fenced frame whose content is rendered in a **different process** than the parent frame. This is a key part of Chromium's process isolation architecture for security and stability.

Here's a breakdown of its functionalities:

**Core Functionality: Representing and Managing Remote Frames**

* **Creation and Initialization:**
    * Provides static methods like `Create`, `CreateMainFrame`, and `CreateForFencedFrame` to instantiate `WebRemoteFrameImpl` objects in various scenarios (main frame, iframe, fenced frame).
    * `InitializeCoreFrame` is a central method to set up the underlying `RemoteFrame` object, linking it to its parent, owner element, page, and setting up communication channels.
* **Inter-Process Communication (IPC):**
    * Uses Mojo for communication with the browser process and the process hosting the actual content of the remote frame. This involves sending and receiving messages related to the frame's state and actions.
    * Holds `mojo::PendingAssociatedRemote<mojom::blink::RemoteFrameHost>` for sending messages to the remote frame's host process.
    * Holds `mojo::PendingAssociatedReceiver<mojom::blink::RemoteFrame>` for receiving messages from the remote frame's host process.
* **State Management:**
    * Stores and manages the replicated state of the remote frame, such as its origin, name, sandbox flags, permissions policy, and ad frame status. This state is synchronized with the remote process.
    * The `SetReplicatedState` method updates the local representation of the remote frame's state based on information received from the remote process.
* **Frame Hierarchy Management:**
    * Provides methods like `CreateLocalChild` and `CreateRemoteChild` to create child frames (either local or remote) within the remote frame.
    * Tracks the frame's parent and previous sibling.
* **Visual Properties:**
    * Manages visual properties of the remote frame, like zoom level, page scale factor, and viewport information, which are often inherited from the parent frame's widget.
    * `InitializeFrameVisualProperties` propagates these properties to the underlying `RemoteFrame`.
* **Accessing Underlying Core Frame:**
    * Provides `GetFrame()` to access the underlying `RemoteFrame` object, which is the core representation of the frame within the Blink rendering engine.
* **Global Object Access:**
    * `GlobalProxy(v8::Isolate*)` provides access to the JavaScript global object of the remote frame. This is crucial for interacting with the JavaScript running within the remote frame.
* **Closing and Detachment:**
    * `Close(DetachReason)` handles the detachment and cleanup of the remote frame.
* **Identifying Frame Type:**
    * `IsWebLocalFrame()` and `IsWebRemoteFrame()` help determine the type of the frame.

**Relationship with JavaScript, HTML, and CSS:**

`WebRemoteFrameImpl` is **heavily intertwined** with JavaScript, HTML, and CSS, as it represents a container for loaded web content.

* **HTML:**
    * **`<iframe>` and `<fencedframe>`:**  `WebRemoteFrameImpl` instances are created when the browser encounters `<iframe>` or `<fencedframe>` elements in the HTML of the parent frame, and decides to render them in a separate process.
    * **Example:** When the browser parses HTML like `<iframe src="https://example.com"></iframe>`, a `WebRemoteFrameImpl` will be created to represent this iframe if it's cross-origin or requires process isolation for other reasons.
    * **Frame Names:** The `name` attribute of an `<iframe>` is replicated and managed by `WebRemoteFrameImpl` via methods like `SetReplicatedState`.
    * **Frame Owners:**  It interacts with `HTMLFrameOwnerElement` (the `<iframe>` or `<fencedframe>` element in the parent document) to establish the frame's context.
* **JavaScript:**
    * **Global Object Access:**  The `GlobalProxy()` method is fundamental for JavaScript interaction. It allows scripts in the parent frame (or browser extensions) to interact with the JavaScript environment within the remote frame (with proper security checks).
    * **`window.opener`:** The `opener` parameter in the `Create` methods relates to the `window.opener` property in JavaScript, allowing communication between the opening and opened frames (subject to security restrictions).
    * **User Gestures:**  The `has_active_user_gesture` and `has_received_user_gesture_before_nav` properties in the replicated state are relevant for JavaScript APIs that are gated by user activation (e.g., opening popups).
    * **Example:**  JavaScript in the parent frame might use `iframeElement.contentWindow.postMessage()` to send messages to the JavaScript in the remote frame. `WebRemoteFrameImpl` plays a role in facilitating this communication.
* **CSS:**
    * **Visual Properties:** The management of `FrameVisualProperties` (zoom, scale, viewport) directly affects how the content within the remote frame is rendered according to CSS rules.
    * **Compositing:** `GetCompositingRect()` returns the rectangle used for compositing the remote frame's content, influencing how it's layered and rendered with other elements on the page.
    * **Example:** If the parent frame has a specific zoom level, this zoom level will be propagated to the `WebRemoteFrameImpl` and affect the rendering of the content within the iframe.

**Logical Inference and Hypothetical Input/Output:**

**Scenario: Creating a cross-origin iframe**

* **Hypothetical Input:**
    * Parent frame in process A navigates to a page with the following HTML: `<iframe src="https://example.com"></iframe>`
* **Logical Inference:**
    1. The HTML parser in process A encounters the `<iframe>` tag.
    2. Based on the `src` attribute being cross-origin, the browser decides to create a new process (process B) for `https://example.com`.
    3. In process A, a `WebRemoteFrameImpl` object is created to represent this remote iframe.
    4. An IPC message is sent to the browser process, requesting the creation of a corresponding `RenderFrameHost` in process B.
    5. The browser process sets up the communication channels (Mojo) between the `WebRemoteFrameImpl` in process A and the `RenderFrameHost` in process B.
    6. The `FrameReplicationState` for the new iframe (origin, name, etc.) is sent from process B to process A and used to populate the `WebRemoteFrameImpl`.
* **Hypothetical Output (within `WebRemoteFrameImpl`):**
    * `IsWebRemoteFrame()` will return `true`.
    * `GetFrame()->IsRemote()` will likely return `true`.
    * The replicated origin will be `https://example.com`.
    * Initially, the frame might be in a loading state.

**Common Usage Errors (from a Blink developer perspective):**

* **Incorrectly Handling Frame Insertion:** Mistakes in the `FrameInsertType` or providing the wrong parent/sibling during `InitializeCoreFrame` can lead to incorrect frame hierarchy and rendering issues.
* **Not Synchronizing Replicated State:** Failing to properly update the replicated state or handle updates from the remote process can lead to inconsistencies between the local and remote frame representations.
    * **Example:** Forgetting to call `SetReplicatedState` when receiving updated sandbox flags from the remote process could lead to security vulnerabilities.
* **Leaking Remote Frame Objects:**  Improperly managing the lifecycle of `WebRemoteFrameImpl` objects (e.g., not closing them when the iframe is removed) can lead to memory leaks.
* **Making Assumptions About Execution Context:** Incorrectly assuming that code in `WebRemoteFrameImpl` runs in the same process as the iframe's content can lead to errors when trying to access local frame data.
* **Incorrectly Passing Mojo Interfaces:** Mishandling the `mojo::PendingAssociatedRemote` and `mojo::PendingAssociatedReceiver` objects can break the communication channel between the processes.
* **Ignoring Security Considerations:**  Blink developers need to be extremely careful when handling cross-process communication to avoid introducing security vulnerabilities. For example, validating data received from the remote process is crucial.

In summary, `web_remote_frame_impl.cc` is a critical component in Chromium's architecture for handling out-of-process iframes and fenced frames. It bridges the gap between the parent frame's process and the remote frame's process, managing state, communication, and visual properties while ensuring security and stability. Its functionality is deeply intertwined with how web content (HTML, CSS, JavaScript) is loaded and rendered within these isolated frames.

Prompt: 
```
这是目录为blink/renderer/core/frame/web_remote_frame_impl.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/frame/web_remote_frame_impl.h"

#include <utility>

#include "mojo/public/cpp/bindings/pending_remote.h"
#include "third_party/blink/public/common/frame/frame_visual_properties.h"
#include "third_party/blink/public/common/permissions_policy/permissions_policy.h"
#include "third_party/blink/public/common/storage_key/storage_key.h"
#include "third_party/blink/public/mojom/frame/frame_replication_state.mojom-blink.h"
#include "third_party/blink/public/mojom/frame/frame_replication_state.mojom.h"
#include "third_party/blink/public/mojom/frame/tree_scope_type.mojom-blink.h"
#include "third_party/blink/public/mojom/security_context/insecure_request_policy.mojom-blink.h"
#include "third_party/blink/public/web/web_document.h"
#include "third_party/blink/public/web/web_element.h"
#include "third_party/blink/public/web/web_frame_owner_properties.h"
#include "third_party/blink/public/web/web_range.h"
#include "third_party/blink/renderer/bindings/core/v8/window_proxy.h"
#include "third_party/blink/renderer/core/execution_context/remote_security_context.h"
#include "third_party/blink/renderer/core/execution_context/security_context.h"
#include "third_party/blink/renderer/core/exported/web_view_impl.h"
#include "third_party/blink/renderer/core/frame/csp/conversion_util.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/remote_frame_client_impl.h"
#include "third_party/blink/renderer/core/frame/remote_frame_owner.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/frame/web_frame_widget_impl.h"
#include "third_party/blink/renderer/core/frame/web_local_frame_impl.h"
#include "third_party/blink/renderer/core/html/fenced_frame/html_fenced_frame_element.h"
#include "third_party/blink/renderer/core/html/html_frame_owner_element.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/layout/layout_object.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/page/chrome_client.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/platform/bindings/dom_wrapper_world.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/wtf/text/atomic_string.h"
#include "ui/gfx/geometry/quad_f.h"
#include "v8/include/v8.h"

namespace blink {

namespace {
mojom::blink::FrameReplicationStatePtr ToBlinkFrameReplicationState(
    mojom::FrameReplicationStatePtr to_convert) {
  mojom::blink::FrameReplicationStatePtr result =
      mojom::blink::FrameReplicationState::New();
  result->origin = SecurityOrigin::CreateFromUrlOrigin(to_convert->origin);
  result->name = WebString::FromUTF8(to_convert->name);
  result->unique_name = WebString::FromUTF8(to_convert->unique_name);

  for (const auto& header : to_convert->permissions_policy_header)
    result->permissions_policy_header.push_back(header);

  result->active_sandbox_flags = to_convert->active_sandbox_flags;
  result->frame_policy = to_convert->frame_policy;
  result->insecure_request_policy = to_convert->insecure_request_policy;

  for (const auto& value : to_convert->insecure_navigations_set)
    result->insecure_navigations_set.push_back(value);

  result->has_potentially_trustworthy_unique_origin =
      to_convert->has_potentially_trustworthy_unique_origin;
  result->has_active_user_gesture = to_convert->has_active_user_gesture;
  result->has_received_user_gesture_before_nav =
      to_convert->has_received_user_gesture_before_nav;
  result->is_ad_frame = to_convert->is_ad_frame;
  return result;
}

}  // namespace

WebRemoteFrame* WebRemoteFrame::FromFrameToken(
    const RemoteFrameToken& frame_token) {
  auto* frame = RemoteFrame::FromFrameToken(frame_token);
  if (!frame)
    return nullptr;
  return WebRemoteFrameImpl::FromFrame(*frame);
}

WebRemoteFrame* WebRemoteFrame::Create(mojom::blink::TreeScopeType scope,
                                       const RemoteFrameToken& frame_token) {
  return MakeGarbageCollected<WebRemoteFrameImpl>(scope, frame_token);
}

// static
WebRemoteFrame* WebRemoteFrame::CreateMainFrame(
    WebView* web_view,
    const RemoteFrameToken& frame_token,
    bool is_loading,
    const base::UnguessableToken& devtools_frame_token,
    WebFrame* opener,
    CrossVariantMojoAssociatedRemote<mojom::blink::RemoteFrameHostInterfaceBase>
        remote_frame_host,
    CrossVariantMojoAssociatedReceiver<mojom::blink::RemoteFrameInterfaceBase>
        receiver,
    mojom::FrameReplicationStatePtr replicated_state) {
  return WebRemoteFrameImpl::CreateMainFrame(
      web_view, frame_token, is_loading, devtools_frame_token, opener,
      std::move(remote_frame_host), std::move(receiver),
      ToBlinkFrameReplicationState(std::move(replicated_state)));
}

// static
WebRemoteFrameImpl* WebRemoteFrameImpl::CreateMainFrame(
    WebView* web_view,
    const RemoteFrameToken& frame_token,
    bool is_loading,
    const base::UnguessableToken& devtools_frame_token,
    WebFrame* opener,
    mojo::PendingAssociatedRemote<mojom::blink::RemoteFrameHost>
        remote_frame_host,
    mojo::PendingAssociatedReceiver<mojom::blink::RemoteFrame> receiver,
    mojom::blink::FrameReplicationStatePtr replicated_state) {
  WebRemoteFrameImpl* frame = MakeGarbageCollected<WebRemoteFrameImpl>(
      mojom::blink::TreeScopeType::kDocument, frame_token);
  Page& page = *To<WebViewImpl>(web_view)->GetPage();
  // It would be nice to DCHECK that the main frame is not set yet here.
  // Unfortunately, there is an edge case with a pending RenderFrameHost that
  // violates this: the embedder may create a pending RenderFrameHost for
  // navigating to a new page in a popup. If the navigation ends up redirecting
  // to a site that requires a process swap, it doesn't go through the standard
  // swapping path and instead directly overwrites the main frame.
  // TODO(dcheng): Remove the need for this and strongly enforce this condition
  // with a DCHECK.
  frame->InitializeCoreFrame(
      page, nullptr, nullptr, nullptr, FrameInsertType::kInsertInConstructor,
      g_null_atom,
      opener ? &ToCoreFrame(*opener)->window_agent_factory() : nullptr,
      devtools_frame_token, std::move(remote_frame_host), std::move(receiver));
  frame->SetReplicatedState(std::move(replicated_state));
  Frame* opener_frame = opener ? ToCoreFrame(*opener) : nullptr;
  ToCoreFrame(*frame)->SetOpenerDoNotNotify(opener_frame);
  if (is_loading) {
    frame->DidStartLoading();
  }
  return frame;
}

WebRemoteFrameImpl* WebRemoteFrameImpl::CreateForFencedFrame(
    mojom::blink::TreeScopeType scope,
    const RemoteFrameToken& frame_token,
    const base::UnguessableToken& devtools_frame_token,
    HTMLFrameOwnerElement* frame_owner,
    mojo::PendingAssociatedRemote<mojom::blink::RemoteFrameHost>
        remote_frame_host,
    mojo::PendingAssociatedReceiver<mojom::blink::RemoteFrame> receiver,
    mojom::blink::FrameReplicationStatePtr replicated_state) {
  // We first convert this to a raw blink::Element*, and manually convert this
  // to an HTMLElement*. That is the only way the IsA<> and To<> casts below
  // will work.
  DCHECK(IsA<HTMLFencedFrameElement>(frame_owner));
  auto* frame = MakeGarbageCollected<WebRemoteFrameImpl>(scope, frame_token);
  ExecutionContext* execution_context = frame_owner->GetExecutionContext();
  DCHECK(RuntimeEnabledFeatures::FencedFramesEnabled(execution_context));
  LocalFrame* host_frame = frame_owner->GetDocument().GetFrame();
  frame->InitializeCoreFrame(
      *host_frame->GetPage(), frame_owner, /*parent=*/nullptr,
      /*previous_sibling=*/nullptr, FrameInsertType::kInsertInConstructor,
      g_null_atom, &host_frame->window_agent_factory(), devtools_frame_token,
      std::move(remote_frame_host), std::move(receiver));
  frame->SetReplicatedState(std::move(replicated_state));
  return frame;
}

WebRemoteFrameImpl::~WebRemoteFrameImpl() = default;

void WebRemoteFrameImpl::Trace(Visitor* visitor) const {
  visitor->Trace(frame_client_);
  visitor->Trace(frame_);
}

bool WebRemoteFrameImpl::IsWebLocalFrame() const {
  return false;
}

WebLocalFrame* WebRemoteFrameImpl::ToWebLocalFrame() {
  NOTREACHED();
}

const WebLocalFrame* WebRemoteFrameImpl::ToWebLocalFrame() const {
  NOTREACHED();
}

bool WebRemoteFrameImpl::IsWebRemoteFrame() const {
  return true;
}

WebRemoteFrame* WebRemoteFrameImpl::ToWebRemoteFrame() {
  return this;
}

const WebRemoteFrame* WebRemoteFrameImpl::ToWebRemoteFrame() const {
  return this;
}

void WebRemoteFrameImpl::Close(DetachReason detach_reason) {
  WebRemoteFrame::Close(detach_reason);

  self_keep_alive_.Clear();
}

WebView* WebRemoteFrameImpl::View() const {
  if (!GetFrame()) {
    return nullptr;
  }
  DCHECK(GetFrame()->GetPage());
  return GetFrame()->GetPage()->GetChromeClient().GetWebView();
}

WebLocalFrame* WebRemoteFrameImpl::CreateLocalChild(
    mojom::blink::TreeScopeType scope,
    const WebString& name,
    const FramePolicy& frame_policy,
    WebLocalFrameClient* client,
    InterfaceRegistry* interface_registry,
    WebFrame* previous_sibling,
    const WebFrameOwnerProperties& frame_owner_properties,
    const LocalFrameToken& frame_token,
    WebFrame* opener,
    const DocumentToken& document_token,
    CrossVariantMojoRemote<mojom::BrowserInterfaceBrokerInterfaceBase>
        interface_broker,
    std::unique_ptr<WebPolicyContainer> policy_container) {
  auto* child = MakeGarbageCollected<WebLocalFrameImpl>(
      base::PassKey<WebRemoteFrameImpl>(), scope, client, interface_registry,
      frame_token);
  auto* owner = MakeGarbageCollected<RemoteFrameOwner>(frame_policy,
                                                       frame_owner_properties);

  WindowAgentFactory* window_agent_factory = nullptr;
  if (opener) {
    window_agent_factory = &ToCoreFrame(*opener)->window_agent_factory();
  } else {
    window_agent_factory = &GetFrame()->window_agent_factory();
  }

  // TODO(https://crbug.com/1355751): Plumb the StorageKey from a value provided
  // by the browser process. This was attempted in patchset 6 of:
  // https://chromium-review.googlesource.com/c/chromium/src/+/3851381/6
  // A remote frame being asked to create a child only happens in some cases to
  // recover from a crash.
  StorageKey storage_key;

  child->InitializeCoreFrame(
      *GetFrame()->GetPage(), owner, this, previous_sibling,
      FrameInsertType::kInsertInConstructor, name, window_agent_factory, opener,
      document_token, std::move(interface_broker), std::move(policy_container),
      storage_key,
      /*creator_base_url=*/KURL());
  DCHECK(child->GetFrame());
  return child;
}

void WebRemoteFrameImpl::InitializeCoreFrame(
    Page& page,
    FrameOwner* owner,
    WebFrame* parent,
    WebFrame* previous_sibling,
    FrameInsertType insert_type,
    const AtomicString& name,
    WindowAgentFactory* window_agent_factory,
    const base::UnguessableToken& devtools_frame_token,
    mojo::PendingAssociatedRemote<mojom::blink::RemoteFrameHost>
        remote_frame_host,
    mojo::PendingAssociatedReceiver<mojom::blink::RemoteFrame>
        remote_frame_receiver) {
  Frame* parent_frame = parent ? ToCoreFrame(*parent) : nullptr;
  Frame* previous_sibling_frame =
      previous_sibling ? ToCoreFrame(*previous_sibling) : nullptr;

  // If this is not a top-level frame, we need to send FrameVisualProperties to
  // the remote renderer process. Some of the properties are inherited from the
  // WebFrameWidget containing this frame, and this is true for regular frames
  // in the frame tree as well as for fenced frames, which are not in the frame
  // tree; hence the code to traverse up through FrameOwner.
  WebFrameWidgetImpl* ancestor_widget = nullptr;
  if (parent) {
    if (parent->IsWebLocalFrame()) {
      ancestor_widget =
          To<WebLocalFrameImpl>(parent)->LocalRoot()->FrameWidgetImpl();
    }
  } else if (owner && owner->IsLocal()) {
    // Never gets to this point unless |owner| is a <fencedframe>
    // element.
    HTMLFrameOwnerElement* owner_element = To<HTMLFrameOwnerElement>(owner);
    DCHECK(owner_element->IsHTMLFencedFrameElement());
    LocalFrame& local_frame =
        owner_element->GetDocument().GetFrame()->LocalFrameRoot();
    ancestor_widget =
        WebLocalFrameImpl::FromFrame(local_frame)->FrameWidgetImpl();
  }

  SetCoreFrame(MakeGarbageCollected<RemoteFrame>(
      frame_client_.Get(), page, owner, parent_frame, previous_sibling_frame,
      insert_type, GetRemoteFrameToken(), window_agent_factory, ancestor_widget,
      devtools_frame_token, std::move(remote_frame_host),
      std::move(remote_frame_receiver)));

  if (ancestor_widget)
    InitializeFrameVisualProperties(ancestor_widget, View());

  GetFrame()->CreateView();
  frame_->Tree().SetName(name);
}

WebRemoteFrameImpl* WebRemoteFrameImpl::CreateRemoteChild(
    mojom::blink::TreeScopeType scope,
    const RemoteFrameToken& frame_token,
    bool is_loading,
    const base::UnguessableToken& devtools_frame_token,
    WebFrame* opener,
    mojo::PendingAssociatedRemote<mojom::blink::RemoteFrameHost>
        remote_frame_host,
    mojo::PendingAssociatedReceiver<mojom::blink::RemoteFrame> receiver,
    mojom::blink::FrameReplicationStatePtr replicated_state,
    mojom::blink::FrameOwnerPropertiesPtr owner_properties) {
  auto* child = MakeGarbageCollected<WebRemoteFrameImpl>(scope, frame_token);
  auto* owner = MakeGarbageCollected<RemoteFrameOwner>(
      replicated_state->frame_policy, WebFrameOwnerProperties());
  WindowAgentFactory* window_agent_factory = nullptr;
  if (opener) {
    window_agent_factory = &ToCoreFrame(*opener)->window_agent_factory();
  } else {
    window_agent_factory = &GetFrame()->window_agent_factory();
  }

  child->InitializeCoreFrame(*GetFrame()->GetPage(), owner, this, LastChild(),
                             FrameInsertType::kInsertInConstructor,
                             AtomicString(replicated_state->name),
                             window_agent_factory, devtools_frame_token,
                             std::move(remote_frame_host), std::move(receiver));
  child->SetReplicatedState(std::move(replicated_state));
  Frame* opener_frame = opener ? ToCoreFrame(*opener) : nullptr;
  ToCoreFrame(*child)->SetOpenerDoNotNotify(opener_frame);

  if (is_loading) {
    child->DidStartLoading();
  }

  DCHECK(owner_properties);
  child->SetFrameOwnerProperties(std::move(owner_properties));

  return child;
}

void WebRemoteFrameImpl::SetCoreFrame(RemoteFrame* frame) {
  frame_ = frame;
}

void WebRemoteFrameImpl::InitializeFrameVisualProperties(
    WebFrameWidgetImpl* ancestor_widget,
    WebView* web_view) {
  FrameVisualProperties visual_properties;
  visual_properties.zoom_level = ancestor_widget->GetZoomLevel();
  visual_properties.css_zoom_factor = ancestor_widget->GetCSSZoomFactor();
  visual_properties.page_scale_factor = ancestor_widget->PageScaleInMainFrame();
  visual_properties.is_pinch_gesture_active =
      ancestor_widget->PinchGestureActiveInMainFrame();
  visual_properties.screen_infos = ancestor_widget->GetOriginalScreenInfos();
  visual_properties.visible_viewport_size =
      ancestor_widget->VisibleViewportSizeInDIPs();
  const WebVector<gfx::Rect>& viewport_segments =
      ancestor_widget->ViewportSegments();
  visual_properties.root_widget_viewport_segments.assign(
      viewport_segments.begin(), viewport_segments.end());
  GetFrame()->InitializeFrameVisualProperties(visual_properties);
}

WebRemoteFrameImpl* WebRemoteFrameImpl::FromFrame(RemoteFrame& frame) {
  if (!frame.Client())
    return nullptr;
  RemoteFrameClientImpl* client =
      static_cast<RemoteFrameClientImpl*>(frame.Client());
  return client->GetWebFrame();
}

void WebRemoteFrameImpl::SetReplicatedOrigin(
    const WebSecurityOrigin& origin,
    bool is_potentially_trustworthy_opaque_origin) {
  DCHECK(GetFrame());
  GetFrame()->SetReplicatedOrigin(origin,
                                  is_potentially_trustworthy_opaque_origin);
}

void WebRemoteFrameImpl::DidStartLoading() {
  GetFrame()->DidStartLoading();
}

void WebRemoteFrameImpl::SetFrameOwnerProperties(
    mojom::blink::FrameOwnerPropertiesPtr owner_properties) {
  GetFrame()->SetFrameOwnerProperties(std::move(owner_properties));
}

v8::Local<v8::Object> WebRemoteFrameImpl::GlobalProxy(
    v8::Isolate* isolate) const {
  return GetFrame()
      ->GetWindowProxy(DOMWrapperWorld::MainWorld(isolate))
      ->GlobalProxyIfNotDetached()
      .ToLocalChecked();
}

gfx::Rect WebRemoteFrameImpl::GetCompositingRect() {
  return GetFrame()->View()->GetCompositingRect();
}

WebString WebRemoteFrameImpl::UniqueName() const {
  return GetFrame()->UniqueName();
}

const FrameVisualProperties&
WebRemoteFrameImpl::GetPendingVisualPropertiesForTesting() const {
  return GetFrame()->GetPendingVisualPropertiesForTesting();
}

bool WebRemoteFrameImpl::IsAdFrame() const {
  return GetFrame()->IsAdFrame();
}

WebRemoteFrameImpl::WebRemoteFrameImpl(mojom::blink::TreeScopeType scope,
                                       const RemoteFrameToken& frame_token)
    : WebRemoteFrame(scope, frame_token),
      frame_client_(MakeGarbageCollected<RemoteFrameClientImpl>(this)) {}

void WebRemoteFrameImpl::SetReplicatedState(
    mojom::FrameReplicationStatePtr replicated_state) {
  SetReplicatedState(ToBlinkFrameReplicationState(std::move(replicated_state)));
}

void WebRemoteFrameImpl::SetReplicatedState(
    mojom::blink::FrameReplicationStatePtr state) {
  RemoteFrame* remote_frame = GetFrame();
  DCHECK(remote_frame);

  remote_frame->SetReplicatedOrigin(
      state->origin, state->has_potentially_trustworthy_unique_origin);

#if DCHECK_IS_ON()
  scoped_refptr<const SecurityOrigin> security_origin_before_sandbox_flags =
      remote_frame->GetSecurityContext()->GetSecurityOrigin();
#endif

  remote_frame->DidSetFramePolicyHeaders(state->active_sandbox_flags,
                                         state->permissions_policy_header);

#if DCHECK_IS_ON()
  // If |state->has_potentially_trustworthy_unique_origin| is set,
  // - |state->origin| should be unique (this is checked in
  //   blink::SecurityOrigin::SetUniqueOriginIsPotentiallyTrustworthy() in
  //   SetReplicatedOrigin()), and thus
  // - The security origin is not updated by SetReplicatedSandboxFlags() and
  //   thus we don't have to apply |has_potentially_trustworthy_unique_origin|
  //   flag after SetReplicatedSandboxFlags().
  if (state->has_potentially_trustworthy_unique_origin) {
    DCHECK(security_origin_before_sandbox_flags ==
           remote_frame->GetSecurityContext()->GetSecurityOrigin());
  }
#endif

  remote_frame->SetReplicatedName(state->name, state->unique_name);
  remote_frame->SetInsecureRequestPolicy(state->insecure_request_policy);
  remote_frame->EnforceInsecureNavigationsSet(state->insecure_navigations_set);
  remote_frame->SetReplicatedIsAdFrame(state->is_ad_frame);

  if (state->has_active_user_gesture) {
    // TODO(crbug.com/1087963): This should be hearing about sticky activations
    // and setting those (as well as the active one?). But the call to
    // UpdateUserActivationState sets the transient activation.
    remote_frame->UpdateUserActivationState(
        mojom::UserActivationUpdateType::kNotifyActivation,
        mojom::UserActivationNotificationType::kMedia);
  }
  remote_frame->SetHadStickyUserActivationBeforeNavigation(
      state->has_received_user_gesture_before_nav);
}

}  // namespace blink

"""

```