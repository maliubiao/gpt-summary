Response:
Let's break down the thought process for analyzing this C++ Chromium source file.

**1. Initial Understanding of the Goal:**

The request asks for a comprehensive analysis of `html_media_element_encrypted_media.cc`. This means identifying its purpose, its interactions with web technologies (JavaScript, HTML, CSS), logical flow, potential errors, and how a user might trigger this code.

**2. Decomposition of the Request:**

I mentally broke the request into these key tasks:

* **Core Functionality:** What does this file *do*?  What problems does it solve?
* **Relationship to Web Technologies:** How does it connect with JavaScript, HTML, and CSS?  Concrete examples are needed.
* **Logical Reasoning:** Identify any decision-making processes or algorithms within the code. This often involves looking for conditional statements and state management. Hypothetical inputs and outputs would be useful here.
* **User/Programming Errors:** What mistakes can developers or users make that would involve this code?
* **User Path (Debugging):** How does a user action eventually lead to this code being executed? This requires tracing the flow from user interaction to the underlying C++ implementation.

**3. Code Analysis Strategy (Iterative Approach):**

I scanned the code, looking for key elements:

* **Includes:**  These provide clues about the file's dependencies and areas of focus (`media/base/eme_constants.h`, `third_party/blink/renderer/core/html/media/html_media_element.h`, `third_party/blink/renderer/modules/encryptedmedia/...`). The presence of "encryptedmedia" is a strong indicator of its primary function.
* **Class Names:** `HTMLMediaElementEncryptedMedia`, `SetMediaKeysHandler`, `SetContentDecryptionModuleResult` immediately suggest the file's role in managing encrypted media within the context of HTML media elements.
* **Method Names:**  `setMediaKeys`, `Encrypted`, `DidBlockPlaybackWaitingForKey`, `DidResumePlaybackBlockedForKey` reveal specific actions related to encrypted media playback.
* **Keywords and Concepts:**  "MediaKeys," "CDM" (Content Decryption Module), "promise," "encrypted," "initData," "waitingforkey," "CORS," "exceptions" are crucial terms.
* **Control Flow:** I looked for patterns like promise handling (`ScriptPromise`, `ScriptPromiseResolver`), callbacks, and state management (e.g., `is_attaching_media_keys_`, `is_waiting_for_key_`).
* **Logging (`DVLOG`):**  These provide insights into the execution flow and debugging information.

**4. Building the Functional Description:**

Based on the code analysis, I formulated the core functions:

* Managing the association between HTML media elements and `MediaKeys` objects (which represent CDMs).
* Handling the `setMediaKeys()` JavaScript API.
* Dispatching the `encrypted` event when encrypted media is encountered.
* Signaling when playback is blocked (`waitingforkey` event) and resumed due to key availability.

**5. Connecting to Web Technologies:**

* **JavaScript:** The `setMediaKeys()` function is a direct mapping to the JavaScript API. The `encrypted` and `waitingforkey` events are also JavaScript events. I looked for how the C++ code interacts with JavaScript promises and event dispatching.
* **HTML:** The code operates within the context of `<video>` and `<audio>` elements (`HTMLMediaElement`). The `crossorigin` attribute is explicitly mentioned in the CORS handling section.
* **CSS:** While not directly manipulating CSS, the playback blocking and resuming could indirectly affect the user experience, which might be styled with CSS (e.g., displaying a loading indicator).

**6. Logical Reasoning and Examples:**

The `SetMediaKeysHandler` class demonstrates a key logical process: the asynchronous setting of `MediaKeys`. I outlined the steps involved (checking for existing keys, reserving the new key, associating the CDM, etc.).

For input/output, I considered the `setMediaKeys()` function:

* **Input:** A `<video>` element and a `MediaKeys` object.
* **Output:** A JavaScript promise that resolves or rejects based on the success or failure of setting the `MediaKeys`.

**7. Identifying Potential Errors:**

I looked for error conditions and exception handling:

* Trying to set `MediaKeys` while another operation is in progress (`InvalidStateError`).
* Using a `MediaKeys` object that's already in use (`QuotaExceededError`).
* Issues with removing existing `MediaKeys` (`NotSupportedError`, `InvalidStateError`).
* Failures during CDM association.
* CORS issues preventing access to `initData`.

I then crafted user/programming error examples based on these conditions.

**8. Tracing User Operations:**

This involved thinking about the sequence of actions a user might take:

1. Embedding a `<video>` element with `src` pointing to encrypted media.
2. Writing JavaScript code to create and configure a `MediaKeys` object.
3. Calling `videoElement.setMediaKeys(mediaKeys)`.

I linked these steps to the corresponding C++ code execution within `html_media_element_encrypted_media.cc`.

**9. Refinement and Structure:**

Finally, I organized the information logically, using headings and bullet points for clarity. I ensured that the explanations were clear, concise, and provided concrete examples. I also paid attention to the specific phrasing of the request to ensure I addressed all aspects.

This iterative process of reading, analyzing, connecting concepts, and providing examples allowed me to generate a comprehensive explanation of the provided source code. The focus was on understanding the *why* and *how* of the code, not just the *what*.
This C++ source file, `html_media_element_encrypted_media.cc`, within the Chromium Blink engine implements the **Encrypted Media Extensions (EME)** functionality for HTML media elements (`<video>` and `<audio>`). Essentially, it provides the underlying mechanism for handling playback of DRM-protected (Digital Rights Management) media content within web browsers.

Here's a breakdown of its functionalities:

**Core Functionalities:**

1. **Managing `MediaKeys` Objects:**
   - It allows associating a `MediaKeys` object (representing a Content Decryption Module or CDM) with an HTML media element. This is done through the JavaScript `HTMLMediaElement.setMediaKeys()` method.
   - It handles the asynchronous nature of setting `MediaKeys`, ensuring proper sequencing and error handling.
   - It keeps track of the currently associated `MediaKeys` object for a given media element.
   - It manages the reservation and release of `MediaKeys` objects to prevent conflicts if a single `MediaKeys` is used with multiple media elements.

2. **Handling the `encrypted` Event:**
   - When the media element encounters encrypted data, the underlying media pipeline triggers a notification that eventually calls the `Encrypted()` method in this file.
   - This method creates and dispatches a `MediaEncryptedEvent` to the JavaScript context. This event contains information about the encryption, specifically the `initData` (initialization data) needed by the CDM to acquire a license.
   - It handles Cross-Origin Resource Sharing (CORS) considerations when dispatching the `encrypted` event. If the media is cross-origin and CORS headers are not properly set, the `initData` might be withheld from the event for security reasons.

3. **Managing Playback Blocking and Resumption due to Encryption:**
   - The `DidBlockPlaybackWaitingForKey()` method is called when the media player encounters encrypted data and needs a key to continue playback. It dispatches a `waitingforkey` event to the JavaScript context.
   - The `DidResumePlaybackBlockedForKey()` method is called when a necessary key becomes available, allowing playback to resume. It manages internal state related to waiting for keys.

**Relationship with JavaScript, HTML, and CSS:**

* **JavaScript:** This file directly implements the backend logic for the JavaScript `HTMLMediaElement.setMediaKeys()` method.
    - **Example:** When a JavaScript application calls `videoElement.setMediaKeys(mediaKeysObject)`, the execution flow will eventually reach the `HTMLMediaElementEncryptedMedia::setMediaKeys()` function in this C++ file.
    - The `encrypted` and `waitingforkey` events are dispatched to the JavaScript context, allowing JavaScript code to handle license acquisition and display appropriate UI.
    - **Example:** JavaScript code might listen for the `encrypted` event, extract the `initData`, and use it to communicate with a license server.
    - **Example:** JavaScript code might listen for the `waitingforkey` event and display a "Loading license..." message to the user.

* **HTML:** This code operates in the context of `<video>` and `<audio>` HTML elements.
    - The `setMediaKeys()` method is a property of the `HTMLMediaElement` interface.
    - The `crossorigin` attribute on the `<video>` or `<audio>` tag influences how the `encrypted` event is handled (specifically, whether `initData` is provided for cross-origin resources).
    - **Example:**  A `<video>` tag with encrypted content might look like: `<video src="encrypted_video.mp4"></video>`.

* **CSS:** While this C++ file doesn't directly interact with CSS, the events it triggers can be used by JavaScript to manipulate the visual presentation of the media element.
    - **Example:** When the `waitingforkey` event is fired, JavaScript could add a CSS class to the video element to display a loading spinner.

**Logical Reasoning and Examples (Hypothetical Input & Output):**

Let's focus on the `setMediaKeys()` function:

**Hypothetical Input:**

* `script_state`:  Represents the JavaScript execution context.
* `element`: A pointer to an `HTMLMediaElement` object (e.g., a `<video>` element).
* `media_keys`: A pointer to a `MediaKeys` object (representing a CDM).

**Logical Steps (Simplified):**

1. **Check if already attaching:** If another `setMediaKeys()` operation is in progress for this element, reject the promise with an `InvalidStateError`.
2. **Check if same `MediaKeys`:** If the provided `media_keys` is the same as the currently set one, resolve the promise immediately.
3. **Set attaching flag:** Mark that a `setMediaKeys()` operation is now in progress.
4. **Asynchronously handle `MediaKeys` setting:**  The `SetMediaKeysHandler` class is used to manage the asynchronous steps:
   - **Clear existing `MediaKeys`:** If there's an existing `MediaKeys` object, attempt to remove it. This involves communicating with the underlying media player.
   - **Set new `MediaKeys`:** Associate the new `MediaKeys` object with the media element. Again, this involves interaction with the media player.
5. **Update internal state:** Set the `mediaKeys_` member of the `HTMLMediaElementEncryptedMedia` object.
6. **Resolve the promise:** Indicate successful completion of the `setMediaKeys()` operation.

**Hypothetical Output:**

* A JavaScript `Promise` object.
    * **Success:** The promise resolves with `undefined`.
    * **Failure:** The promise rejects with a `DOMException` (e.g., `InvalidStateError`, `QuotaExceededError`, `NotSupportedError`).

**User or Programming Common Usage Errors:**

1. **Calling `setMediaKeys()` multiple times concurrently:**
   - **Error:**  The second call to `setMediaKeys()` will likely throw an `InvalidStateError` because the `is_attaching_media_keys_` flag will be true.
   - **User Scenario:** A web application might inadvertently trigger multiple calls to `setMediaKeys()` due to improper event handling or logic.

2. **Trying to use a `MediaKeys` object that is already in use by another media element:**
   - **Error:** The promise returned by `setMediaKeys()` will be rejected with a `QuotaExceededError`.
   - **User Scenario:** A developer might try to reuse the same `MediaKeys` object across multiple `<video>` elements without proper management.

3. **Not handling the `encrypted` event:**
   - **Error:**  Playback will likely fail because the browser won't know how to acquire the necessary decryption keys.
   - **User Scenario:** A developer might forget to implement the logic to handle the `encrypted` event and obtain a license.

4. **CORS issues preventing `initData` access:**
   - **Error:**  The `encrypted` event might be dispatched with empty `initData`, making it impossible to acquire a license if the media is cross-origin and the server doesn't send the correct CORS headers.
   - **User Scenario:** A developer might host encrypted media on a different domain without configuring proper CORS headers on the media server.

**How User Operations Lead Here (Debugging Clues):**

Let's consider a scenario where a user is trying to play an encrypted video:

1. **User opens a web page containing a `<video>` element with encrypted content.** The browser starts loading the video metadata.
2. **The browser's media pipeline encounters encrypted data.** This triggers an internal notification.
3. **The `Encrypted()` method in `html_media_element_encrypted_media.cc` is called.** This method creates and dispatches the `encrypted` event to the JavaScript context.
4. **JavaScript code on the page listens for the `encrypted` event.**
5. **The JavaScript code extracts the `initData` from the event.**
6. **The JavaScript code sends the `initData` to a license server.**
7. **The license server returns a license.**
8. **JavaScript code creates a `MediaKeySession` and calls `generateRequest()` with the license request type and `initData`.**
9. **The browser (specifically the CDM) processes the license request.**
10. **If the license is successfully acquired, the JavaScript code might call `mediaKeySession.update()` with the license data.**
11. **The browser's media pipeline can now use the acquired key to decrypt the video data.**
12. **If the browser encounters encrypted data again and needs a new key (e.g., for key rotation), the `DidBlockPlaybackWaitingForKey()` method might be called.** This triggers the `waitingforkey` event.

**Debugging Tips:**

* **Set breakpoints in `html_media_element_encrypted_media.cc`:** If you are working on the Chromium codebase, you can set breakpoints in functions like `Encrypted()`, `setMediaKeys()`, `DidBlockPlaybackWaitingForKey()`, and `DidResumePlaybackBlockedForKey()` to trace the execution flow and inspect variables.
* **Use `DVLOG` statements:** The code uses `DVLOG(EME_LOG_LEVEL)` for logging. Ensure that the `EME_LOG_LEVEL` is set appropriately during development to see detailed logs related to EME.
* **Inspect JavaScript console:** Look for `encrypted` and `waitingforkey` events in the browser's developer console. Check for any errors or warnings related to EME.
* **Examine network requests:** Inspect the network tab in the developer tools to see if license requests are being made and if the responses are successful.
* **Use EME-specific debugging tools:** Some browsers provide specific developer tools for inspecting EME-related information (e.g., key sessions, CDM information).

In summary, `html_media_element_encrypted_media.cc` is a crucial component for enabling DRM-protected content playback in web browsers. It bridges the gap between the JavaScript EME API and the underlying media pipeline, handling the complex interactions with CDMs and managing the lifecycle of encrypted media playback.

Prompt: 
```
这是目录为blink/renderer/modules/encryptedmedia/html_media_element_encrypted_media.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/encryptedmedia/html_media_element_encrypted_media.h"

#include "base/compiler_specific.h"
#include "base/containers/span.h"
#include "media/base/eme_constants.h"
#include "third_party/blink/public/platform/task_type.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_throw_dom_exception.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/html/media/html_media_element.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_typed_array.h"
#include "third_party/blink/renderer/modules/encryptedmedia/content_decryption_module_result_promise.h"
#include "third_party/blink/renderer/modules/encryptedmedia/encrypted_media_utils.h"
#include "third_party/blink/renderer/modules/encryptedmedia/media_encrypted_event.h"
#include "third_party/blink/renderer/modules/encryptedmedia/media_keys.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/content_decryption_module_result.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/heap/self_keep_alive.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"

#define EME_LOG_LEVEL 3

namespace blink {

// This class allows MediaKeys to be set asynchronously.
class SetMediaKeysHandler : public GarbageCollected<SetMediaKeysHandler> {
 public:
  static ScriptPromise<IDLUndefined> Create(ScriptState*,
                                            HTMLMediaElement&,
                                            MediaKeys*,
                                            const ExceptionContext&);

  SetMediaKeysHandler(ScriptState*,
                      HTMLMediaElement&,
                      MediaKeys*,
                      const ExceptionContext&);

  SetMediaKeysHandler(const SetMediaKeysHandler&) = delete;
  SetMediaKeysHandler& operator=(const SetMediaKeysHandler&) = delete;

  ~SetMediaKeysHandler();

  void Trace(Visitor*) const;

 private:
  void TimerFired(TimerBase*);

  void ClearExistingMediaKeys();
  void SetNewMediaKeys();

  void Finish();
  void Fail(WebContentDecryptionModuleException, const String& error_message);

  void ClearFailed(WebContentDecryptionModuleException,
                   const String& error_message);
  void SetFailed(WebContentDecryptionModuleException,
                 const String& error_message);

  Member<ScriptPromiseResolver<IDLUndefined>> resolver_;
  // Keep media element alive until promise is fulfilled
  Member<HTMLMediaElement> element_;
  Member<MediaKeys> new_media_keys_;
  bool made_reservation_;
  // Timer uses weak reference, so keep ourselves alive explicitly
  // while timer is pending.
  SelfKeepAlive<SetMediaKeysHandler> keep_alive_;
  HeapTaskRunnerTimer<SetMediaKeysHandler> timer_;
};

typedef base::OnceCallback<void()> SuccessCallback;
typedef base::OnceCallback<void(WebContentDecryptionModuleException,
                                const String&)>
    FailureCallback;

// Represents the result used when setContentDecryptionModule() is called.
// Calls |success| if result is resolved, |failure| if result is rejected.
class SetContentDecryptionModuleResult final
    : public ContentDecryptionModuleResult {
 public:
  SetContentDecryptionModuleResult(SuccessCallback success,
                                   FailureCallback failure)
      : success_callback_(std::move(success)),
        failure_callback_(std::move(failure)) {}

  // ContentDecryptionModuleResult implementation.
  void Complete() override {
    DVLOG(EME_LOG_LEVEL) << __func__ << ": promise resolved.";
    std::move(success_callback_).Run();
  }

  void CompleteWithContentDecryptionModule(
      std::unique_ptr<WebContentDecryptionModule>) override {
    NOTREACHED();
  }

  void CompleteWithSession(
      WebContentDecryptionModuleResult::SessionStatus status) override {
    NOTREACHED();
  }

  void CompleteWithKeyStatus(
      WebEncryptedMediaKeyInformation::KeyStatus key_status) override {
    NOTREACHED();
  }

  void CompleteWithError(WebContentDecryptionModuleException code,
                         uint32_t system_code,
                         const WebString& message) override {
    // Non-zero |systemCode| is appended to the |message|. If the |message|
    // is empty, we'll report "Rejected with system code (systemCode)".
    StringBuilder result;
    result.Append(message);
    if (system_code != 0) {
      if (result.empty())
        result.Append("Rejected with system code");
      result.Append(" (");
      result.AppendNumber(system_code);
      result.Append(')');
    }

    DVLOG(EME_LOG_LEVEL) << __func__ << ": promise rejected with code " << code
                         << " and message: " << result.ToString();

    std::move(failure_callback_).Run(code, result.ToString());
  }

 private:
  SuccessCallback success_callback_;
  FailureCallback failure_callback_;
};

ScriptPromise<IDLUndefined> SetMediaKeysHandler::Create(
    ScriptState* script_state,
    HTMLMediaElement& element,
    MediaKeys* media_keys,
    const ExceptionContext& exception_context) {
  SetMediaKeysHandler* handler = MakeGarbageCollected<SetMediaKeysHandler>(
      script_state, element, media_keys, exception_context);
  return handler->resolver_->Promise();
}

SetMediaKeysHandler::SetMediaKeysHandler(
    ScriptState* script_state,
    HTMLMediaElement& element,
    MediaKeys* media_keys,
    const ExceptionContext& exception_context)
    : resolver_(MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(
          script_state,
          exception_context)),
      element_(element),
      new_media_keys_(media_keys),
      made_reservation_(false),
      keep_alive_(this),
      timer_(ExecutionContext::From(script_state)
                 ->GetTaskRunner(TaskType::kMiscPlatformAPI),
             this,
             &SetMediaKeysHandler::TimerFired) {
  DVLOG(EME_LOG_LEVEL) << __func__;

  // 5. Run the following steps in parallel.
  timer_.StartOneShot(base::TimeDelta(), FROM_HERE);
}

SetMediaKeysHandler::~SetMediaKeysHandler() = default;

void SetMediaKeysHandler::TimerFired(TimerBase*) {
  keep_alive_.Clear();
  ClearExistingMediaKeys();
}

void SetMediaKeysHandler::ClearExistingMediaKeys() {
  DVLOG(EME_LOG_LEVEL) << __func__;
  HTMLMediaElementEncryptedMedia& this_element =
      HTMLMediaElementEncryptedMedia::From(*element_);

  // 5.1 If mediaKeys is not null, the CDM instance represented by
  //     mediaKeys is already in use by another media element, and
  //     the user agent is unable to use it with this element, let
  //     this object's attaching media keys value be false and
  //     reject promise with a QuotaExceededError.
  if (new_media_keys_) {
    if (!new_media_keys_->ReserveForMediaElement(element_.Get())) {
      this_element.is_attaching_media_keys_ = false;
      Fail(kWebContentDecryptionModuleExceptionQuotaExceededError,
           "The MediaKeys object is already in use by another media element.");
      return;
    }
    // Note that |m_newMediaKeys| is now considered reserved for
    // |m_element|, so it needs to be accepted or cancelled.
    made_reservation_ = true;
  }

  // 5.2 If the mediaKeys attribute is not null, run the following steps:
  if (this_element.media_keys_) {
    WebMediaPlayer* media_player = element_->GetWebMediaPlayer();
    if (media_player) {
      // 5.2.1 If the user agent or CDM do not support removing the
      //       association, let this object's attaching media keys
      //       value be false and reject promise with a NotSupportedError.
      // 5.2.2 If the association cannot currently be removed,
      //       let this object's attaching media keys value be false
      //       and reject promise with an InvalidStateError.
      // 5.2.3 Stop using the CDM instance represented by the mediaKeys
      //       attribute to decrypt media data and remove the association
      //       with the media element.
      // (All 3 steps handled as needed in Chromium.)
      SuccessCallback success_callback = WTF::BindOnce(
          &SetMediaKeysHandler::SetNewMediaKeys, WrapPersistent(this));
      FailureCallback failure_callback = WTF::BindOnce(
          &SetMediaKeysHandler::ClearFailed, WrapPersistent(this));
      ContentDecryptionModuleResult* result =
          MakeGarbageCollected<SetContentDecryptionModuleResult>(
              std::move(success_callback), std::move(failure_callback));
      media_player->SetContentDecryptionModule(nullptr, result->Result());

      // Don't do anything more until |result| is resolved (or rejected).
      return;
    }
  }

  // MediaKeys not currently set or no player connected, so continue on.
  SetNewMediaKeys();
}

void SetMediaKeysHandler::SetNewMediaKeys() {
  DVLOG(EME_LOG_LEVEL) << __func__;

  // 5.3 If mediaKeys is not null, run the following steps:
  if (new_media_keys_) {
    // 5.3.1 Associate the CDM instance represented by mediaKeys with the
    //       media element for decrypting media data.
    // 5.3.2 If the preceding step failed, run the following steps:
    //       (done in setFailed()).
    // 5.3.3 Queue a task to run the Attempt to Resume Playback If Necessary
    //       algorithm on the media element.
    //       (Handled in Chromium).
    if (element_->GetWebMediaPlayer()) {
      SuccessCallback success_callback =
          WTF::BindOnce(&SetMediaKeysHandler::Finish, WrapPersistent(this));
      FailureCallback failure_callback =
          WTF::BindOnce(&SetMediaKeysHandler::SetFailed, WrapPersistent(this));
      ContentDecryptionModuleResult* result =
          MakeGarbageCollected<SetContentDecryptionModuleResult>(
              std::move(success_callback), std::move(failure_callback));
      element_->GetWebMediaPlayer()->SetContentDecryptionModule(
          new_media_keys_->ContentDecryptionModule(), result->Result());

      // Don't do anything more until |result| is resolved (or rejected).
      return;
    }
  }

  // MediaKeys doesn't need to be set on the player, so continue on.
  Finish();
}

void SetMediaKeysHandler::Finish() {
  DVLOG(EME_LOG_LEVEL) << __func__;
  HTMLMediaElementEncryptedMedia& this_element =
      HTMLMediaElementEncryptedMedia::From(*element_);

  // 5.4 Set the mediaKeys attribute to mediaKeys.
  if (this_element.media_keys_)
    this_element.media_keys_->ClearMediaElement();
  this_element.media_keys_ = new_media_keys_;
  if (made_reservation_)
    new_media_keys_->AcceptReservation();

  // 5.5 Let this object's attaching media keys value be false.
  this_element.is_attaching_media_keys_ = false;

  // 5.6 Resolve promise with undefined.
  resolver_->Resolve();
}

void SetMediaKeysHandler::Fail(WebContentDecryptionModuleException code,
                               const String& error_message) {
  // Reset ownership of |m_newMediaKeys|.
  if (made_reservation_)
    new_media_keys_->CancelReservation();

  // Make sure attaching media keys value is false.
  DCHECK(!HTMLMediaElementEncryptedMedia::From(*element_)
              .is_attaching_media_keys_);

  // Reject promise with an appropriate error.
  WebCdmExceptionToPromiseRejection(resolver_, code, error_message);
}

void SetMediaKeysHandler::ClearFailed(WebContentDecryptionModuleException code,
                                      const String& error_message) {
  DVLOG(EME_LOG_LEVEL) << __func__ << "(" << code << ", " << error_message
                       << ")";
  HTMLMediaElementEncryptedMedia& this_element =
      HTMLMediaElementEncryptedMedia::From(*element_);

  // 5.2.4 If the preceding step failed, let this object's attaching media
  //      keys value be false and reject promise with an appropriate
  //      error name.
  this_element.is_attaching_media_keys_ = false;
  Fail(code, error_message);
}

void SetMediaKeysHandler::SetFailed(WebContentDecryptionModuleException code,
                                    const String& error_message) {
  DVLOG(EME_LOG_LEVEL) << __func__ << "(" << code << ", " << error_message
                       << ")";
  HTMLMediaElementEncryptedMedia& this_element =
      HTMLMediaElementEncryptedMedia::From(*element_);

  // 5.3.2 If the preceding step failed (in setContentDecryptionModule()
  //       called from setNewMediaKeys()), run the following steps:
  // 5.3.2.1 Set the mediaKeys attribute to null.
  this_element.media_keys_.Clear();

  // 5.3.2.2 Let this object's attaching media keys value be false.
  this_element.is_attaching_media_keys_ = false;

  // 5.3.2.3 Reject promise with a new DOMException whose name is the
  //         appropriate error name.
  Fail(code, error_message);
}

void SetMediaKeysHandler::Trace(Visitor* visitor) const {
  visitor->Trace(resolver_);
  visitor->Trace(element_);
  visitor->Trace(new_media_keys_);
  visitor->Trace(timer_);
}

// static
const char HTMLMediaElementEncryptedMedia::kSupplementName[] =
    "HTMLMediaElementEncryptedMedia";

HTMLMediaElementEncryptedMedia::HTMLMediaElementEncryptedMedia(
    HTMLMediaElement& element)
    : Supplement(element),
      is_waiting_for_key_(false),
      is_attaching_media_keys_(false) {}

HTMLMediaElementEncryptedMedia::~HTMLMediaElementEncryptedMedia() {
  DVLOG(EME_LOG_LEVEL) << __func__;
}

HTMLMediaElementEncryptedMedia& HTMLMediaElementEncryptedMedia::From(
    HTMLMediaElement& element) {
  HTMLMediaElementEncryptedMedia* supplement =
      Supplement<HTMLMediaElement>::From<HTMLMediaElementEncryptedMedia>(
          element);
  if (!supplement) {
    supplement = MakeGarbageCollected<HTMLMediaElementEncryptedMedia>(element);
    ProvideTo(element, supplement);
  }
  return *supplement;
}

MediaKeys* HTMLMediaElementEncryptedMedia::mediaKeys(
    HTMLMediaElement& element) {
  HTMLMediaElementEncryptedMedia& this_element =
      HTMLMediaElementEncryptedMedia::From(element);
  return this_element.media_keys_.Get();
}

ScriptPromise<IDLUndefined> HTMLMediaElementEncryptedMedia::setMediaKeys(
    ScriptState* script_state,
    HTMLMediaElement& element,
    MediaKeys* media_keys,
    ExceptionState& exception_state) {
  HTMLMediaElementEncryptedMedia& this_element =
      HTMLMediaElementEncryptedMedia::From(element);
  DVLOG(EME_LOG_LEVEL) << __func__ << ": current("
                       << this_element.media_keys_.Get() << "), new("
                       << media_keys << ")";

  // From http://w3c.github.io/encrypted-media/#setMediaKeys

  // 1. If this object's attaching media keys value is true, return a
  //    promise rejected with an InvalidStateError.
  if (this_element.is_attaching_media_keys_) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "Another request is in progress.");
    return EmptyPromise();
  }

  // 2. If mediaKeys and the mediaKeys attribute are the same object,
  //    return a resolved promise.
  if (this_element.media_keys_ == media_keys)
    return ToResolvedUndefinedPromise(script_state);

  // 3. Let this object's attaching media keys value be true.
  this_element.is_attaching_media_keys_ = true;

  // 4. Let promise be a new promise. Remaining steps done in handler.
  return SetMediaKeysHandler::Create(script_state, element, media_keys,
                                     exception_state.GetContext());
}

// Create a MediaEncryptedEvent for WD EME.
static Event* CreateEncryptedEvent(media::EmeInitDataType init_data_type,
                                   const unsigned char* init_data,
                                   unsigned init_data_length) {
  MediaEncryptedEventInit* initializer = MediaEncryptedEventInit::Create();
  initializer->setInitDataType(
      EncryptedMediaUtils::ConvertFromInitDataType(init_data_type));
  initializer->setInitData(DOMArrayBuffer::Create(
      UNSAFE_TODO(base::span(init_data, init_data_length))));
  initializer->setBubbles(false);
  initializer->setCancelable(false);

  return MakeGarbageCollected<MediaEncryptedEvent>(event_type_names::kEncrypted,
                                                   initializer);
}

void HTMLMediaElementEncryptedMedia::Encrypted(
    media::EmeInitDataType init_data_type,
    const unsigned char* init_data,
    unsigned init_data_length) {
  DVLOG(EME_LOG_LEVEL) << __func__;

  Event* event;
  if (GetSupplementable()->IsMediaDataCorsSameOrigin()) {
    event = CreateEncryptedEvent(init_data_type, init_data, init_data_length);
  } else {
    // Current page is not allowed to see content from the media file,
    // so don't return the initData. However, they still get an event.
    event = CreateEncryptedEvent(media::EmeInitDataType::UNKNOWN, nullptr, 0);
    GetSupplementable()->GetExecutionContext()->AddConsoleMessage(
        MakeGarbageCollected<ConsoleMessage>(
            mojom::ConsoleMessageSource::kJavaScript,
            mojom::ConsoleMessageLevel::kWarning,
            "Media element must be CORS-same-origin with "
            "the embedding page. If cross-origin, you "
            "should use the `crossorigin` attribute and "
            "make sure CORS headers on the media data "
            "response are CORS-same-origin."));
  }

  event->SetTarget(GetSupplementable());
  GetSupplementable()->ScheduleEvent(event);
}

void HTMLMediaElementEncryptedMedia::DidBlockPlaybackWaitingForKey() {
  DVLOG(EME_LOG_LEVEL) << __func__;

  // From https://w3c.github.io/encrypted-media/#queue-waitingforkey:
  // It should only be called when the HTMLMediaElement object is potentially
  // playing and its readyState is equal to HAVE_FUTURE_DATA or greater.
  // FIXME: Is this really required?

  // 1. Let the media element be the specified HTMLMediaElement object.
  // 2. If the media element's waiting for key value is false, queue a task
  //    to fire a simple event named waitingforkey at the media element.
  if (!is_waiting_for_key_) {
    Event* event = Event::Create(event_type_names::kWaitingforkey);
    event->SetTarget(GetSupplementable());
    GetSupplementable()->ScheduleEvent(event);
  }

  // 3. Set the media element's waiting for key value to true.
  is_waiting_for_key_ = true;

  // 4. Suspend playback.
  //    (Already done on the Chromium side by the decryptors.)
}

void HTMLMediaElementEncryptedMedia::DidResumePlaybackBlockedForKey() {
  DVLOG(EME_LOG_LEVEL) << __func__;

  // Logic is on the Chromium side to attempt to resume playback when a new
  // key is available. However, |m_isWaitingForKey| needs to be cleared so
  // that a later waitingForKey() call can generate the event.
  is_waiting_for_key_ = false;
}

WebContentDecryptionModule*
HTMLMediaElementEncryptedMedia::ContentDecryptionModule() {
  return media_keys_ ? media_keys_->ContentDecryptionModule() : nullptr;
}

void HTMLMediaElementEncryptedMedia::Trace(Visitor* visitor) const {
  visitor->Trace(media_keys_);
  Supplement<HTMLMediaElement>::Trace(visitor);
}

}  // namespace blink

"""

```