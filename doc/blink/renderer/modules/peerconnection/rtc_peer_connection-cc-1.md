Response:
The user wants to understand the functionality of the provided C++ code snippet from `rtc_peer_connection.cc`. This is part 2 of a 4-part series, so I need to summarize the functionality present in this specific part.

Here's a breakdown of the code and its functions:

1. **`createOffer` (Promise-based and Callback-based):**  These functions initiate the offer creation process for establishing a WebRTC connection. They interact with the underlying WebRTC engine to generate the SDP offer.
2. **`createAnswer` (Promise-based and Callback-based):** These functions initiate the answer creation process, responding to a received offer. They also interact with the WebRTC engine to generate the SDP answer.
3. **`checkSdpForStateErrors`:** This function validates Session Description Protocol (SDP) strings against the current state of the `RTCPeerConnection` to detect invalid modifications or state issues.
4. **`ActiveIceTransports`:** This function retrieves a set of currently active ICE transports associated with the peer connection.
5. **`GenerateCertificateCompleted`:** A callback function used when generating a new TLS certificate for the peer connection.
6. **`UpdateIceConnectionState`:**  This function checks and updates the current ICE connection state.
7. **`setLocalDescription` (Promise-based and Callback-based):**  These functions set the local end's session description (SDP), which describes the local media capabilities.
8. **`localDescription`, `currentLocalDescription`, `pendingLocalDescription`:** Accessor methods to get the current and pending local descriptions.
9. **`setRemoteDescription` (Promise-based and Callback-based):** These functions set the remote end's session description (SDP), received from the other peer.
10. **`remoteDescription`, `currentRemoteDescription`, `pendingRemoteDescription`:** Accessor methods to get the current and pending remote descriptions.
11. **`getConfiguration`:** This function retrieves the current configuration of the `RTCPeerConnection`, such as ICE servers and policies.
12. **`setConfiguration`:** This function allows updating the configuration of the `RTCPeerConnection`. It includes checks for valid modifications.
13. **`generateCertificate`:** This function initiates the generation of a new TLS certificate using WebCrypto API parameters.
14. **`addIceCandidate` (Promise-based and Callback-based):** These functions add ICE candidates (network address information) gathered during the ICE process to the peer connection.

Based on these functions, the main functionalities in this part are:

*   **SDP Offer/Answer Creation:**  Generating and handling the initial negotiation details.
*   **SDP Validation:** Checking the validity and consistency of SDP strings.
*   **Local/Remote Description Handling:** Setting and accessing the local and remote session descriptions.
*   **Configuration Management:** Retrieving and setting the `RTCPeerConnection`'s configuration.
*   **Certificate Generation:** Creating new TLS certificates for secure communication.
*   **ICE Candidate Handling:** Adding ICE candidates to facilitate network connectivity.
好的，这是 Chromium Blink 引擎 `RTCPeerConnection.cc` 文件的第二部分，主要功能集中在以下几个方面：

**核心功能归纳:**

*   **创建和处理 SDP Offer 和 Answer:**  这部分代码包含了创建 SDP (Session Description Protocol) Offer 和 Answer 的核心逻辑。这是 WebRTC 连接建立过程中的关键步骤，用于协商媒体能力和连接参数。
*   **设置和管理本地及远端会话描述 (Local and Remote Descriptions):** 提供了设置本地和远端 SDP 的功能，以及访问当前和待处理的 SDP 描述。这是连接建立和更新媒体流的重要组成部分。
*   **配置管理:**  包含了获取和设置 `RTCPeerConnection` 配置的功能，例如 ICE 服务器、ICE 策略、捆绑策略等。
*   **证书生成:**  允许为 `RTCPeerConnection` 生成新的 TLS 证书，用于安全连接。
*   **添加 ICE Candidate:** 提供了向 `RTCPeerConnection` 添加 ICE (Interactive Connectivity Establishment) Candidate 的功能，用于帮助建立网络连接。
*   **SDP 状态检查和错误处理:**  实现了对 SDP 的状态错误检查，例如在连接关闭状态下的操作，以及对 SDP 内容的修改检查。
*   **ICE Transport 管理:**  跟踪和管理活跃的 ICE Transport。

**与 Javascript, HTML, CSS 的关系及举例说明:**

这部分代码直接关联到 WebRTC API，这些 API 在 JavaScript 中暴露给开发者，用于创建和管理实时的音视频和数据通信。

*   **`createOffer()` 和 `createAnswer()`:**
    *   **JavaScript:** 开发者在 JavaScript 中调用 `RTCPeerConnection.createOffer()` 来发起 Offer 的创建，或调用 `RTCPeerConnection.createAnswer()` 来响应收到的 Offer。
    *   **HTML:**  HTML 可能包含触发这些 JavaScript 调用的用户界面元素，例如一个 "发起通话" 或 "接受通话" 的按钮。
    *   **CSS:** CSS 可以用来样式化这些按钮，使其更易于用户交互。
    *   **例子:**
        ```javascript
        // JavaScript
        const peerConnection = new RTCPeerConnection();
        document.getElementById('callButton').addEventListener('click', async () => {
          try {
            const offer = await peerConnection.createOffer();
            await peerConnection.setLocalDescription(offer);
            // 将 offer 发送给远端
            console.log('Generated offer:', offer.sdp);
          } catch (error) {
            console.error('Failed to create offer:', error);
          }
        });
        ```

*   **`setLocalDescription()` 和 `setRemoteDescription()`:**
    *   **JavaScript:**  开发者使用 `RTCPeerConnection.setLocalDescription(sdp)` 设置本地 SDP，并使用 `RTCPeerConnection.setRemoteDescription(sdp)` 设置从远端接收到的 SDP。
    *   **HTML:**  可能没有直接的 HTML 关联，但通常与接收和发送 SDP 消息的网络通信相关联。
    *   **CSS:** 无直接关联。
    *   **例子:**
        ```javascript
        // JavaScript (接收到远端 Offer 后)
        peerConnection.addEventListener('negotiationneeded', async () => {
          try {
            const offer = await peerConnection.createOffer();
            await peerConnection.setLocalDescription(offer);
            // 将 offer 发送给远端
          } catch (error) {
            console.error('Failed to create offer:', error);
          }
        });

        // JavaScript (接收到远端 Answer 后)
        async function handleRemoteAnswer(answerSdp) {
          try {
            await peerConnection.setRemoteDescription(new RTCSessionDescription({ type: 'answer', sdp: answerSdp }));
          } catch (error) {
            console.error('Failed to set remote description:', error);
          }
        }
        ```

*   **`getConfiguration()` 和 `setConfiguration()`:**
    *   **JavaScript:** 开发者可以使用 `RTCPeerConnection.getConfiguration()` 获取当前配置，并使用 `RTCPeerConnection.setConfiguration(config)` 设置新的配置。
    *   **HTML:**  配置项可能在 HTML 中通过表单等元素收集，然后传递给 JavaScript。
    *   **CSS:** 用于样式化配置表单。
    *   **例子:**
        ```javascript
        // JavaScript
        const config = peerConnection.getConfiguration();
        console.log('Current configuration:', config);

        const newConfig = {
          iceServers: [
            { urls: 'stun:stun.example.org' }
          ]
        };
        peerConnection.setConfiguration(newConfig);
        ```

*   **`addIceCandidate()`:**
    *   **JavaScript:**  当 ICE 框架发现新的 Candidate 时，会触发 `icecandidate` 事件，开发者在事件处理函数中使用 `RTCPeerConnection.addIceCandidate(candidate)` 将其添加到连接中。
    *   **HTML:**  可能没有直接的 HTML 关联，但与网络连接状态的展示可能有关。
    *   **CSS:** 用于样式化网络连接状态的指示器。
    *   **例子:**
        ```javascript
        // JavaScript
        peerConnection.addEventListener('icecandidate', event => {
          if (event.candidate) {
            // 将 candidate 发送给远端
            console.log('New ICE candidate:', event.candidate.candidate);
          }
        });

        async function handleRemoteCandidate(candidate) {
          try {
            await peerConnection.addIceCandidate(candidate);
          } catch (error) {
            console.error('Error adding remote candidate:', error);
          }
        }
        ```

**逻辑推理与假设输入输出:**

*   **`checkSdpForStateErrors`:**
    *   **假设输入:**  一个 `ExecutionContext` 对象和一个 `ParsedSessionDescription` 对象。
    *   **假设场景:** 在 `setLocalDescription` 或 `setRemoteDescription` 时，用户尝试设置一个新的 SDP。
    *   **输出:** 如果 SDP 与当前状态冲突（例如在 `signalingState` 为 `closed` 时尝试设置），则返回一个 `DOMException` 对象；如果 SDP 是对本地 SDP 的合法修改，则返回 `nullptr`。
    *   **例子:**
        *   **输入:** `signaling_state_` 为 `closed`, `parsed_sdp.type()` 为 `"offer"`。
        *   **输出:** 返回一个 `DOMException`，错误代码为 `kInvalidStateError`，消息为 `kSignalingStateClosedMessage`。
        *   **输入:** `signaling_state_` 为 `stable`,  `parsed_sdp.type()` 为 `"offer"`, `parsed_sdp.sdp()` 与 `last_offer_` 不同但指纹匹配失败。
        *   **输出:** 返回一个 `DOMException`，错误代码为 `kInvalidModificationError`，消息为 `kModifiedSdpMessage`。

**用户或编程常见的使用错误:**

*   **在 `signalingState` 为 `closed` 时调用 `createOffer` 或 `createAnswer`:**  用户可能在连接已经关闭后，仍然尝试创建新的 Offer 或 Answer。
    *   **错误示例:**  在 `RTCPeerConnection.close()` 被调用后，JavaScript 代码仍然尝试调用 `peerConnection.createOffer()`。
    *   **代码中的处理:** 代码会检查 `signaling_state_`，如果为 `closed`，则会抛出 `InvalidStateError` 异常。
*   **在错误的信令状态下设置 Local 或 Remote Description:**  WebRTC 的信令过程有明确的状态转换。例如，在没有收到 Offer 的情况下尝试设置 Answer 可能会导致错误。
    *   **错误示例:**  在 `signalingState` 不是 `have-local-offer` 或 `have-remote-offer` 时，尝试调用 `setRemoteDescription` 并传入一个 `answer` 类型的 SDP。
    *   **代码中的处理:**  `checkSdpForStateErrors` 函数会进行部分检查，但更严格的状态管理由 WebRTC 引擎处理。
*   **修改已经设置的本地或远端 SDP 并再次设置:**  直接修改已经设置的 SDP 字符串并尝试重新设置通常是不允许的或会导致问题。
    *   **错误示例:**  获取 `peerConnection.localDescription.sdp`，手动修改字符串，然后再次调用 `peerConnection.setLocalDescription()`。
    *   **代码中的处理:** `checkSdpForStateErrors` 会检测到指纹不匹配，并可能抛出 `InvalidModificationError`。
*   **不正确的 ICE Candidate 格式:**  提供的 ICE Candidate 字符串格式不正确会导致添加失败。
    *   **错误示例:**  从信令服务器接收到的 Candidate 字符串存在格式错误，例如缺少必要的字段或格式不符合规范。
    *   **代码中的处理:** 底层的 WebRTC 引擎会解析 ICE Candidate，如果格式不正确，添加操作会失败，并可能触发错误回调。
*   **配置项设置错误:**  尝试设置不支持的配置项或提供无效的配置值。
    *   **错误示例:**  尝试设置一个不存在的 `iceTransportPolicy` 值。
    *   **代码中的处理:** `setConfiguration` 函数会调用 `ParseConfiguration` 来解析配置，如果配置无效，会抛出 `SyntaxError` 或 `InvalidModificationError`。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户发起或接收通话:** 用户点击网页上的 "发起通话" 或 "接受通话" 按钮。
2. **JavaScript 调用 `RTCPeerConnection` API:**  按钮的点击事件触发 JavaScript 代码，该代码创建 `RTCPeerConnection` 对象。
3. **创建 Offer 或 Answer:**
    *   **发起方:** JavaScript 调用 `peerConnection.createOffer()`，最终会调用到 `RTCPeerConnection::createOffer` 方法。
    *   **接收方:** JavaScript 接收到远端的 Offer 后，调用 `peerConnection.createAnswer()`，最终会调用到 `RTCPeerConnection::createAnswer` 方法。
4. **设置本地描述:**  JavaScript 调用 `peerConnection.setLocalDescription(offer)` 或 `peerConnection.setLocalDescription(answer)`，会调用到 `RTCPeerConnection::setLocalDescription`。
5. **设置远端描述:** JavaScript 接收到远端的 SDP 后，调用 `peerConnection.setRemoteDescription(remoteOffer)` 或 `peerConnection.setRemoteDescription(remoteAnswer)`，会调用到 `RTCPeerConnection::setRemoteDescription`。
6. **添加 ICE Candidate:**  当 `icecandidate` 事件触发时，JavaScript 调用 `peerConnection.addIceCandidate(candidate)`，会调用到 `RTCPeerConnection::addIceCandidate`。
7. **获取或设置配置:** 用户可能通过页面上的设置界面修改 WebRTC 的配置，JavaScript 调用 `peerConnection.getConfiguration()` 或 `peerConnection.setConfiguration()`，会调用到 `RTCPeerConnection::getConfiguration` 或 `RTCPeerConnection::setConfiguration`。
8. **证书生成 (不常见):**  某些应用可能需要动态生成证书，JavaScript 调用 `peerConnection.generateCertificate()`，会调用到 `RTCPeerConnection::generateCertificate`。

通过查看 JavaScript 代码中对 `RTCPeerConnection` API 的调用顺序和参数，结合浏览器的开发者工具中的网络请求和控制台输出，可以逐步追踪到 `RTCPeerConnection.cc` 中相应的 C++ 代码的执行。例如，在 `createOffer` 调用失败时，可以检查 JavaScript 的错误回调，并查看是否有相关的 Blink 日志输出，从而定位到 `RTCPeerConnection::createOffer` 中可能抛出异常的位置。

总而言之，这部分代码是 `RTCPeerConnection` 接口的核心实现，负责处理 WebRTC 连接建立和维护的关键信令过程，并与底层的 WebRTC 引擎进行交互。

### 提示词
```
这是目录为blink/renderer/modules/peerconnection/rtc_peer_connection.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      kSignalingStateClosedMessage);
    return EmptyPromise();
  }
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<RTCSessionDescriptionInit>>(
          script_state, exception_state.GetContext());
  auto promise = resolver->Promise();
  RTCSessionDescriptionRequest* request =
      RTCSessionDescriptionRequestPromiseImpl::Create(this, resolver);

  ExecutionContext* context = ExecutionContext::From(script_state);
  UseCounter::Count(context, WebFeature::kRTCPeerConnectionCreateOffer);
  UseCounter::Count(context, WebFeature::kRTCPeerConnectionCreateOfferPromise);
  if (options->hasOfferToReceiveAudio() || options->hasOfferToReceiveVideo()) {
    UseCounter::Count(
        context,
        WebFeature::kRTCPeerConnectionCreateOfferOptionsOfferToReceive);
  }

  auto platform_transceivers = peer_handler_->CreateOffer(
      request, ConvertToRTCOfferOptionsPlatform(options));
  for (auto& platform_transceiver : platform_transceivers)
    CreateOrUpdateTransceiver(std::move(platform_transceiver));
  return promise;
}

ScriptPromise<IDLUndefined> RTCPeerConnection::createOffer(
    ScriptState* script_state,
    V8RTCSessionDescriptionCallback* success_callback,
    V8RTCPeerConnectionErrorCallback* error_callback,
    const RTCOfferOptions* options,
    ExceptionState& exception_state) {
  DCHECK(success_callback);
  DCHECK(error_callback);
  ExecutionContext* context = ExecutionContext::From(script_state);
  UseCounter::Count(context, WebFeature::kRTCPeerConnectionCreateOffer);
  UseCounter::Count(
      context, WebFeature::kRTCPeerConnectionCreateOfferLegacyFailureCallback);
  UseCounter::Count(context,
                    WebFeature::kRTCPeerConnectionCreateOfferLegacyCompliant);
  if (CallErrorCallbackIfSignalingStateClosed(context, signaling_state_,
                                              error_callback))
    return ToResolvedUndefinedPromise(script_state);

  RTCSessionDescriptionRequest* request =
      RTCSessionDescriptionRequestImpl::Create(
          GetExecutionContext(), this, success_callback, error_callback);

  Vector<std::unique_ptr<RTCRtpTransceiverPlatform>> platform_transceivers =
      peer_handler_->CreateOffer(request,
                                 ConvertToRTCOfferOptionsPlatform(options));
  for (auto& platform_transceiver : platform_transceivers)
    CreateOrUpdateTransceiver(std::move(platform_transceiver));

  return ToResolvedUndefinedPromise(script_state);
}

ScriptPromise<RTCSessionDescriptionInit> RTCPeerConnection::createAnswer(
    ScriptState* script_state,
    const RTCAnswerOptions* options,
    ExceptionState& exception_state) {
  if (signaling_state_ ==
      webrtc::PeerConnectionInterface::SignalingState::kClosed) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      kSignalingStateClosedMessage);
    return EmptyPromise();
  }

  ExecutionContext* context = ExecutionContext::From(script_state);
  UseCounter::Count(context, WebFeature::kRTCPeerConnectionCreateAnswer);
  UseCounter::Count(context, WebFeature::kRTCPeerConnectionCreateAnswerPromise);

  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<RTCSessionDescriptionInit>>(
          script_state, exception_state.GetContext());
  auto promise = resolver->Promise();
  RTCSessionDescriptionRequest* request =
      RTCSessionDescriptionRequestPromiseImpl::Create(this, resolver);
  peer_handler_->CreateAnswer(request,
                              ConvertToRTCAnswerOptionsPlatform(options));
  return promise;
}

ScriptPromise<IDLUndefined> RTCPeerConnection::createAnswer(
    ScriptState* script_state,
    V8RTCSessionDescriptionCallback* success_callback,
    V8RTCPeerConnectionErrorCallback* error_callback,
    ExceptionState&) {
  DCHECK(success_callback);
  DCHECK(error_callback);
  ExecutionContext* context = ExecutionContext::From(script_state);
  UseCounter::Count(context, WebFeature::kRTCPeerConnectionCreateAnswer);
  UseCounter::Count(
      context, WebFeature::kRTCPeerConnectionCreateAnswerLegacyFailureCallback);
  UseCounter::Count(context,
                    WebFeature::kRTCPeerConnectionCreateAnswerLegacyCompliant);

  if (CallErrorCallbackIfSignalingStateClosed(context, signaling_state_,
                                              error_callback))
    return ToResolvedUndefinedPromise(script_state);

  RTCSessionDescriptionRequest* request =
      RTCSessionDescriptionRequestImpl::Create(
          GetExecutionContext(), this, success_callback, error_callback);
  peer_handler_->CreateAnswer(request, nullptr);
  return ToResolvedUndefinedPromise(script_state);
}

DOMException* RTCPeerConnection::checkSdpForStateErrors(
    ExecutionContext* context,
    const ParsedSessionDescription& parsed_sdp) {
  if (signaling_state_ ==
      webrtc::PeerConnectionInterface::SignalingState::kClosed) {
    return MakeGarbageCollected<DOMException>(
        DOMExceptionCode::kInvalidStateError, kSignalingStateClosedMessage);
  }

  if (parsed_sdp.type() == "offer") {
    if (parsed_sdp.sdp() != last_offer_) {
      if (FingerprintMismatch(last_offer_, parsed_sdp.sdp())) {
        return MakeGarbageCollected<DOMException>(
            DOMExceptionCode::kInvalidModificationError, kModifiedSdpMessage);
      } else {
        UseCounter::Count(context, WebFeature::kRTCLocalSdpModification);
        if (ContainsLegacySimulcast(parsed_sdp.sdp())) {
          UseCounter::Count(context,
                            WebFeature::kRTCLocalSdpModificationSimulcast);
        }
        if (IceUfragPwdMismatch(last_offer_, parsed_sdp.sdp())) {
          UseCounter::Count(context,
                            WebFeature::kRTCLocalSdpModificationIceUfragPwd);
        }
        if (ContainsOpusStereo(parsed_sdp.sdp()) &&
            !ContainsOpusStereo(last_offer_)) {
          UseCounter::Count(context,
                            WebFeature::kRTCLocalSdpModificationOpusStereo);
        }
        return nullptr;
        // TODO(https://crbug.com/823036): Return failure for all modification.
      }
    }
  } else if (parsed_sdp.type() == "answer" || parsed_sdp.type() == "pranswer") {
    if (parsed_sdp.sdp() != last_answer_) {
      if (FingerprintMismatch(last_answer_, parsed_sdp.sdp())) {
        return MakeGarbageCollected<DOMException>(
            DOMExceptionCode::kInvalidModificationError, kModifiedSdpMessage);
      } else {
        UseCounter::Count(context, WebFeature::kRTCLocalSdpModification);
        if (ContainsLegacySimulcast(parsed_sdp.sdp())) {
          UseCounter::Count(context,
                            WebFeature::kRTCLocalSdpModificationSimulcast);
        }
        if (IceUfragPwdMismatch(last_answer_, parsed_sdp.sdp())) {
          UseCounter::Count(context,
                            WebFeature::kRTCLocalSdpModificationIceUfragPwd);
        }
        if (ContainsOpusStereo(parsed_sdp.sdp()) &&
            !ContainsOpusStereo(last_offer_)) {
          UseCounter::Count(context,
                            WebFeature::kRTCLocalSdpModificationOpusStereo);
        }
        return nullptr;
        // TODO(https://crbug.com/823036): Return failure for all modification.
      }
    }
  }
  return nullptr;
}

HeapHashSet<Member<RTCIceTransport>> RTCPeerConnection::ActiveIceTransports()
    const {
  HeapHashSet<Member<RTCIceTransport>> active_transports;
  for (auto transceiver : transceivers_) {
    auto* sender = transceiver->sender();
    if (sender) {
      auto* dtls_transport = transceiver->sender()->transport();
      if (dtls_transport) {
        auto* ice_transport = dtls_transport->iceTransport();
        if (ice_transport) {
          active_transports.insert(ice_transport);
        }
      }
    }
  }
  if (sctp_transport_) {
    auto* dtls_transport = sctp_transport_->transport();
    if (dtls_transport) {
      auto* ice_transport = dtls_transport->iceTransport();
      if (ice_transport) {
        active_transports.insert(ice_transport);
      }
    }
  }
  return active_transports;
}

void RTCPeerConnection::GenerateCertificateCompleted(
    ScriptPromiseResolver<RTCCertificate>* resolver,
    rtc::scoped_refptr<rtc::RTCCertificate> certificate) {
  if (!certificate) {
    resolver->Reject();
    return;
  }

  resolver->Resolve(
      MakeGarbageCollected<RTCCertificate>(std::move(certificate)));
}

void RTCPeerConnection::UpdateIceConnectionState() {
  auto new_state = ComputeIceConnectionState();
  if (ice_connection_state_ != new_state) {
    peer_handler_->TrackIceConnectionStateChange(new_state);
  }
  ChangeIceConnectionState(new_state);
}

ScriptPromise<IDLUndefined> RTCPeerConnection::setLocalDescription(
    ScriptState* script_state,
    ExceptionState& exception_state) {
  DCHECK(script_state->ContextIsValid());
  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(
      script_state, exception_state.GetContext());
  auto promise = resolver->Promise();
  auto* request =
      MakeGarbageCollected<RTCVoidRequestPromiseImpl>(this, resolver);
  peer_handler_->SetLocalDescription(request);
  return promise;
}

ScriptPromise<IDLUndefined> RTCPeerConnection::setLocalDescription(
    ScriptState* script_state,
    const RTCSessionDescriptionInit* session_description_init,
    ExceptionState& exception_state) {
  if (closed_) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      kSignalingStateClosedMessage);
    return EmptyPromise();
  }

  DCHECK(script_state->ContextIsValid());
  if (!session_description_init->hasType()) {
    return setLocalDescription(script_state, exception_state);
  }
  String sdp = session_description_init->sdp();
  // https://w3c.github.io/webrtc-pc/#dom-peerconnection-setlocaldescription
  // step 4.4 and 4.5: If SDP is empty, return the last created offer or answer.
  if (sdp.empty()) {
    switch (session_description_init->type().AsEnum()) {
      case V8RTCSdpType::Enum::kOffer:
        sdp = last_offer_;
        break;
      case V8RTCSdpType::Enum::kPranswer:
      case V8RTCSdpType::Enum::kAnswer:
        sdp = last_answer_;
        break;
      case V8RTCSdpType::Enum::kRollback:
        break;
    }
  }
  ParsedSessionDescription parsed_sdp = ParsedSessionDescription::Parse(
      session_description_init->type().AsString(), sdp);
  if (session_description_init->type() != V8RTCSdpType::Enum::kRollback) {
    DOMException* exception = checkSdpForStateErrors(
        ExecutionContext::From(script_state), parsed_sdp);
    if (exception) {
      exception_state.ThrowDOMException(
          static_cast<DOMExceptionCode>(exception->code()),
          exception->message());
      return EmptyPromise();
    }
  }
  ExecutionContext* context = ExecutionContext::From(script_state);
  UseCounter::Count(context, WebFeature::kRTCPeerConnectionSetLocalDescription);
  UseCounter::Count(context,
                    WebFeature::kRTCPeerConnectionSetLocalDescriptionPromise);

  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(
      script_state, exception_state.GetContext());
  auto promise = resolver->Promise();
  auto* request =
      MakeGarbageCollected<RTCVoidRequestPromiseImpl>(this, resolver);
  peer_handler_->SetLocalDescription(request, std::move(parsed_sdp));
  return promise;
}

ScriptPromise<IDLUndefined> RTCPeerConnection::setLocalDescription(
    ScriptState* script_state,
    const RTCSessionDescriptionInit* session_description_init,
    V8VoidFunction* success_callback,
    V8RTCPeerConnectionErrorCallback* error_callback) {
  if (CallErrorCallbackIfSignalingStateClosed(
          ExecutionContext::From(script_state), signaling_state_,
          error_callback)) {
    return ToResolvedUndefinedPromise(script_state);
  }

  DCHECK(script_state->ContextIsValid());
  String sdp = session_description_init->sdp();
  // https://w3c.github.io/webrtc-pc/#dom-peerconnection-setlocaldescription
  // step 4.4 and 4.5: If SDP is empty, return the last created offer or answer.
  if (sdp.empty() && session_description_init->hasType()) {
    switch (session_description_init->type().AsEnum()) {
      case V8RTCSdpType::Enum::kOffer:
        sdp = last_offer_;
        break;
      case V8RTCSdpType::Enum::kPranswer:
      case V8RTCSdpType::Enum::kAnswer:
        sdp = last_answer_;
        break;
      case V8RTCSdpType::Enum::kRollback:
        break;
    }
  }
  ParsedSessionDescription parsed_sdp = ParsedSessionDescription::Parse(
      session_description_init->hasType()
          ? session_description_init->type().AsString()
          : String(),
      sdp);
  ExecutionContext* context = ExecutionContext::From(script_state);
  UseCounter::Count(context, WebFeature::kRTCPeerConnectionSetLocalDescription);
  if (success_callback && error_callback) {
    UseCounter::Count(
        context,
        WebFeature::kRTCPeerConnectionSetLocalDescriptionLegacyCompliant);
  } else {
    if (!success_callback)
      UseCounter::Count(
          context,
          WebFeature::
              kRTCPeerConnectionSetLocalDescriptionLegacyNoSuccessCallback);
    if (!error_callback)
      UseCounter::Count(
          context,
          WebFeature::
              kRTCPeerConnectionSetLocalDescriptionLegacyNoFailureCallback);
  }
  if (!session_description_init->hasType() ||
      session_description_init->type() != V8RTCSdpType::Enum::kRollback) {
    DOMException* exception = checkSdpForStateErrors(context, parsed_sdp);
    if (exception) {
      if (error_callback)
        AsyncCallErrorCallback(context, error_callback, exception);
      return ToResolvedUndefinedPromise(script_state);
    }
  }
  auto* request = MakeGarbageCollected<RTCVoidRequestImpl>(
      GetExecutionContext(), this, success_callback, error_callback);
  peer_handler_->SetLocalDescription(request, std::move(parsed_sdp));
  return ToResolvedUndefinedPromise(script_state);
}

RTCSessionDescription* RTCPeerConnection::localDescription() const {
  return pending_local_description_ ? pending_local_description_
                                    : current_local_description_;
}

RTCSessionDescription* RTCPeerConnection::currentLocalDescription() const {
  return current_local_description_.Get();
}

RTCSessionDescription* RTCPeerConnection::pendingLocalDescription() const {
  return pending_local_description_.Get();
}

ScriptPromise<IDLUndefined> RTCPeerConnection::setRemoteDescription(
    ScriptState* script_state,
    const RTCSessionDescriptionInit* session_description_init,
    ExceptionState& exception_state) {
  if (closed_) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      kSignalingStateClosedMessage);
    return EmptyPromise();
  }

  DCHECK(script_state->ContextIsValid());
  ParsedSessionDescription parsed_sdp =
      ParsedSessionDescription::Parse(session_description_init);
  if (signaling_state_ ==
      webrtc::PeerConnectionInterface::SignalingState::kClosed) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      kSignalingStateClosedMessage);
    return EmptyPromise();
  }

  ExecutionContext* context = ExecutionContext::From(script_state);
  UseCounter::Count(context,
                    WebFeature::kRTCPeerConnectionSetRemoteDescription);
  UseCounter::Count(context,
                    WebFeature::kRTCPeerConnectionSetRemoteDescriptionPromise);

  if (ContainsLegacyRtpDataChannel(session_description_init->sdp())) {
    UseCounter::Count(context, WebFeature::kRTCLegacyRtpDataChannelNegotiated);
  }

  if (ContainsCandidate(session_description_init->sdp()))
    DisableBackForwardCache(context);

  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(
      script_state, exception_state.GetContext());
  auto promise = resolver->Promise();
  auto* request =
      MakeGarbageCollected<RTCVoidRequestPromiseImpl>(this, resolver);
  peer_handler_->SetRemoteDescription(request, std::move(parsed_sdp));
  return promise;
}

ScriptPromise<IDLUndefined> RTCPeerConnection::setRemoteDescription(
    ScriptState* script_state,
    const RTCSessionDescriptionInit* session_description_init,
    V8VoidFunction* success_callback,
    V8RTCPeerConnectionErrorCallback* error_callback) {
  if (CallErrorCallbackIfSignalingStateClosed(
          ExecutionContext::From(script_state), signaling_state_,
          error_callback)) {
    return ToResolvedUndefinedPromise(script_state);
  }

  DCHECK(script_state->ContextIsValid());
  ParsedSessionDescription parsed_sdp =
      ParsedSessionDescription::Parse(session_description_init);
  ExecutionContext* context = ExecutionContext::From(script_state);
  UseCounter::Count(context,
                    WebFeature::kRTCPeerConnectionSetRemoteDescription);
  if (success_callback && error_callback) {
    UseCounter::Count(
        context,
        WebFeature::kRTCPeerConnectionSetRemoteDescriptionLegacyCompliant);
  } else {
    if (!success_callback)
      UseCounter::Count(
          context,
          WebFeature::
              kRTCPeerConnectionSetRemoteDescriptionLegacyNoSuccessCallback);
    if (!error_callback)
      UseCounter::Count(
          context,
          WebFeature::
              kRTCPeerConnectionSetRemoteDescriptionLegacyNoFailureCallback);
  }

  if (ContainsLegacyRtpDataChannel(session_description_init->sdp())) {
    UseCounter::Count(context, WebFeature::kRTCLegacyRtpDataChannelNegotiated);
  }

  if (ContainsCandidate(session_description_init->sdp()))
    DisableBackForwardCache(context);

  if (CallErrorCallbackIfSignalingStateClosed(context, signaling_state_,
                                              error_callback))
    return ToResolvedUndefinedPromise(script_state);

  auto* request = MakeGarbageCollected<RTCVoidRequestImpl>(
      GetExecutionContext(), this, success_callback, error_callback);
  peer_handler_->SetRemoteDescription(request, std::move(parsed_sdp));
  return ToResolvedUndefinedPromise(script_state);
}

RTCSessionDescription* RTCPeerConnection::remoteDescription() const {
  return pending_remote_description_ ? pending_remote_description_
                                     : current_remote_description_;
}

RTCSessionDescription* RTCPeerConnection::currentRemoteDescription() const {
  return current_remote_description_.Get();
}

RTCSessionDescription* RTCPeerConnection::pendingRemoteDescription() const {
  return pending_remote_description_.Get();
}

RTCConfiguration* RTCPeerConnection::getConfiguration(
    ScriptState* script_state) const {
  RTCConfiguration* result = RTCConfiguration::Create();
  const auto& webrtc_configuration = peer_handler_->GetConfiguration();

  switch (webrtc_configuration.type) {
    case webrtc::PeerConnectionInterface::kRelay:
      result->setIceTransportPolicy("relay");
      break;
    case webrtc::PeerConnectionInterface::kAll:
      result->setIceTransportPolicy("all");
      break;
    default:
      NOTREACHED();
  }

  switch (webrtc_configuration.bundle_policy) {
    case webrtc::PeerConnectionInterface::kBundlePolicyMaxCompat:
      result->setBundlePolicy("max-compat");
      break;
    case webrtc::PeerConnectionInterface::kBundlePolicyMaxBundle:
      result->setBundlePolicy("max-bundle");
      break;
    case webrtc::PeerConnectionInterface::kBundlePolicyBalanced:
      result->setBundlePolicy("balanced");
      break;
    default:
      NOTREACHED();
  }

  switch (webrtc_configuration.rtcp_mux_policy) {
    case webrtc::PeerConnectionInterface::kRtcpMuxPolicyNegotiate:
      result->setRtcpMuxPolicy("negotiate");
      break;
    case webrtc::PeerConnectionInterface::kRtcpMuxPolicyRequire:
      result->setRtcpMuxPolicy("require");
      break;
    default:
      NOTREACHED();
  }

  HeapVector<Member<RTCIceServer>> ice_servers;
  ice_servers.reserve(
      base::checked_cast<wtf_size_t>(webrtc_configuration.servers.size()));
  for (const auto& webrtc_server : webrtc_configuration.servers) {
    auto* ice_server = RTCIceServer::Create();

    Vector<String> url_vector;
    url_vector.reserve(
        base::checked_cast<wtf_size_t>(webrtc_server.urls.size()));
    for (const auto& url : webrtc_server.urls) {
      url_vector.emplace_back(url.c_str());
    }
    auto* urls = MakeGarbageCollected<V8UnionStringOrStringSequence>(
        std::move(url_vector));

    ice_server->setUrls(urls);
    ice_server->setUsername(webrtc_server.username.c_str());
    ice_server->setCredential(webrtc_server.password.c_str());
    ice_servers.push_back(ice_server);
  }
  result->setIceServers(ice_servers);

  if (!webrtc_configuration.certificates.empty()) {
    HeapVector<blink::Member<RTCCertificate>> certificates;
    certificates.reserve(base::checked_cast<wtf_size_t>(
        webrtc_configuration.certificates.size()));
    for (const auto& webrtc_certificate : webrtc_configuration.certificates) {
      certificates.emplace_back(
          MakeGarbageCollected<RTCCertificate>(webrtc_certificate));
    }
    result->setCertificates(certificates);
  }

  result->setIceCandidatePoolSize(webrtc_configuration.ice_candidate_pool_size);

  const auto* context = ExecutionContext::From(script_state);
  if (RuntimeEnabledFeatures::RtcAudioJitterBufferMaxPacketsEnabled(context)) {
    int audio_jitter_buffer_max_packets =
        webrtc_configuration.audio_jitter_buffer_max_packets;
    result->setRtcAudioJitterBufferMaxPackets(
        static_cast<int32_t>(audio_jitter_buffer_max_packets));
    result->setRtcAudioJitterBufferFastAccelerate(
        webrtc_configuration.audio_jitter_buffer_fast_accelerate);
    int audio_jitter_buffer_min_delay_ms =
        webrtc_configuration.audio_jitter_buffer_min_delay_ms;
    result->setRtcAudioJitterBufferMinDelayMs(
        static_cast<int32_t>(audio_jitter_buffer_min_delay_ms));
  }
  result->setEncodedInsertableStreams(
      peer_handler_->encoded_insertable_streams());

  return result;
}

void RTCPeerConnection::setConfiguration(
    ScriptState* script_state,
    const RTCConfiguration* rtc_configuration,
    ExceptionState& exception_state) {
  if (ThrowExceptionIfSignalingStateClosed(signaling_state_, &exception_state))
    return;

  webrtc::PeerConnectionInterface::RTCConfiguration configuration =
      ParseConfiguration(ExecutionContext::From(script_state),
                         rtc_configuration, &exception_state);

  if (exception_state.HadException())
    return;

  if (peer_handler_->encoded_insertable_streams() !=
      rtc_configuration->encodedInsertableStreams()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidModificationError,
        "Attempted to modify the PeerConnection's "
        "configuration in an unsupported way.");
  }

  webrtc::RTCErrorType error = peer_handler_->SetConfiguration(configuration);
  if (error == webrtc::RTCErrorType::NONE) {
    return;
  } else if (error == webrtc::RTCErrorType::INVALID_MODIFICATION) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidModificationError,
        "Attempted to modify the PeerConnection's configuration in an "
        "unsupported way.");
  } else if (error == webrtc::RTCErrorType::SYNTAX_ERROR) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kSyntaxError,
        "The given configuration has a syntax error.");
  } else {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kOperationError,
        "Could not update the PeerConnection with the given configuration.");
  }
}

ScriptPromise<RTCCertificate> RTCPeerConnection::generateCertificate(
    ScriptState* script_state,
    const V8AlgorithmIdentifier* keygen_algorithm,
    ExceptionState& exception_state) {
  // Normalize |keygenAlgorithm| with WebCrypto, making sure it is a recognized
  // AlgorithmIdentifier.
  WebCryptoAlgorithm crypto_algorithm;
  if (!NormalizeAlgorithm(script_state->GetIsolate(), keygen_algorithm,
                          kWebCryptoOperationGenerateKey, crypto_algorithm,
                          exception_state)) {
    return EmptyPromise();
  }

  // Check if |keygenAlgorithm| contains the optional DOMTimeStamp |expires|
  // attribute.
  std::optional<DOMTimeStamp> expires;
  if (keygen_algorithm->IsObject()) {
    Dictionary keygen_algorithm_dict(script_state->GetIsolate(),
                                     keygen_algorithm->GetAsObject().V8Value(),
                                     exception_state);
    if (exception_state.HadException())
      return EmptyPromise();

    bool has_expires =
        keygen_algorithm_dict.HasProperty("expires", exception_state);
    if (exception_state.HadException())
      return EmptyPromise();

    if (has_expires) {
      v8::Local<v8::Value> expires_value;
      keygen_algorithm_dict.Get("expires", expires_value);
      if (expires_value->IsNumber()) {
        double expires_double =
            expires_value
                ->ToNumber(script_state->GetIsolate()->GetCurrentContext())
                .ToLocalChecked()
                ->Value();
        if (expires_double >= 0) {
          expires = static_cast<DOMTimeStamp>(expires_double);
        } else {
          exception_state.ThrowTypeError(
              "Negative value for expires attribute.");
          return EmptyPromise();
        }
      } else {
        exception_state.ThrowTypeError("Invalid type for expires attribute.");
        return EmptyPromise();
      }
    }
  }

  // Convert from WebCrypto representation to recognized WebRTCKeyParams. WebRTC
  // supports a small subset of what are valid AlgorithmIdentifiers.
  const char* unsupported_params_string =
      "The 1st argument provided is an AlgorithmIdentifier with a supported "
      "algorithm name, but the parameters are not supported.";
  std::optional<rtc::KeyParams> key_params;
  switch (crypto_algorithm.Id()) {
    case kWebCryptoAlgorithmIdRsaSsaPkcs1v1_5: {
      // name: "RSASSA-PKCS1-v1_5"
      std::optional<uint32_t> public_exponent =
          crypto_algorithm.RsaHashedKeyGenParams()->PublicExponentAsU32();
      unsigned modulus_length =
          crypto_algorithm.RsaHashedKeyGenParams()->ModulusLengthBits();
      // Parameters must fit in int to be passed to rtc::KeyParams::RSA. The
      // only recognized "hash" is "SHA-256".
      // TODO(bugs.webrtc.org/364338811): deprecate 1024 bit keys.
      if (public_exponent &&
          base::IsValueInRangeForNumericType<int>(*public_exponent) &&
          base::IsValueInRangeForNumericType<int>(modulus_length) &&
          crypto_algorithm.RsaHashedKeyGenParams()->GetHash().Id() ==
              kWebCryptoAlgorithmIdSha256) {
        key_params =
            rtc::KeyParams::RSA(base::checked_cast<int>(modulus_length),
                                base::checked_cast<int>(*public_exponent));
      } else {
        exception_state.ThrowDOMException(DOMExceptionCode::kNotSupportedError,
                                          unsupported_params_string);
        return EmptyPromise();
      }
      break;
    }
    case kWebCryptoAlgorithmIdEcdsa:
      // name: "ECDSA"
      // The only recognized "namedCurve" is "P-256".
      if (crypto_algorithm.EcKeyGenParams()->NamedCurve() ==
          kWebCryptoNamedCurveP256) {
        key_params = rtc::KeyParams::ECDSA(rtc::EC_NIST_P256);
      } else {
        exception_state.ThrowDOMException(DOMExceptionCode::kNotSupportedError,
                                          unsupported_params_string);
        return EmptyPromise();
      }
      break;
    default:
      exception_state.ThrowDOMException(DOMExceptionCode::kNotSupportedError,
                                        "The 1st argument provided is an "
                                        "AlgorithmIdentifier, but the "
                                        "algorithm is not supported.");
      return EmptyPromise();
  }
  DCHECK(key_params.has_value());
  MeasureGenerateCertificateKeyType(key_params);

  auto certificate_generator = std::make_unique<RTCCertificateGenerator>();

  // |keyParams| was successfully constructed, but does the certificate
  // generator support these parameters?
  if (!certificate_generator->IsSupportedKeyParams(key_params.value())) {
    exception_state.ThrowDOMException(DOMExceptionCode::kNotSupportedError,
                                      unsupported_params_string);
    return EmptyPromise();
  }

  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<RTCCertificate>>(
      script_state, exception_state.GetContext());
  auto promise = resolver->Promise();

  // Helper closure callback for RTCPeerConnection::generateCertificate.
  auto completion_callback =
      WTF::BindOnce(RTCPeerConnection::GenerateCertificateCompleted,
                    WrapPersistent(resolver));

  // Generate certificate. The |certificateObserver| will resolve the promise
  // asynchronously upon completion. The observer will manage its own
  // destruction as well as the resolver's destruction.
  scoped_refptr<base::SingleThreadTaskRunner> task_runner =
      ExecutionContext::From(script_state)
          ->GetTaskRunner(blink::TaskType::kInternalMedia);
  if (!expires) {
    certificate_generator->GenerateCertificate(
        key_params.value(), std::move(completion_callback),
        *ExecutionContext::From(script_state), task_runner);
  } else {
    certificate_generator->GenerateCertificateWithExpiration(
        key_params.value(), expires.value(), std::move(completion_callback),
        *ExecutionContext::From(script_state), task_runner);
  }

  return promise;
}

ScriptPromise<IDLUndefined> RTCPeerConnection::addIceCandidate(
    ScriptState* script_state,
    const RTCIceCandidateInit* candidate,
    ExceptionState& exception_state) {
  DCHECK(script_state->ContextIsValid());
  if (signaling_state_ ==
      webrtc::PeerConnectionInterface::SignalingState::kClosed) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      kSignalingStateClosedMessage);
    return EmptyPromise();
  }

  if (candidate->hasCandidate() && candidate->candidate().empty()) {
    // Temporary mitigation to avoid throwing an exception when candidate is
    // empty or nothing was passed.
    // TODO(crbug.com/978582): Remove this mitigation when the WebRTC layer
    // handles the empty candidate field or the null candidate correctly.
    return ToResolvedUndefinedPromise(script_state);
  }

  RTCIceCandidatePlatform* platform_candidate =
      ConvertToRTCIceCandidatePlatform(ExecutionContext::From(script_state),
                                       candidate);

  if (IsIceCandidateMissingSdpMidAndMLineIndex(candidate)) {
    exception_state.ThrowTypeError(
        "Candidate missing values for both sdpMid and sdpMLineIndex");
    return EmptyPromise();
  }

  DisableBackForwardCache(GetExecutionContext());

  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(
      script_state, exception_state.GetContext());
  auto promise = resolver->Promise();
  auto* request =
      MakeGarbageCollected<RTCVoidRequestPromiseImpl>(this, resolver);
  peer_handler_->AddIceCandidate(request, std::move(platform_candidate));
  return promise;
}

ScriptPromise<IDLUndefined> RTCPeerConnection::addIceCandidate(
    ScriptState* script_state,
    const RTCIceCandidateInit* candidate,
    V8VoidFunction* success_callback,
    V8RTCPeerConnectionErrorCallback* error_callback,
    ExceptionState& exception_state) {
  DCHECK(script_state->ContextIsValid());
  DCHECK(success_callback);
  DCHECK(error_callback);

  if (CallErrorCallbackIfSignalingStateClosed(
          ExecutionContext::From(script_state), signaling_state_,
          error_callback))
    return ToResolvedUndefinedPromise(script_state);

  if (IsIceCandidateMissingSdpMidAndMLineIndex(candidate)) {
    exception_state.ThrowTypeError(
        "Candidate missing values for both sdpMid and sdpMLineIndex");
    return EmptyPromise();
  }

  RTCIceCandidatePlatform* platform_candidate =
      ConvertToRTCIceCandidatePlatform(ExecutionContext::From(script_state),
                                       candidate);

  // Temporary mitigation to avoid throwing an exception when candidate is
  // empty.
  // TODO(crbug.com/978582): Remove this mitigation when the WebRTC layer
  // handles the empty candidate field or the null candidate correctly.
  if (platform_candidate->Candidate().empty())
    return ToResolvedUndefinedPromise(script_state);

  DisableBackForwardCache(GetExecutionContext());

  auto* request = MakeGarbageCollected<RTCVoidReques
```