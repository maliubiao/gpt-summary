Response:
Let's break down the request and form a plan to address it comprehensively.

**1. Understanding the Core Request:**

The primary goal is to analyze the provided C++ source code file (`quic_crypto_client_handshaker.cc`) and describe its functionality within the Chromium network stack. Specifically, the request asks for:

* **Functionality Listing:** A description of what the code does.
* **JavaScript Relationship:** If and how the code interacts with JavaScript in a web browser context.
* **Logical Reasoning (Hypothetical I/O):**  Demonstrating the code's behavior with example inputs and outputs.
* **Common Usage Errors:** Identifying potential mistakes developers might make.
* **Debugging Guidance:** Explaining how a user's actions might lead to this code being executed.

**2. Initial Code Scan and High-Level Understanding:**

A quick glance at the code reveals keywords like "handshake," "crypto," "client," "server," "config," "proof," "encryption," and "session."  This strongly suggests that the file is responsible for handling the client-side cryptographic handshake process in the QUIC protocol. It seems to manage the exchange of messages with the server to establish a secure connection.

**3. Deeper Dive into Functionality:**

To detail the functionality, I need to analyze the key classes and methods:

* **`QuicCryptoClientHandshaker` Class:**  This is the central class. I need to understand its responsibilities, member variables, and the purpose of its methods.
* **State Machine (`next_state_` and `DoHandshakeLoop`):** The code uses a state machine to manage the handshake process. I need to enumerate the states and the transitions between them.
* **Key Methods:**
    * `CryptoConnect()`: Initiates the handshake.
    * `OnHandshakeMessage()`: Handles incoming handshake messages from the server.
    * `DoInitialize()`, `DoSendCHLO()`, `DoReceiveREJ()`, etc.: The different states of the handshake process.
    * Methods related to proof verification (`DoVerifyProof`, `DoVerifyProofComplete`).
    * Methods for handling server config updates (`HandleServerConfigUpdateMessage`, `DoInitializeServerConfigUpdate`).
* **Interactions with Other Classes:** The code interacts with `QuicCryptoClientStream`, `QuicSession`, `QuicCryptoClientConfig`, `ProofVerifier`, etc. I need to note these interactions and their purpose.

**4. Addressing the JavaScript Relationship:**

This is crucial. While the C++ code itself doesn't *directly* execute JavaScript, it's part of the Chromium network stack that *enables* secure communication for web browsers. The connection is indirect but fundamental. I need to explain:

* How the handshake process enables secure HTTPS connections.
* How JavaScript uses browser APIs (like `fetch` or `XMLHttpRequest` over HTTPS) that rely on this underlying QUIC implementation.
* A concrete example of a JavaScript action (e.g., loading an HTTPS page) and how it triggers this C++ code.

**5. Logical Reasoning (Hypothetical I/O):**

I need to create a simplified scenario:

* **Input:**  Assume a fresh connection attempt to a QUIC server.
* **Steps:**  Trace the execution flow through the state machine, highlighting key message exchanges (CHLO, SHLO).
* **Output:**  Describe the final state (secure connection established) and the key material generated.

**6. Common Usage Errors:**

This requires thinking about potential mistakes or scenarios that could lead to problems:

* **Configuration Issues:**  Incorrect `QuicCryptoClientConfig`.
* **Server Misbehavior:**  Server sending unexpected messages or failing to respond.
* **Network Issues:**  Although the code doesn't directly handle network errors, they can disrupt the handshake. I should focus on crypto-specific errors exposed by this code.
* **Caching Issues:** Problems with cached server configurations.

**7. Debugging Guidance (User Actions):**

I need to link user actions to the execution of this code:

* **Simple HTTPS request:**  The most basic trigger.
* **Visiting a website that uses QUIC:**  Explaining how to verify if QUIC is in use (e.g., developer tools).
* **Troubleshooting scenarios:** What a user might observe if the handshake fails (e.g., connection errors). How developers can use network debugging tools to see the QUIC handshake messages.

**8. Structuring the Answer:**

I'll organize the answer into sections corresponding to the request:

* **Functionality:**  A clear and concise list of the code's responsibilities.
* **JavaScript Relationship:** A detailed explanation with examples.
* **Logical Reasoning:**  The hypothetical input/output scenario.
* **Common Usage Errors:**  Specific examples of potential mistakes.
* **Debugging Guidance:**  Step-by-step explanation of how a user reaches this code.

**Self-Correction/Refinement during the Thought Process:**

* **Initial thought:** Focus heavily on the low-level cryptographic details.
* **Correction:**  Balance the technical details with the broader context of how this code fits into the web browsing experience and how it relates to JavaScript. The user likely isn't a QUIC protocol expert.
* **Initial thought:** Provide very technical error examples.
* **Correction:** Frame errors in terms of user-observable symptoms or common development mistakes.
* **Initial thought:**  Provide a very detailed trace of every function call.
* **Correction:** Focus on the high-level state transitions and key message exchanges in the logical reasoning example.

By following this plan and iteratively refining my understanding, I can provide a comprehensive and helpful answer to the user's request.
This C++ source code file, `quic_crypto_client_handshaker.cc`, is a crucial part of the Chromium network stack, specifically within the QUIC protocol implementation. Its primary function is to manage the **client-side cryptographic handshake process** when a QUIC client (like a Chrome browser) attempts to establish a secure connection with a QUIC server.

Here's a breakdown of its functionalities:

**Core Functionalities:**

1. **Initiating the Handshake:**
   - The `CryptoConnect()` method is the entry point, triggering the handshake process.
   - It sets the initial state of the handshake and starts the handshake loop.

2. **Managing Handshake States:**
   - The code utilizes a state machine (represented by `next_state_` and the `DoHandshakeLoop()` method) to orchestrate the different stages of the handshake.
   - Key states include:
     - `STATE_INITIALIZE`: Initial setup.
     - `STATE_SEND_CHLO`: Sending the ClientHello (CHLO) message.
     - `STATE_RECV_REJ`: Receiving and processing a Rejection (REJ) message from the server.
     - `STATE_VERIFY_PROOF`: Verifying the server's cryptographic proof of identity.
     - `STATE_RECV_SHLO`: Receiving and processing the ServerHello (SHLO) message.
     - `STATE_INITIALIZE_SCUP`: Handling Server Config Updates (SCUP).

3. **Generating and Sending ClientHello (CHLO):**
   - The `DoSendCHLO()` method constructs the CHLO message, which contains information about the client's capabilities and preferences for the connection.
   - It handles both initial CHLOs and subsequent CHLOs after receiving a rejection.
   - It interacts with `QuicCryptoClientConfig` to retrieve cached configuration data and fill necessary fields in the CHLO.

4. **Processing ServerHello (SHLO):**
   - The `DoReceiveSHLO()` method handles the SHLO message from the server.
   - It verifies the message and extracts critical parameters like the negotiated encryption algorithms and protocol versions.
   - It updates the session's encryption state based on the SHLO.

5. **Handling Rejections (REJ):**
   - The `DoReceiveREJ()` method processes REJ messages, which indicate the server couldn't accept the client's initial CHLO.
   - It analyzes the rejection reasons and potentially adjusts the client's configuration for the next attempt.

6. **Verifying Server Proof:**
   - The `DoVerifyProof()` and `DoVerifyProofComplete()` methods are responsible for verifying the server's cryptographic proof, ensuring the client is connecting to the intended server and not a malicious imposter.
   - It uses a `ProofVerifier` (from `crypto_config_`) to perform the verification.
   - It handles both cached server configurations and fresh verifications.

7. **Handling Server Config Updates (SCUP):**
   - The `HandleServerConfigUpdateMessage()` and `DoInitializeServerConfigUpdate()` methods deal with Server Config Update Protocol (SCUP) messages, which allow the server to push updated configuration information to the client.

8. **Key Exchange and Encryption:**
   - While this file doesn't implement the low-level cryptographic primitives, it manages the flow of information that leads to the establishment of encryption keys.
   - It interacts with the `QuicSession` to set the appropriate encryption levels.

9. **Resumption and Early Data (0-RTT):**
   - The code includes logic for attempting session resumption (though the comments indicate it's not the same as TLS resumption) and sending early data (0-RTT) if the server supports it.

10. **Error Handling:**
    - The code includes error checks and calls `stream_->OnUnrecoverableError()` to signal fatal handshake failures.

**Relationship with JavaScript Functionality:**

This C++ code in the Chromium network stack is **fundamental** to the security and performance of web browsing, and thus has a **direct but indirect relationship with JavaScript**. Here's how:

* **Secure HTTPS Connections:** When a JavaScript application running in a web browser (like Chrome) makes an HTTPS request to a server that supports QUIC, this `QuicCryptoClientHandshaker` code is involved in establishing the secure QUIC connection.
* **`fetch()` API and `XMLHttpRequest`:**  JavaScript code uses APIs like `fetch()` and `XMLHttpRequest` to make network requests. When these requests are made to HTTPS URLs over QUIC, the underlying network stack, including this C++ code, handles the cryptographic handshake to secure the connection before any data (including JavaScript's request and the server's response) is transmitted.

**Example:**

Imagine a simple JavaScript snippet:

```javascript
fetch('https://example.com/data.json')
  .then(response => response.json())
  .then(data => console.log(data));
```

**How it relates to `quic_crypto_client_handshaker.cc`:**

1. When this JavaScript code executes, the browser's network stack checks if QUIC is enabled and if the server (`example.com`) supports it.
2. If QUIC is used, the browser initiates a QUIC connection.
3. The `QuicCryptoClientHandshaker` in this C++ file takes over the task of establishing a secure connection. It will:
   - Send a ClientHello message to the server.
   - Potentially receive a Rejection and retry.
   - Verify the server's certificate.
   - Receive the ServerHello.
   - Negotiate encryption parameters.
4. Once the handshake is complete and a secure connection is established by this C++ code, the actual HTTP request for `/data.json` is sent over the encrypted QUIC connection.
5. The server's response (the JSON data) is received over the secure connection, and the JavaScript code can then process it.

**Logical Reasoning (Hypothetical Input & Output):**

**Assumption:** A client is connecting to a QUIC server for the first time, and no cached information is available.

**Hypothetical Input:**

* **User Action:** User types `https://secure.example.com` in the browser's address bar and hits Enter.
* **Server Information:** The server at `secure.example.com` supports QUIC.

**Steps (Simplified):**

1. **`CryptoConnect()` is called:**  The handshake begins. `next_state_` is set to `STATE_INITIALIZE`.
2. **`DoHandshakeLoop()` executes `STATE_INITIALIZE`:** Since there's no cached server config, `next_state_` becomes `STATE_SEND_CHLO`.
3. **`DoHandshakeLoop()` executes `STATE_SEND_CHLO`:**
   - A `CryptoHandshakeMessage` (ClientHello - CHLO) is created.
   - This CHLO includes the client's supported QUIC versions, cryptographic capabilities, etc.
   - The CHLO is sent to the server using `SendHandshakeMessage(out, ENCRYPTION_INITIAL)`.
   - `next_state_` becomes `STATE_RECV_REJ`.
4. **Assuming the server doesn't reject immediately, the server sends a ServerHello (SHLO):**
   - **`OnHandshakeMessage()` is called** when the SHLO is received.
   - **`DoHandshakeLoop()` executes `STATE_RECV_SHLO`:**
     - The SHLO message is parsed.
     - Encryption parameters are negotiated.
     - Encryption keys are established.
     - `one_rtt_keys_available_` becomes `true`.
     - The connection is now secure.

**Hypothetical Output:**

* **`encryption_established_` becomes `true`.**
* **`one_rtt_keys_available_` becomes `true`.**
* The QUIC connection is now in a state where application data can be sent securely.
* The JavaScript code making the `fetch()` request can now send its request over this secure connection.

**If the server had rejected:**

* **Input:** Same as above.
* **Output (in case of rejection):**
    * **`OnHandshakeMessage()` is called** with a REJ message.
    * **`DoHandshakeLoop()` executes `STATE_RECV_REJ`:**
        * The rejection reasons are processed.
        * The client might attempt to send another CHLO with adjusted parameters (`next_state_` becomes `STATE_SEND_CHLO`).

**User or Programming Common Usage Errors:**

1. **Incorrect `QuicCryptoClientConfig`:**
   - **Example:**  A developer embedding Chromium might misconfigure the `QuicCryptoClientConfig` with an invalid `ProofVerifier`, preventing the client from verifying server certificates.
   - **Symptom:** The handshake will likely fail at the `STATE_VERIFY_PROOF` stage, and the connection will be refused. The error message might indicate a problem with the server's certificate or proof.

2. **Server Configuration Issues:**
   - **Example:** The server might be configured to require a specific cryptographic algorithm that the client doesn't support.
   - **Symptom:** The handshake might fail during the negotiation phase (SHLO processing), and the error message might indicate a mismatch in supported algorithms.

3. **Network Interference:**
   - **Example:** A firewall might be blocking QUIC traffic (which typically uses UDP).
   - **Symptom:** The handshake might time out, or specific handshake messages might not reach the client or server. This isn't directly an error in this code but a condition it reacts to.

4. **Clock Skew:**
   - **Example:**  Significant time differences between the client and server machines can cause issues with certificate validation and potentially the handshake process.
   - **Symptom:** Certificate verification might fail, even if the certificate is valid, leading to handshake errors.

5. **Overriding Default Behavior Incorrectly:**
   - **Example:** A developer might try to customize the handshake process without fully understanding the implications, leading to unexpected state transitions or errors.

**User Operations Leading to This Code (Debugging Clues):**

A user's actions that initiate a QUIC connection will inevitably lead to the execution of this code. Here's a step-by-step example:

1. **User Enters a URL:** The user types an HTTPS URL (e.g., `https://www.google.com`) in the Chrome address bar and presses Enter.
2. **DNS Resolution:** Chrome performs a DNS lookup to find the IP address of `www.google.com`.
3. **QUIC Support Check:** Chrome checks if QUIC is enabled in its settings and if the server at the resolved IP address is known to support QUIC (this might involve ALPN in the TLS handshake for the initial connection, or through cached information).
4. **Socket Creation:** Chrome creates a UDP socket to communicate with the server.
5. **Connection Attempt:**  The QUIC connection attempt is initiated. This involves creating a `QuicConnection` object and a `QuicCryptoClientStream`.
6. **`QuicCryptoClientHandshaker` Instantiation:** An instance of `QuicCryptoClientHandshaker` is created, associated with the `QuicCryptoClientStream`.
7. **`CryptoConnect()` Called:** The `CryptoConnect()` method of the `QuicCryptoClientHandshaker` is called to begin the handshake.
8. **State Machine Execution:** The `DoHandshakeLoop()` starts executing, transitioning through the states (INITIALIZE, SEND_CHLO, etc.) as handshake messages are exchanged with the server.
9. **Message Handling:** When the server sends handshake messages (like REJ or SHLO), the `OnHandshakeMessage()` method of the `QuicCryptoClientHandshaker` is invoked to process them.
10. **Encryption Establishment:** If the handshake is successful, the `one_rtt_keys_available_` flag will be set to `true`, indicating a secure connection.

**Debugging:**

To debug issues related to this code, developers might:

* **Use `netlog`:** Chromium's network logging tool (`chrome://net-export/`) can capture detailed information about QUIC connections, including the handshake messages exchanged.
* **Set Breakpoints:** In a Chromium development environment, breakpoints can be set in this C++ code to inspect the state of variables and the flow of execution during the handshake.
* **Analyze Error Messages:**  Error messages logged by the `stream_->OnUnrecoverableError()` calls can provide clues about the stage of the handshake where the failure occurred.
* **Examine QUIC Internal State:** Tools exist to inspect the internal state of QUIC connections within Chrome's debugging interfaces.

In summary, `quic_crypto_client_handshaker.cc` is the engine responsible for the critical cryptographic handshake process on the client side of a QUIC connection, making it a vital component for secure and efficient web communication initiated by JavaScript and other browser functionalities.

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/core/quic_crypto_client_handshaker.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/quic_crypto_client_handshaker.h"

#include <memory>
#include <string>
#include <utility>

#include "absl/strings/str_cat.h"
#include "quiche/quic/core/crypto/crypto_protocol.h"
#include "quiche/quic/core/crypto/crypto_utils.h"
#include "quiche/quic/core/quic_session.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/platform/api/quic_client_stats.h"
#include "quiche/quic/platform/api/quic_flags.h"
#include "quiche/quic/platform/api/quic_logging.h"
#include "quiche/common/platform/api/quiche_logging.h"

namespace quic {

QuicCryptoClientHandshaker::ProofVerifierCallbackImpl::
    ProofVerifierCallbackImpl(QuicCryptoClientHandshaker* parent)
    : parent_(parent) {}

QuicCryptoClientHandshaker::ProofVerifierCallbackImpl::
    ~ProofVerifierCallbackImpl() {}

void QuicCryptoClientHandshaker::ProofVerifierCallbackImpl::Run(
    bool ok, const std::string& error_details,
    std::unique_ptr<ProofVerifyDetails>* details) {
  if (parent_ == nullptr) {
    return;
  }

  parent_->verify_ok_ = ok;
  parent_->verify_error_details_ = error_details;
  parent_->verify_details_ = std::move(*details);
  parent_->proof_verify_callback_ = nullptr;
  parent_->DoHandshakeLoop(nullptr);

  // The ProofVerifier owns this object and will delete it when this method
  // returns.
}

void QuicCryptoClientHandshaker::ProofVerifierCallbackImpl::Cancel() {
  parent_ = nullptr;
}

QuicCryptoClientHandshaker::QuicCryptoClientHandshaker(
    const QuicServerId& server_id, QuicCryptoClientStream* stream,
    QuicSession* session, std::unique_ptr<ProofVerifyContext> verify_context,
    QuicCryptoClientConfig* crypto_config,
    QuicCryptoClientStream::ProofHandler* proof_handler)
    : QuicCryptoHandshaker(stream, session),
      stream_(stream),
      session_(session),
      delegate_(session),
      next_state_(STATE_IDLE),
      num_client_hellos_(0),
      crypto_config_(crypto_config),
      server_id_(server_id),
      generation_counter_(0),
      verify_context_(std::move(verify_context)),
      proof_verify_callback_(nullptr),
      proof_handler_(proof_handler),
      verify_ok_(false),
      proof_verify_start_time_(QuicTime::Zero()),
      num_scup_messages_received_(0),
      encryption_established_(false),
      one_rtt_keys_available_(false),
      crypto_negotiated_params_(new QuicCryptoNegotiatedParameters) {}

QuicCryptoClientHandshaker::~QuicCryptoClientHandshaker() {
  if (proof_verify_callback_) {
    proof_verify_callback_->Cancel();
  }
}

void QuicCryptoClientHandshaker::OnHandshakeMessage(
    const CryptoHandshakeMessage& message) {
  QuicCryptoHandshaker::OnHandshakeMessage(message);
  if (message.tag() == kSCUP) {
    if (!one_rtt_keys_available()) {
      stream_->OnUnrecoverableError(
          QUIC_CRYPTO_UPDATE_BEFORE_HANDSHAKE_COMPLETE,
          "Early SCUP disallowed");
      return;
    }

    // |message| is an update from the server, so we treat it differently from a
    // handshake message.
    HandleServerConfigUpdateMessage(message);
    num_scup_messages_received_++;
    return;
  }

  // Do not process handshake messages after the handshake is confirmed.
  if (one_rtt_keys_available()) {
    stream_->OnUnrecoverableError(QUIC_CRYPTO_MESSAGE_AFTER_HANDSHAKE_COMPLETE,
                                  "Unexpected handshake message");
    return;
  }

  DoHandshakeLoop(&message);
}

bool QuicCryptoClientHandshaker::CryptoConnect() {
  next_state_ = STATE_INITIALIZE;
  DoHandshakeLoop(nullptr);
  return session()->connection()->connected();
}

int QuicCryptoClientHandshaker::num_sent_client_hellos() const {
  return num_client_hellos_;
}

bool QuicCryptoClientHandshaker::ResumptionAttempted() const {
  QUICHE_DCHECK(false);
  return false;
}

bool QuicCryptoClientHandshaker::IsResumption() const {
  QUIC_BUG_IF(quic_bug_12522_1, !one_rtt_keys_available_);
  // While 0-RTT handshakes could be considered to be like resumption, QUIC
  // Crypto doesn't have the same notion of a resumption like TLS does.
  return false;
}

bool QuicCryptoClientHandshaker::EarlyDataAccepted() const {
  QUIC_BUG_IF(quic_bug_12522_2, !one_rtt_keys_available_);
  return num_client_hellos_ == 1;
}

ssl_early_data_reason_t QuicCryptoClientHandshaker::EarlyDataReason() const {
  return early_data_reason_;
}

bool QuicCryptoClientHandshaker::ReceivedInchoateReject() const {
  QUIC_BUG_IF(quic_bug_12522_3, !one_rtt_keys_available_);
  return num_client_hellos_ >= 3;
}

int QuicCryptoClientHandshaker::num_scup_messages_received() const {
  return num_scup_messages_received_;
}

std::string QuicCryptoClientHandshaker::chlo_hash() const { return chlo_hash_; }

bool QuicCryptoClientHandshaker::encryption_established() const {
  return encryption_established_;
}

bool QuicCryptoClientHandshaker::IsCryptoFrameExpectedForEncryptionLevel(
    EncryptionLevel /*level*/) const {
  return true;
}

EncryptionLevel
QuicCryptoClientHandshaker::GetEncryptionLevelToSendCryptoDataOfSpace(
    PacketNumberSpace space) const {
  if (space == INITIAL_DATA) {
    return ENCRYPTION_INITIAL;
  }
  QUICHE_DCHECK(false);
  return NUM_ENCRYPTION_LEVELS;
}

bool QuicCryptoClientHandshaker::one_rtt_keys_available() const {
  return one_rtt_keys_available_;
}

const QuicCryptoNegotiatedParameters&
QuicCryptoClientHandshaker::crypto_negotiated_params() const {
  return *crypto_negotiated_params_;
}

CryptoMessageParser* QuicCryptoClientHandshaker::crypto_message_parser() {
  return QuicCryptoHandshaker::crypto_message_parser();
}

HandshakeState QuicCryptoClientHandshaker::GetHandshakeState() const {
  return one_rtt_keys_available() ? HANDSHAKE_COMPLETE : HANDSHAKE_START;
}

void QuicCryptoClientHandshaker::OnHandshakeDoneReceived() {
  QUICHE_DCHECK(false);
}

void QuicCryptoClientHandshaker::OnNewTokenReceived(
    absl::string_view /*token*/) {
  QUICHE_DCHECK(false);
}

size_t QuicCryptoClientHandshaker::BufferSizeLimitForLevel(
    EncryptionLevel level) const {
  return QuicCryptoHandshaker::BufferSizeLimitForLevel(level);
}

std::unique_ptr<QuicDecrypter>
QuicCryptoClientHandshaker::AdvanceKeysAndCreateCurrentOneRttDecrypter() {
  // Key update is only defined in QUIC+TLS.
  QUICHE_DCHECK(false);
  return nullptr;
}

std::unique_ptr<QuicEncrypter>
QuicCryptoClientHandshaker::CreateCurrentOneRttEncrypter() {
  // Key update is only defined in QUIC+TLS.
  QUICHE_DCHECK(false);
  return nullptr;
}

void QuicCryptoClientHandshaker::OnConnectionClosed(
    QuicErrorCode /*error*/, ConnectionCloseSource /*source*/) {
  next_state_ = STATE_CONNECTION_CLOSED;
}

void QuicCryptoClientHandshaker::HandleServerConfigUpdateMessage(
    const CryptoHandshakeMessage& server_config_update) {
  QUICHE_DCHECK(server_config_update.tag() == kSCUP);
  std::string error_details;
  QuicCryptoClientConfig::CachedState* cached =
      crypto_config_->LookupOrCreate(server_id_);
  QuicErrorCode error = crypto_config_->ProcessServerConfigUpdate(
      server_config_update, session()->connection()->clock()->WallNow(),
      session()->transport_version(), chlo_hash_, cached,
      crypto_negotiated_params_, &error_details);

  if (error != QUIC_NO_ERROR) {
    stream_->OnUnrecoverableError(
        error, "Server config update invalid: " + error_details);
    return;
  }

  QUICHE_DCHECK(one_rtt_keys_available());
  if (proof_verify_callback_) {
    proof_verify_callback_->Cancel();
  }
  next_state_ = STATE_INITIALIZE_SCUP;
  DoHandshakeLoop(nullptr);
}

void QuicCryptoClientHandshaker::DoHandshakeLoop(
    const CryptoHandshakeMessage* in) {
  QuicCryptoClientConfig::CachedState* cached =
      crypto_config_->LookupOrCreate(server_id_);

  QuicAsyncStatus rv = QUIC_SUCCESS;
  do {
    QUICHE_CHECK_NE(STATE_NONE, next_state_);
    const State state = next_state_;
    next_state_ = STATE_IDLE;
    rv = QUIC_SUCCESS;
    switch (state) {
      case STATE_INITIALIZE:
        DoInitialize(cached);
        break;
      case STATE_SEND_CHLO:
        DoSendCHLO(cached);
        return;  // return waiting to hear from server.
      case STATE_RECV_REJ:
        DoReceiveREJ(in, cached);
        break;
      case STATE_VERIFY_PROOF:
        rv = DoVerifyProof(cached);
        break;
      case STATE_VERIFY_PROOF_COMPLETE:
        DoVerifyProofComplete(cached);
        break;
      case STATE_RECV_SHLO:
        DoReceiveSHLO(in, cached);
        break;
      case STATE_IDLE:
        // This means that the peer sent us a message that we weren't expecting.
        stream_->OnUnrecoverableError(QUIC_INVALID_CRYPTO_MESSAGE_TYPE,
                                      "Handshake in idle state");
        return;
      case STATE_INITIALIZE_SCUP:
        DoInitializeServerConfigUpdate(cached);
        break;
      case STATE_NONE:
        QUICHE_NOTREACHED();
        return;
      case STATE_CONNECTION_CLOSED:
        rv = QUIC_FAILURE;
        return;  // We are done.
    }
  } while (rv != QUIC_PENDING && next_state_ != STATE_NONE);
}

void QuicCryptoClientHandshaker::DoInitialize(
    QuicCryptoClientConfig::CachedState* cached) {
  if (!cached->IsEmpty() && !cached->signature().empty()) {
    // Note that we verify the proof even if the cached proof is valid.
    // This allows us to respond to CA trust changes or certificate
    // expiration because it may have been a while since we last verified
    // the proof.
    QUICHE_DCHECK(crypto_config_->proof_verifier());
    // Track proof verification time when cached server config is used.
    proof_verify_start_time_ = session()->connection()->clock()->Now();
    chlo_hash_ = cached->chlo_hash();
    // If the cached state needs to be verified, do it now.
    next_state_ = STATE_VERIFY_PROOF;
  } else {
    next_state_ = STATE_SEND_CHLO;
  }
}

void QuicCryptoClientHandshaker::DoSendCHLO(
    QuicCryptoClientConfig::CachedState* cached) {
  // Send the client hello in plaintext.
  session()->connection()->SetDefaultEncryptionLevel(ENCRYPTION_INITIAL);
  encryption_established_ = false;
  if (num_client_hellos_ >= QuicCryptoClientStream::kMaxClientHellos) {
    stream_->OnUnrecoverableError(
        QUIC_CRYPTO_TOO_MANY_REJECTS,
        absl::StrCat("More than ", QuicCryptoClientStream::kMaxClientHellos,
                     " rejects"));
    return;
  }
  num_client_hellos_++;

  CryptoHandshakeMessage out;
  QUICHE_DCHECK(session() != nullptr);
  QUICHE_DCHECK(session()->config() != nullptr);
  // Send all the options, regardless of whether we're sending an
  // inchoate or subsequent hello.
  session()->config()->ToHandshakeMessage(&out, session()->transport_version());

  bool fill_inchoate_client_hello = false;
  if (!cached->IsComplete(session()->connection()->clock()->WallNow())) {
    early_data_reason_ = ssl_early_data_no_session_offered;
    fill_inchoate_client_hello = true;
  } else if (session()->config()->HasClientRequestedIndependentOption(
                 kQNZ2, session()->perspective()) &&
             num_client_hellos_ == 1) {
    early_data_reason_ = ssl_early_data_disabled;
    fill_inchoate_client_hello = true;
  }
  if (fill_inchoate_client_hello) {
    crypto_config_->FillInchoateClientHello(
        server_id_, session()->supported_versions().front(), cached,
        session()->connection()->random_generator(),
        /* demand_x509_proof= */ true, crypto_negotiated_params_, &out);
    // Pad the inchoate client hello to fill up a packet.
    const QuicByteCount kFramingOverhead = 50;  // A rough estimate.
    const QuicByteCount max_packet_size =
        session()->connection()->max_packet_length();
    if (max_packet_size <= kFramingOverhead) {
      QUIC_DLOG(DFATAL) << "max_packet_length (" << max_packet_size
                        << ") has no room for framing overhead.";
      stream_->OnUnrecoverableError(QUIC_INTERNAL_ERROR,
                                    "max_packet_size too smalll");
      return;
    }
    if (kClientHelloMinimumSize > max_packet_size - kFramingOverhead) {
      QUIC_DLOG(DFATAL) << "Client hello won't fit in a single packet.";
      stream_->OnUnrecoverableError(QUIC_INTERNAL_ERROR, "CHLO too large");
      return;
    }
    next_state_ = STATE_RECV_REJ;
    chlo_hash_ = CryptoUtils::HashHandshakeMessage(out, Perspective::IS_CLIENT);
    session()->connection()->set_fully_pad_crypto_handshake_packets(
        crypto_config_->pad_inchoate_hello());
    SendHandshakeMessage(out, ENCRYPTION_INITIAL);
    return;
  }

  std::string error_details;
  QuicErrorCode error = crypto_config_->FillClientHello(
      server_id_, session()->connection()->connection_id(),
      session()->supported_versions().front(),
      session()->connection()->version(), cached,
      session()->connection()->clock()->WallNow(),
      session()->connection()->random_generator(), crypto_negotiated_params_,
      &out, &error_details);
  if (error != QUIC_NO_ERROR) {
    // Flush the cached config so that, if it's bad, the server has a
    // chance to send us another in the future.
    cached->InvalidateServerConfig();
    stream_->OnUnrecoverableError(error, error_details);
    return;
  }
  chlo_hash_ = CryptoUtils::HashHandshakeMessage(out, Perspective::IS_CLIENT);
  if (cached->proof_verify_details()) {
    proof_handler_->OnProofVerifyDetailsAvailable(
        *cached->proof_verify_details());
  }
  next_state_ = STATE_RECV_SHLO;
  session()->connection()->set_fully_pad_crypto_handshake_packets(
      crypto_config_->pad_full_hello());
  SendHandshakeMessage(out, ENCRYPTION_INITIAL);
  // Be prepared to decrypt with the new server write key.
  delegate_->OnNewEncryptionKeyAvailable(
      ENCRYPTION_ZERO_RTT,
      std::move(crypto_negotiated_params_->initial_crypters.encrypter));
  delegate_->OnNewDecryptionKeyAvailable(
      ENCRYPTION_ZERO_RTT,
      std::move(crypto_negotiated_params_->initial_crypters.decrypter),
      /*set_alternative_decrypter=*/true,
      /*latch_once_used=*/true);
  encryption_established_ = true;
  delegate_->SetDefaultEncryptionLevel(ENCRYPTION_ZERO_RTT);
  if (early_data_reason_ == ssl_early_data_unknown && num_client_hellos_ > 1) {
    early_data_reason_ = ssl_early_data_peer_declined;
  }
}

void QuicCryptoClientHandshaker::DoReceiveREJ(
    const CryptoHandshakeMessage* in,
    QuicCryptoClientConfig::CachedState* cached) {
  // We sent a dummy CHLO because we didn't have enough information to
  // perform a handshake, or we sent a full hello that the server
  // rejected. Here we hope to have a REJ that contains the information
  // that we need.
  if (in->tag() != kREJ) {
    next_state_ = STATE_NONE;
    stream_->OnUnrecoverableError(QUIC_INVALID_CRYPTO_MESSAGE_TYPE,
                                  "Expected REJ");
    return;
  }

  QuicTagVector reject_reasons;
  static_assert(sizeof(QuicTag) == sizeof(uint32_t), "header out of sync");
  if (in->GetTaglist(kRREJ, &reject_reasons) == QUIC_NO_ERROR) {
    uint32_t packed_error = 0;
    for (size_t i = 0; i < reject_reasons.size(); ++i) {
      // HANDSHAKE_OK is 0 and don't report that as error.
      if (reject_reasons[i] == HANDSHAKE_OK || reject_reasons[i] >= 32) {
        continue;
      }
      HandshakeFailureReason reason =
          static_cast<HandshakeFailureReason>(reject_reasons[i]);
      packed_error |= 1 << (reason - 1);
    }
    QUIC_DVLOG(1) << "Reasons for rejection: " << packed_error;
  }

  // Receipt of a REJ message means that the server received the CHLO
  // so we can cancel and retransmissions.
  delegate_->NeuterUnencryptedData();

  std::string error_details;
  QuicErrorCode error = crypto_config_->ProcessRejection(
      *in, session()->connection()->clock()->WallNow(),
      session()->transport_version(), chlo_hash_, cached,
      crypto_negotiated_params_, &error_details);

  if (error != QUIC_NO_ERROR) {
    next_state_ = STATE_NONE;
    stream_->OnUnrecoverableError(error, error_details);
    return;
  }
  if (!cached->proof_valid()) {
    if (!cached->signature().empty()) {
      // Note that we only verify the proof if the cached proof is not
      // valid. If the cached proof is valid here, someone else must have
      // just added the server config to the cache and verified the proof,
      // so we can assume no CA trust changes or certificate expiration
      // has happened since then.
      next_state_ = STATE_VERIFY_PROOF;
      return;
    }
  }
  next_state_ = STATE_SEND_CHLO;
}

QuicAsyncStatus QuicCryptoClientHandshaker::DoVerifyProof(
    QuicCryptoClientConfig::CachedState* cached) {
  ProofVerifier* verifier = crypto_config_->proof_verifier();
  QUICHE_DCHECK(verifier);
  next_state_ = STATE_VERIFY_PROOF_COMPLETE;
  generation_counter_ = cached->generation_counter();

  ProofVerifierCallbackImpl* proof_verify_callback =
      new ProofVerifierCallbackImpl(this);

  verify_ok_ = false;

  QuicAsyncStatus status = verifier->VerifyProof(
      server_id_.host(), server_id_.port(), cached->server_config(),
      session()->transport_version(), chlo_hash_, cached->certs(),
      cached->cert_sct(), cached->signature(), verify_context_.get(),
      &verify_error_details_, &verify_details_,
      std::unique_ptr<ProofVerifierCallback>(proof_verify_callback));

  switch (status) {
    case QUIC_PENDING:
      proof_verify_callback_ = proof_verify_callback;
      QUIC_DVLOG(1) << "Doing VerifyProof";
      break;
    case QUIC_FAILURE:
      break;
    case QUIC_SUCCESS:
      verify_ok_ = true;
      break;
  }
  return status;
}

void QuicCryptoClientHandshaker::DoVerifyProofComplete(
    QuicCryptoClientConfig::CachedState* cached) {
  if (proof_verify_start_time_.IsInitialized()) {
    QUIC_CLIENT_HISTOGRAM_TIMES(
        "QuicSession.VerifyProofTime.CachedServerConfig",
        (session()->connection()->clock()->Now() - proof_verify_start_time_),
        QuicTime::Delta::FromMilliseconds(1), QuicTime::Delta::FromSeconds(10),
        50, "");
  }
  if (!verify_ok_) {
    if (verify_details_) {
      proof_handler_->OnProofVerifyDetailsAvailable(*verify_details_);
    }
    if (num_client_hellos_ == 0) {
      cached->Clear();
      next_state_ = STATE_INITIALIZE;
      return;
    }
    next_state_ = STATE_NONE;
    QUIC_CLIENT_HISTOGRAM_BOOL("QuicVerifyProofFailed.HandshakeConfirmed",
                               one_rtt_keys_available(), "");
    stream_->OnUnrecoverableError(QUIC_PROOF_INVALID,
                                  "Proof invalid: " + verify_error_details_);
    return;
  }

  // Check if generation_counter has changed between STATE_VERIFY_PROOF and
  // STATE_VERIFY_PROOF_COMPLETE state changes.
  if (generation_counter_ != cached->generation_counter()) {
    next_state_ = STATE_VERIFY_PROOF;
  } else {
    SetCachedProofValid(cached);
    cached->SetProofVerifyDetails(verify_details_.release());
    if (!one_rtt_keys_available()) {
      next_state_ = STATE_SEND_CHLO;
    } else {
      next_state_ = STATE_NONE;
    }
  }
}

void QuicCryptoClientHandshaker::DoReceiveSHLO(
    const CryptoHandshakeMessage* in,
    QuicCryptoClientConfig::CachedState* cached) {
  next_state_ = STATE_NONE;
  // We sent a CHLO that we expected to be accepted and now we're
  // hoping for a SHLO from the server to confirm that.  First check
  // to see whether the response was a reject, and if so, move on to
  // the reject-processing state.
  if (in->tag() == kREJ) {
    // A reject message must be sent in ENCRYPTION_INITIAL.
    if (session()->connection()->last_decrypted_level() != ENCRYPTION_INITIAL) {
      // The rejection was sent encrypted!
      stream_->OnUnrecoverableError(QUIC_CRYPTO_ENCRYPTION_LEVEL_INCORRECT,
                                    "encrypted REJ message");
      return;
    }
    next_state_ = STATE_RECV_REJ;
    return;
  }

  if (in->tag() != kSHLO) {
    stream_->OnUnrecoverableError(
        QUIC_INVALID_CRYPTO_MESSAGE_TYPE,
        absl::StrCat("Expected SHLO or REJ. Received: ",
                     QuicTagToString(in->tag())));
    return;
  }

  if (session()->connection()->last_decrypted_level() == ENCRYPTION_INITIAL) {
    // The server hello was sent without encryption.
    stream_->OnUnrecoverableError(QUIC_CRYPTO_ENCRYPTION_LEVEL_INCORRECT,
                                  "unencrypted SHLO message");
    return;
  }
  if (num_client_hellos_ == 1) {
    early_data_reason_ = ssl_early_data_accepted;
  }

  std::string error_details;
  QuicErrorCode error = crypto_config_->ProcessServerHello(
      *in, session()->connection()->connection_id(),
      session()->connection()->version(),
      session()->connection()->server_supported_versions(), cached,
      crypto_negotiated_params_, &error_details);

  if (error != QUIC_NO_ERROR) {
    stream_->OnUnrecoverableError(error,
                                  "Server hello invalid: " + error_details);
    return;
  }
  error = session()->config()->ProcessPeerHello(*in, SERVER, &error_details);
  if (error != QUIC_NO_ERROR) {
    stream_->OnUnrecoverableError(error,
                                  "Server hello invalid: " + error_details);
    return;
  }
  session()->OnConfigNegotiated();

  CrypterPair* crypters = &crypto_negotiated_params_->forward_secure_crypters;
  // TODO(agl): we don't currently latch this decrypter because the idea
  // has been floated that the server shouldn't send packets encrypted
  // with the FORWARD_SECURE key until it receives a FORWARD_SECURE
  // packet from the client.
  delegate_->OnNewEncryptionKeyAvailable(ENCRYPTION_FORWARD_SECURE,
                                         std::move(crypters->encrypter));
  delegate_->OnNewDecryptionKeyAvailable(ENCRYPTION_FORWARD_SECURE,
                                         std::move(crypters->decrypter),
                                         /*set_alternative_decrypter=*/true,
                                         /*latch_once_used=*/false);
  one_rtt_keys_available_ = true;
  delegate_->SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);
  delegate_->DiscardOldEncryptionKey(ENCRYPTION_INITIAL);
  delegate_->NeuterHandshakeData();
}

void QuicCryptoClientHandshaker::DoInitializeServerConfigUpdate(
    QuicCryptoClientConfig::CachedState* cached) {
  bool update_ignored = false;
  if (!cached->IsEmpty() && !cached->signature().empty()) {
    // Note that we verify the proof even if the cached proof is valid.
    QUICHE_DCHECK(crypto_config_->proof_verifier());
    next_state_ = STATE_VERIFY_PROOF;
  } else {
    update_ignored = true;
    next_state_ = STATE_NONE;
  }
  QUIC_CLIENT_HISTOGRAM_COUNTS("QuicNumServerConfig.UpdateMessagesIgnored",
                               update_ignored, 1, 1000000, 50, "");
}

void QuicCryptoClientHandshaker::SetCachedProofValid(
    QuicCryptoClientConfig::CachedState* cached) {
  cached->SetProofValid();
  proof_handler_->OnProofValid(*cached);
}

}  // namespace quic
```