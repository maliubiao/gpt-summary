Response:
Let's break down the thought process to analyze the `websocket_common.cc` file and answer the user's request.

**1. Initial Understanding of the Request:**

The request asks for a functional breakdown of a specific Chromium Blink source file related to WebSockets. Key points include:

* **Functionality:** What does this code *do*?
* **Relationship to Web Technologies:** How does it connect to JavaScript, HTML, and CSS?
* **Logic and Examples:**  If there's decision-making, provide input/output examples.
* **Common Errors:** Identify typical user or programmer mistakes related to this code.
* **Debugging Path:** How does a user interaction lead to this code being executed?

**2. High-Level Code Scan:**

The first step is to quickly read through the code to get a general sense of its purpose. Keywords and structures that stand out are:

* `#include`: Indicates dependencies on other parts of the Chromium codebase (metrics, networking, security, core rendering, etc.). This suggests this file deals with core WebSocket logic rather than UI.
* `namespace blink`: Confirms it's part of the Blink rendering engine.
* `WebSocketCommon`: The central class. This is likely where the core functionality resides.
* `Connect`, `CloseInternal`, `ValidateCloseCodeAndReason`: These function names immediately suggest core WebSocket operations.
* `ExceptionState`:  Indicates error handling and reporting.
* `URL`, `String`, `Vector`: Data types used, hinting at processing URLs and lists of protocols.
* `ContentSecurityPolicy`, `SecurityContext`:  Suggests security considerations are handled.
* `UseCounter`:  Points to tracking usage statistics.

**3. Detailed Function Analysis (Iterative Process):**

Now, go through each function in detail:

* **`Connect`:**
    * **Goal:**  Initiate a WebSocket connection.
    * **Inputs:** `ExecutionContext`, `url`, `protocols`, `WebSocketChannel`, `ExceptionState`.
    * **Logic:**
        * URL validation (syntax, protocol, fragment).
        * Protocol upgrade (http -> ws, https -> wss) with "Upgrade Insecure Requests" handling.
        * Content Security Policy (CSP) checks.
        * Subprotocol validation (syntax, duplicates).
        * Calls `channel->Connect()`.
    * **Relates to JavaScript:** Directly called when JavaScript uses the `WebSocket` constructor.
    * **Example:**  JavaScript code `new WebSocket("ws://example.com", ["chat", "debug"])` would invoke this.
    * **Common Errors:** Invalid URLs, insecure connections from secure pages.

* **`CloseInternal`:**
    * **Goal:** Close a WebSocket connection.
    * **Inputs:** Optional `code`, `reason`, `WebSocketChannel`, `ExceptionState`.
    * **Logic:**
        * Validation of close code and reason using `ValidateCloseCodeAndReason`.
        * Handles different WebSocket states (connecting, open, closing).
        * Calls `channel->Close()` or `channel->Fail()`.
    * **Relates to JavaScript:** Called when JavaScript calls `websocket.close()`.
    * **Example:** `websocket.close(1001, "Going away")`.
    * **Common Errors:** Invalid close codes, reasons that are too long.

* **`IsValidSubprotocolCharacter`, `IsValidSubprotocolString`, `EncodeSubprotocolString`:**
    * **Goal:** Validate and encode WebSocket subprotocols.
    * **Logic:**  Character-by-character validation against allowed characters, encoding special characters.
    * **Relates to JavaScript:** Ensures the subprotocols specified in the `WebSocket` constructor are valid.

* **`JoinStrings`:**
    * **Goal:** Concatenate strings with a separator.
    * **Logic:** Simple string joining.
    * **Relates to JavaScript:** Used internally to format the list of subprotocols for the connection request.

* **`ValidateCloseCodeAndReason`:**
    * **Goal:** Verify the validity of the close code and reason.
    * **Logic:** Checks the code against allowed ranges and the reason against length limits.
    * **Relates to JavaScript:** Ensures that the arguments passed to `websocket.close()` are valid.

**4. Identifying Connections to Web Technologies:**

Based on the function analysis, it's clear how this code interacts with JavaScript:

* **`Connect`:** Directly implements the logic behind the `new WebSocket()` constructor.
* **`CloseInternal`:**  Implements the logic behind the `websocket.close()` method.
* **Subprotocol validation:** Enforces rules on what subprotocols JavaScript can specify.
* **Close code/reason validation:** Enforces rules on the arguments passed to `websocket.close()`.

The connection to HTML and CSS is less direct, but important:

* **HTML:** The `<script>` tag embedding the JavaScript code that uses `WebSocket` is the entry point. The security context of the HTML document (HTTPS vs. HTTP) affects WebSocket connection attempts.
* **CSS:**  Indirectly related. CSS might trigger JavaScript that then opens a WebSocket connection (e.g., through user interaction leading to a state change).

**5. Crafting Examples and Error Scenarios:**

Now, create concrete examples for inputs and outputs, and think about common mistakes:

* **Input/Output:**  Focus on key functions like `Connect` and scenarios where the URL or protocols are invalid.
* **User Errors:** Think about what a web developer might do incorrectly when using the `WebSocket` API.
* **Debugging:**  Trace the user actions that would lead to this code being executed, starting from the browser.

**6. Structuring the Answer:**

Finally, organize the findings into a clear and logical structure, addressing each part of the user's request:

* Start with a summary of the file's purpose.
* Detail each function's functionality.
* Explicitly link to JavaScript, HTML, and CSS with examples.
* Provide concrete input/output scenarios.
* List common user/programmer errors.
* Explain the debugging path from user action to this code.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Maybe this file handles the low-level socket communication.
* **Correction:**  Looking at the includes (`WebSocketChannel`) suggests it's more about the high-level logic and validation *before* the actual socket connection. The `WebSocketChannel` likely handles the lower-level details.
* **Initial thought:**  CSS might directly trigger WebSocket connections.
* **Refinement:** CSS is more likely to *indirectly* trigger connections via JavaScript responding to style changes or user interactions.

By following this structured approach, combining high-level understanding with detailed analysis, and constantly relating the code back to the user's perspective (web developers), a comprehensive and helpful answer can be generated.
这个文件 `blink/renderer/modules/websockets/websocket_common.cc` 的主要功能是 **提供 WebSocket 实现中通用的、与具体连接通道无关的逻辑和辅助功能**。它封装了 WebSocket 连接建立和关闭过程中的一些共同步骤和验证逻辑，确保 WebSocket API 的正确性和安全性。

以下是更详细的功能列表以及与 JavaScript、HTML、CSS 的关系、逻辑推理、常见错误和调试线索：

**主要功能:**

1. **WebSocket 连接的初始化和参数验证 (`Connect` 函数):**
   - 接收 JavaScript 中 `new WebSocket(url, protocols)` 调用的 URL 和子协议参数。
   - 验证 URL 的有效性（例如，必须是 `ws://` 或 `wss://` 协议）。
   - 处理 URL 协议的自动升级（例如，在 HTTPS 页面中，`http://` 会被升级为 `ws://`，并根据 "Upgrade Insecure Requests" 指令将 `ws://` 升级为 `wss://`）。
   - 检查 URL 中是否包含不允许的片段标识符 (#)。
   - 进行内容安全策略 (CSP) 检查，确保允许连接到指定的 WebSocket 地址。
   - 验证提供的子协议字符串的有效性，包括字符限制和重复检查。
   - 如果所有验证通过，则调用 `WebSocketChannel` 的 `Connect` 方法来建立实际的连接。

2. **WebSocket 连接的关闭 (`CloseInternal` 函数):**
   - 接收 JavaScript 中 `websocket.close(code, reason)` 调用的关闭代码和原因。
   - 调用 `ValidateCloseCodeAndReason` 函数来验证关闭代码和原因的有效性。
   - 处理 WebSocket 连接的不同状态（例如，正在连接、打开、正在关闭、已关闭），并采取相应的操作。
   - 如果连接尚未建立 (`kConnecting` 状态)，则直接通过 `Fail` 方法通知连接失败。
   - 如果连接已建立，则调用 `WebSocketChannel` 的 `Close` 方法来关闭连接。

3. **WebSocket 关闭代码和原因的验证 (`ValidateCloseCodeAndReason` 函数):**
   - 验证关闭代码是否在允许的范围内 (1000 或 3000-4999)。
   - 验证关闭原因的 UTF-8 编码长度是否不超过限制 (123 字节)。

4. **WebSocket 子协议字符串的验证和编码 (`IsValidSubprotocolCharacter`, `IsValidSubprotocolString`, `EncodeSubprotocolString` 函数):**
   - 验证子协议字符串是否只包含允许的字符。
   - 提供用于编码子协议字符串的函数，以便在日志或错误消息中显示。

5. **辅助函数 (`JoinStrings`):**
   - 提供将字符串数组连接成一个字符串的通用方法，用于组合子协议字符串。

**与 JavaScript, HTML, CSS 的关系:**

* **JavaScript:** 这个文件是实现 JavaScript `WebSocket` API 的一部分。当 JavaScript 代码中使用 `new WebSocket(url, protocols)` 创建 WebSocket 对象或调用 `websocket.close(code, reason)` 方法时，最终会调用到这个文件中的相应函数。

   **举例:**
   ```javascript
   // JavaScript 代码
   const websocket = new WebSocket("ws://example.com/socket", ["chat", "game"]);

   websocket.onopen = () => {
     console.log("WebSocket connection opened");
   };

   websocket.onmessage = (event) => {
     console.log("Message received:", event.data);
   };

   websocket.onclose = (event) => {
     console.log("WebSocket connection closed:", event.code, event.reason);
   };

   websocket.onerror = (error) => {
     console.error("WebSocket error:", error);
   };

   // 关闭连接
   websocket.close(1001, "User initiated close");
   ```
   在这个例子中，`new WebSocket(...)` 的调用会触发 `WebSocketCommon::Connect` 函数，而 `websocket.close(...)` 的调用会触发 `WebSocketCommon::CloseInternal` 函数。

* **HTML:** HTML 文件中通过 `<script>` 标签引入的 JavaScript 代码可以创建和操作 WebSocket 对象。HTML 页面的安全上下文（例如，是否是 HTTPS 页面）会影响 WebSocket 连接的建立，`WebSocketCommon::Connect` 函数会处理这些情况。

   **举例:**
   一个 HTTPS 页面上的 JavaScript 尝试连接到 `ws://insecure.example.com`。`WebSocketCommon::Connect` 中的逻辑会根据 "Upgrade Insecure Requests" 策略，可能将协议升级为 `wss://`。

* **CSS:** CSS 本身不直接与 `websocket_common.cc` 交互。但是，CSS 样式可能会影响 JavaScript 的行为，从而间接地导致 WebSocket 连接的建立或关闭。例如，用户点击一个按钮（样式由 CSS 定义），触发 JavaScript 代码来打开 WebSocket 连接。

**逻辑推理 (假设输入与输出):**

**假设输入 (Connect 函数):**

* `execution_context`: 当前执行上下文，包含页面的安全信息。
* `url`: "ws://example.com/socket"
* `protocols`: ["chat", "game"]
* `channel`: 一个 `WebSocketChannel` 对象。
* `exception_state`: 用于报告异常。

**输出 (Connect 函数):**

* 如果 URL 有效，协议合法，且没有 CSP 阻止，则调用 `channel->Connect("ws://example.com/socket", "chat, game")` 并返回 `ConnectResult::kSuccess`。
* 如果 URL 无效（例如，包含空格），则 `exception_state` 会抛出一个 `DOMExceptionCode::kSyntaxError` 异常，并返回 `ConnectResult::kException`。
* 如果子协议包含非法字符（例如，包含分号），则 `exception_state` 会抛出一个 `DOMExceptionCode::kSyntaxError` 异常，并返回 `ConnectResult::kException`。
* 如果 CSP 策略阻止连接到 `ws://example.com/socket`，则返回 `ConnectResult::kAsyncError`。

**假设输入 (CloseInternal 函数):**

* `code`: 1005
* `reason`: "No reason provided"
* `channel`: 一个 `WebSocketChannel` 对象。
* `exception_state`: 用于报告异常。

**输出 (CloseInternal 函数):**

* `ValidateCloseCodeAndReason` 会检查到代码 1005 是有效的，理由长度也符合要求。
* 如果当前 WebSocket 状态是 `kConnecting`，则会调用 `channel->Fail(...)`。
* 如果当前 WebSocket 状态是打开的，则会调用 `channel->Close(1005, "No reason provided")`。

**涉及用户或编程常见的使用错误:**

1. **无效的 WebSocket URL:** 用户在 JavaScript 中提供的 URL 格式不正确，例如缺少协议前缀，或者使用了 `http://` 或 `https://` 而不是 `ws://` 或 `wss://`。
   **举例:** `new WebSocket("example.com/socket")` 会导致语法错误。

2. **在 HTTPS 页面上尝试连接到不安全的 WebSocket (ws://):**  浏览器通常会阻止这种行为，除非页面明确允许混合内容。
   **举例:** 一个通过 `https://` 加载的页面尝试 `new WebSocket("ws://insecure.example.com")`，可能会抛出安全错误。

3. **使用无效的 WebSocket 子协议:** 提供的子协议包含不允许的字符或包含重复项。
   **举例:** `new WebSocket("ws://example.com", ["chat;", "chat"])` 会导致语法错误。

4. **使用无效的关闭代码:**  在调用 `websocket.close()` 时使用了超出允许范围的关闭代码。
   **举例:** `websocket.close(2000, "Some reason")` 会导致 `InvalidAccessError` 异常，因为 2000 不是一个有效的用户自定义关闭代码。

5. **关闭原因过长:**  提供的关闭原因字符串的 UTF-8 编码长度超过了 123 字节的限制。
   **举例:** `websocket.close(1000, "非常非常长...超过123字节的关闭原因字符串...")` 会导致 `SyntaxError` 异常。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

假设用户在一个网页上点击了一个按钮，这个按钮的点击事件绑定了一个 JavaScript 函数来打开一个 WebSocket 连接：

1. **用户操作:** 用户在浏览器中打开一个网页，并点击了页面上的一个按钮。
2. **事件触发:** 按钮的 `click` 事件被触发。
3. **JavaScript 执行:** 与该按钮绑定的 JavaScript 函数开始执行。
4. **创建 WebSocket 对象:** JavaScript 函数中调用 `new WebSocket("ws://example.com/socket", ["chat"])` 来创建一个新的 WebSocket 对象。
5. **Blink 引擎处理 (WebSocketCommon::Connect):**
   - 浏览器引擎 (Blink) 接收到创建 WebSocket 对象的请求。
   - `blink/renderer/modules/websockets/WebSocketCommon::Connect` 函数被调用。
   - 该函数会进行 URL 验证、协议升级、CSP 检查和子协议验证。
   - 如果验证通过，`WebSocketCommon::Connect` 会调用 `WebSocketChannel` 的 `Connect` 方法，后者会负责建立底层的网络连接。

如果用户之后点击了另一个按钮来关闭连接：

1. **用户操作:** 用户点击页面上的关闭按钮。
2. **事件触发:** 关闭按钮的 `click` 事件被触发。
3. **JavaScript 执行:** 与关闭按钮绑定的 JavaScript 函数开始执行。
4. **调用 close 方法:** JavaScript 函数中调用 `websocket.close(1000, "User closed")`。
5. **Blink 引擎处理 (WebSocketCommon::CloseInternal):**
   - 浏览器引擎接收到关闭 WebSocket 连接的请求。
   - `blink/renderer/modules/websockets/WebSocketCommon::CloseInternal` 函数被调用。
   - 该函数会调用 `ValidateCloseCodeAndReason` 来验证关闭代码和原因。
   - 最终，`WebSocketCommon::CloseInternal` 会调用 `WebSocketChannel` 的 `Close` 方法来关闭底层的网络连接。

**调试线索:**

当调试 WebSocket 相关问题时，可以关注以下线索：

* **网络面板:** 浏览器的开发者工具中的 "网络" 面板可以查看 WebSocket 连接的握手过程 (HTTP Upgrade 请求) 和后续的数据帧传输。
* **控制台错误:** 如果 JavaScript 代码使用不当（例如，无效的 URL 或子协议），浏览器的控制台会显示相应的错误信息。这些错误信息通常与 `WebSocketCommon` 中抛出的异常相关。
* **Blink 调试日志:**  在 Chromium 的开发者版本中，可以启用 Blink 的调试日志，以查看更详细的 WebSocket 操作流程，包括 `WebSocketCommon` 中进行的验证和状态转换。
* **断点调试:**  可以在 `WebSocketCommon::Connect` 和 `WebSocketCommon::CloseInternal` 等关键函数中设置断点，逐步跟踪代码执行，查看参数值和状态变化，以理解连接建立或关闭失败的原因。

总而言之，`websocket_common.cc` 文件是 Blink 引擎中处理 WebSocket 通用逻辑的关键组件，它确保了 WebSocket API 的正确使用和安全性，并为 `WebSocketChannel` 提供了必要的辅助功能。理解这个文件的工作原理有助于深入了解浏览器如何实现 WebSocket 功能。

Prompt: 
```
这是目录为blink/renderer/modules/websockets/websocket_common.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/websockets/websocket_common.h"

#include <stddef.h>

#include "base/metrics/histogram_macros.h"
#include "services/network/public/cpp/is_potentially_trustworthy.h"
#include "third_party/blink/public/common/security_context/insecure_request_policy.h"
#include "third_party/blink/public/mojom/security_context/insecure_request_policy.mojom-blink.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/execution_context/security_context.h"
#include "third_party/blink/renderer/core/frame/csp/content_security_policy.h"
#include "third_party/blink/renderer/core/frame/web_feature.h"
#include "third_party/blink/renderer/core/loader/mixed_content_checker.h"
#include "third_party/blink/renderer/modules/websockets/websocket_channel.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/weborigin/security_origin.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"
#include "third_party/blink/renderer/platform/wtf/text/string_utf8_adaptor.h"
#include "third_party/blink/renderer/platform/wtf/wtf_size_t.h"

namespace blink {

namespace {

constexpr char kWebSocketSubprotocolSeparator[] = ", ";
constexpr size_t kMaxReasonSizeInBytes = 123;

}  // namespace

WebSocketCommon::ConnectResult WebSocketCommon::Connect(
    ExecutionContext* execution_context,
    const String& url,
    const Vector<String>& protocols,
    WebSocketChannel* channel,
    ExceptionState& exception_state) {
  // CompleteURL is not used here because this is expected to always be UTF-8,
  // and not match document encoding.
  url_ = KURL(execution_context->BaseURL(), url);

  if (url_.IsValid()) {
    if (url_.ProtocolIs("http")) {
      url_.SetProtocol("ws");
    } else if (url_.ProtocolIs("https")) {
      url_.SetProtocol("wss");
    }
  }

  bool upgrade_insecure_requests_set =
      (execution_context->GetSecurityContext().GetInsecureRequestPolicy() &
       mojom::blink::InsecureRequestPolicy::kUpgradeInsecureRequests) !=
      mojom::blink::InsecureRequestPolicy::kLeaveInsecureRequestsAlone;

  if (upgrade_insecure_requests_set && url_.Protocol() == "ws" &&
      !network::IsUrlPotentiallyTrustworthy(GURL(url_))) {
    UseCounter::Count(
        execution_context,
        WebFeature::kUpgradeInsecureRequestsUpgradedRequestWebsocket);
    url_.SetProtocol("wss");
    if (url_.Port() == 80)
      url_.SetPort(443);
  }

  if (!url_.IsValid()) {
    state_ = kClosed;
    exception_state.ThrowDOMException(DOMExceptionCode::kSyntaxError,
                                      "The URL '" + url + "' is invalid.");
    return ConnectResult::kException;
  }
  if (!url_.ProtocolIs("ws") && !url_.ProtocolIs("wss")) {
    state_ = kClosed;
    exception_state.ThrowDOMException(
        DOMExceptionCode::kSyntaxError,
        "The URL's scheme must be either 'http', 'https', 'ws', or 'wss'. '" +
            url_.Protocol() + "' is not allowed.");
    return ConnectResult::kException;
  }

  if (url_.HasFragmentIdentifier()) {
    state_ = kClosed;
    exception_state.ThrowDOMException(
        DOMExceptionCode::kSyntaxError,
        "The URL contains a fragment identifier ('" +
            url_.FragmentIdentifier() +
            "'). Fragment identifiers are not allowed in WebSocket URLs.");
    return ConnectResult::kException;
  }

  if (!execution_context->GetContentSecurityPolicyForCurrentWorld()
           ->AllowConnectToSource(url_, url_, RedirectStatus::kNoRedirect)) {
    state_ = kClosed;

    return ConnectResult::kAsyncError;
  }

  // Fail if not all elements in |protocols| are valid.
  for (const String& protocol : protocols) {
    if (!IsValidSubprotocolString(protocol)) {
      state_ = kClosed;
      exception_state.ThrowDOMException(DOMExceptionCode::kSyntaxError,
                                        "The subprotocol '" +
                                            EncodeSubprotocolString(protocol) +
                                            "' is invalid.");
      return ConnectResult::kException;
    }
  }

  // Fail if there're duplicated elements in |protocols|.
  HashSet<String> visited;
  for (const String& protocol : protocols) {
    if (!visited.insert(protocol).is_new_entry) {
      state_ = kClosed;
      exception_state.ThrowDOMException(DOMExceptionCode::kSyntaxError,
                                        "The subprotocol '" +
                                            EncodeSubprotocolString(protocol) +
                                            "' is duplicated.");
      return ConnectResult::kException;
    }
  }

  String protocol_string;
  if (!protocols.empty())
    protocol_string = JoinStrings(protocols, kWebSocketSubprotocolSeparator);

  if (!channel->Connect(url_, protocol_string)) {
    state_ = kClosed;
    exception_state.ThrowSecurityError(
        "An insecure WebSocket connection may not be initiated from a page "
        "loaded over HTTPS.");
    channel->Disconnect();
    return ConnectResult::kException;
  }

  return ConnectResult::kSuccess;
}

void WebSocketCommon::CloseInternal(std::optional<uint16_t> code,
                                    const String& reason,
                                    WebSocketChannel* channel,
                                    ExceptionState& exception_state) {
  if (code) {
    DVLOG(1) << "WebSocket " << this << " close() code=" << code.value()
             << " reason=" << reason;
  } else {
    DVLOG(1) << "WebSocket " << this << " close() without code and reason";
  }
  const std::optional<uint16_t> maybe_code =
      ValidateCloseCodeAndReason(code, reason, exception_state);
  const int valid_code = maybe_code
                             ? static_cast<int>(maybe_code.value())
                             : WebSocketChannel::kCloseEventCodeNotSpecified;

  if (exception_state.HadException()) {
    return;
  }

  if (state_ == kClosing || state_ == kClosed)
    return;
  if (state_ == kConnecting) {
    state_ = kClosing;
    channel->Fail(
        "WebSocket is closed before the connection is established.",
        mojom::ConsoleMessageLevel::kWarning,
        std::make_unique<SourceLocation>(String(), String(), 0, 0, nullptr));
    return;
  }
  state_ = kClosing;
  if (channel)
    channel->Close(valid_code, reason);
}

inline bool WebSocketCommon::IsValidSubprotocolCharacter(UChar character) {
  const UChar kMinimumProtocolCharacter = '!';  // U+0021.
  const UChar kMaximumProtocolCharacter = '~';  // U+007E.
  // Set to true if character does not matches "separators" ABNF defined in
  // RFC2616. SP and HT are excluded since the range check excludes them.
  bool is_not_separator =
      character != '"' && character != '(' && character != ')' &&
      character != ',' && character != '/' &&
      !(character >= ':' &&
        character <=
            '@')  // U+003A - U+0040 (':', ';', '<', '=', '>', '?', '@').
      && !(character >= '[' &&
           character <= ']')  // U+005B - U+005D ('[', '\\', ']').
      && character != '{' && character != '}';
  return character >= kMinimumProtocolCharacter &&
         character <= kMaximumProtocolCharacter && is_not_separator;
}

bool WebSocketCommon::IsValidSubprotocolString(const String& protocol) {
  if (protocol.empty())
    return false;
  for (wtf_size_t i = 0; i < protocol.length(); ++i) {
    if (!IsValidSubprotocolCharacter(protocol[i]))
      return false;
  }
  return true;
}

String WebSocketCommon::EncodeSubprotocolString(const String& protocol) {
  StringBuilder builder;
  for (wtf_size_t i = 0; i < protocol.length(); i++) {
    if (protocol[i] < 0x20 || protocol[i] > 0x7E)
      builder.AppendFormat("\\u%04X", protocol[i]);
    else if (protocol[i] == 0x5c)
      builder.Append("\\\\");
    else
      builder.Append(protocol[i]);
  }
  return builder.ToString();
}

String WebSocketCommon::JoinStrings(const Vector<String>& strings,
                                    const char* separator) {
  StringBuilder builder;
  for (wtf_size_t i = 0; i < strings.size(); ++i) {
    if (i)
      builder.Append(separator);
    builder.Append(strings[i]);
  }
  return builder.ToString();
}

std::optional<uint16_t> WebSocketCommon::ValidateCloseCodeAndReason(
    std::optional<uint16_t> code,
    const String& reason,
    ExceptionState& exception_state) {
  if (code) {
    const uint16_t close_code = code.value();
    if (!(close_code == WebSocketChannel::kCloseEventCodeNormalClosure ||
          (WebSocketChannel::kCloseEventCodeMinimumUserDefined <= close_code &&
           close_code <=
               WebSocketChannel::kCloseEventCodeMaximumUserDefined))) {
      exception_state.ThrowDOMException(
          DOMExceptionCode::kInvalidAccessError,
          "The close code must be either 1000, or between 3000 and 4999. " +
              String::Number(close_code) + " is neither.");
      return code;
    }
  } else if (!reason.empty()) {
    code = WebSocketChannel::kCloseEventCodeNormalClosure;
  }

  // Bindings specify USVString, so unpaired surrogates are already replaced
  // with U+FFFD.
  StringUTF8Adaptor utf8(reason);
  if (utf8.size() > kMaxReasonSizeInBytes) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kSyntaxError,
        "The close reason must not be greater than " +
            String::Number(kMaxReasonSizeInBytes) + " UTF-8 bytes.");
    return code;
  }
  return code;
}

}  // namespace blink

"""

```