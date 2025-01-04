Response:
My goal is to analyze the provided C++ code snippet from Chromium's network stack and address all the user's requests. Here's a breakdown of the thinking process:

1. **Understand the Context:** The user states this is part of `net/http/http_cache_transaction.cc` and the third of five parts. This immediately tells me I'm dealing with the logic for handling HTTP caching within a transaction. Knowing it's part 3/5 implies a larger flow is being described, and this section likely focuses on a specific stage of the caching process.

2. **Identify the Core Functionality:** I need to read through the code and understand what it *does*. A quick scan reveals several key actions:
    * **Sending Requests:**  Functions like `DoSendRequestComplete` and `DoSuccessfulSendRequest` deal with sending HTTP requests to the network.
    * **Handling Responses:**  Code checks response codes (200, 304, 206, 401, 407, 416), handles authentication challenges, and processes successful responses.
    * **Cache Interactions:**  The code interacts with the cache to update, overwrite, and validate entries. Functions like `DoUpdateCachedResponse`, `DoOverwriteCachedResponse`, `DoCacheWriteResponse`, and `DoCacheReadData` are central to this.
    * **Partial Content (206):**  There's specific logic for handling partial content responses, especially through the `PartialData` class.
    * **Conditional Requests:**  The code handles `If-Modified-Since` and `If-None-Match` headers for conditional requests.
    * **Error Handling:** The code checks for various errors (network errors, cache errors, authentication failures).
    * **State Management:** The `TransitionToState` calls indicate a state machine managing the lifecycle of the transaction.

3. **Address Each User Request Systematically:**

    * **功能 (Functionality):**  I need to summarize the core actions identified above concisely. Focusing on the key verbs (sending, receiving, updating, validating, etc.) is helpful.

    * **与 JavaScript 的关系 (Relationship with JavaScript):** This requires understanding how JavaScript interacts with the network stack. Key areas are:
        * **`fetch()` API:**  A primary way for JavaScript to make network requests, which would trigger this caching logic.
        * **`cache: '...'` options in `fetch()`:**  Specifically, `only-if-cached` and how the code handles its potential conflict with byte ranges.
        * **Service Workers:**  Service workers can intercept network requests and interact with the cache.
        * **Browser Cache Settings:** User browser settings influence how the cache behaves.

    * **逻辑推理 (Logical Reasoning):**  The request asks for assumed inputs and outputs. The most logical place to apply this is within the conditional logic (e.g., `if` statements). I should pick a few representative scenarios:
        * **Successful conditional GET (304 Not Modified):**  Input: Validation headers, existing cache entry. Output: Cache entry updated, no new data fetched.
        * **Unsuccessful conditional GET (200 OK):** Input: Validation headers, existing cache entry. Output: Cache entry overwritten with new data.
        * **Partial content request (206 Partial Content):** Input: `Range` header. Output: Cache entry updated or created with the requested range.
        * **Authentication challenge (401 or 407):** Input: Unauthorized response. Output: Potential restart with authentication credentials.

    * **用户/编程常见错误 (Common User/Programming Errors):**  Think about how developers or users might misuse or encounter issues with caching:
        * **Incorrect Cache Headers:** Servers sending incorrect `Cache-Control` or `Expires` headers.
        * **Conflicting `fetch()` options:** Using `only-if-cached` with range requests.
        * **Authentication Issues:** Expired credentials leading to repeated authentication failures.
        * **Cache Invalidation Problems:**  Not invalidating the cache correctly after data changes.

    * **用户操作到达这里 (User Actions Leading Here):** This is about tracing back the user's journey that would involve this code:
        * **Typing a URL:**  A basic navigation.
        * **Clicking a link:**  Another common navigation.
        * **Subresource loading:** Images, scripts, stylesheets on a web page.
        * **`fetch()` requests from JavaScript.**
        * **Form submissions.**
        * **Service worker intercepting requests.**

    * **调试线索 (Debugging Clues):**  What information would be helpful for a developer debugging issues related to this code?
        * **NetLog:**  Essential for seeing the detailed network activity.
        * **Cache Inspection Tools:**  Browser developer tools to examine the cache.
        * **Breakpoints:**  Setting breakpoints in the code to step through execution.
        * **Request Headers:**  Examining the request and response headers.
        * **Error Codes:**  Looking at the specific `net::ERR_...` codes.

    * **归纳功能 (Summary of Functionality):**  Condense the overall purpose of this specific code segment, considering its context within the larger transaction. Focus on the transitions between states and the core caching actions performed.

4. **Structure the Answer:** Organize the information clearly using headings and bullet points to make it easy to read and understand. Present the information logically, following the order of the user's requests.

5. **Review and Refine:**  Read through the generated answer to ensure accuracy, completeness, and clarity. Check for any inconsistencies or areas that could be explained better. For instance, ensure the JavaScript examples are relevant and the debugging tips are practical.

By following these steps, I can produce a comprehensive and accurate answer that addresses all aspects of the user's request. The decomposed approach allows for focusing on each requirement individually and then integrating the pieces into a coherent whole.
好的，让我们来分析一下 `net/http/http_cache_transaction.cc` 文件的第三部分代码的功能。

**代码功能归纳 (第 3 部分)**

这段代码主要负责处理 HTTP 缓存事务中与 **发送请求、接收响应头并根据响应头进行后续处理** 相关的逻辑。它涉及以下关键步骤：

1. **发送网络请求 (DoSendRequest):**  启动真正的网络请求，并处理请求启动后的结果。如果发生错误，会记录相关信息。

2. **处理发送请求完成 (DoSendRequestComplete):**
   - 检查网络请求的结果（成功或失败）。
   - 如果请求失败，记录失败原因，并根据错误类型进行不同的处理，例如：
     - 对于证书错误，记录 SSL 信息。
     - 对于需要客户端证书认证，记录证书请求信息。
     - 对于 IP 地址空间不一致的错误，标记条目为 "doom"。
   - 如果请求成功，则进入下一个状态。

3. **处理成功发送请求 (DoSuccessfulSendRequest):**
   - 获取响应头。
   - **处理认证挑战 (401 Unauthorized, 407 Proxy Authentication Required):** 如果收到认证质询，会尝试使用之前存储的凭据进行重试。如果重试失败（例如，没有凭据或凭据已过期），则会进行清理并返回错误。
   - **处理部分响应 (206 Partial Content):** 验证部分响应是否有效。如果无效，则重新发送完整的请求。
   - **处理缓存条目的更新和失效:**
     - 如果以 `WRITE` 模式且没有条件化请求失败，则更新缓存条目的状态。
     - 对于 `PUT`, `DELETE`, `PATCH` 请求成功后，会使缓存中相应的 `GET` 请求失效。
     - 对于 `POST` 请求成功后，也会使缓存中相应的条目失效。
   - **处理 `416 Requested Range Not Satisfiable`:**  如果服务器返回此错误，表示请求的范围无效。
   - **处理条件请求的结果 (304 Not Modified, 206 Partial Content):**
     - 如果收到 `304` 或 `206`，则更新缓存中的响应头。
     - 如果是 `304`，表示缓存的副本仍然有效。
     - 如果是 `206`，表示服务器返回了请求的范围。
   - **处理需要覆盖缓存的情况:** 如果响应指示需要覆盖现有缓存条目，则进入覆盖缓存的状态。

4. **更新缓存的响应头 (DoUpdateCachedResponse, DoCacheWriteUpdatedResponse, DoCacheWriteUpdatedResponseComplete, DoUpdateCachedResponseComplete):**
   - 更新缓存中响应头的各种属性，例如响应时间、网络访问状态、SSL 信息等。
   - 处理 `Vary` 头，确保缓存的响应与请求头匹配。
   - 将更新后的响应头写回缓存。

5. **覆盖缓存的响应 (DoOverwriteCachedResponse, DoCacheWriteResponse, DoCacheWriteResponseComplete, DoTruncateCachedData, DoTruncateCachedDataComplete):**
   - 如果是 `HEAD` 请求，则只更新响应头，不写入响应体。
   - 如果是部分响应且无法继续，则不存储该资源。
   - 将新的响应信息写入缓存。
   - 如果需要，截断缓存中的现有数据。

6. **处理部分响应头接收完成 (DoPartialHeadersReceived):**  在处理部分响应后，对响应头进行最后的调整。

7. **处理头部阶段无法继续 (DoHeadersPhaseCannotProceed):**  如果头部处理阶段由于缓存错误而无法继续，则重新启动事务。

8. **完成头部处理 (DoFinishHeaders, DoFinishHeadersComplete):**
   - 当响应头处理完成后，通知缓存系统。
   - 如果需要等待其他事务完成写入，则会返回 `ERR_IO_PENDING`。

9. **网络读取并写入缓存 (DoNetworkReadCacheWrite, DoNetworkReadCacheWriteComplete):** 从网络读取数据，并将其写入缓存。

10. **处理部分网络读取完成 (DoPartialNetworkReadCompleted):**  处理部分内容下载完成的情况，可能需要请求下一个范围。

11. **网络读取 (DoNetworkRead, DoNetworkReadComplete):** 从网络读取数据，但不涉及缓存写入（可能用于读取未缓存的资源）。

12. **从缓存读取数据 (DoCacheReadData, DoCacheReadDataComplete):** 从缓存读取响应体数据。

13. **设置请求信息 (SetRequest):**  初始化请求相关的状态，包括解析请求头中的特殊指令（如 `Cache-Control`，`Pragma` 等）来设置加载标志。处理 `Range` 请求头，并根据情况创建 `PartialData` 对象。

14. **判断是否直接通过网络 (ShouldPassThrough):**  判断某些请求是否应该绕过缓存，例如非 `GET` 或 `HEAD` 请求，或者启用了 `LOAD_DISABLE_CACHE` 标志。

15. **开始缓存读取 (BeginCacheRead):**  开始从缓存读取数据的准备工作，检查缓存的完整性和有效性。

16. **开始缓存验证 (BeginCacheValidation):**  对于需要验证的缓存条目，准备发起条件请求（例如带有 `If-Modified-Since` 或 `If-None-Match` 头）。

**与 JavaScript 的关系及举例说明**

这段 C++ 代码是 Chromium 浏览器网络栈的一部分，负责底层的 HTTP 缓存管理。JavaScript 代码通过浏览器的 `fetch` API 或传统的 `XMLHttpRequest` 发起网络请求，这些请求最终会路由到 Chromium 的网络栈进行处理，其中就包括这段缓存逻辑。

**举例说明:**

假设一个 JavaScript 代码使用 `fetch` API 请求一个图片资源：

```javascript
fetch('https://example.com/image.png')
  .then(response => response.blob())
  .then(imageBlob => {
    // 处理图片数据
  });
```

1. **用户操作:** 用户访问一个包含上述 JavaScript 代码的网页。
2. **JavaScript 发起请求:**  `fetch` 函数被调用，向 `https://example.com/image.png` 发起 GET 请求。
3. **网络栈处理:**  Chromium 的网络栈接收到这个请求。
4. **进入 `HttpCache::Transaction`:**  创建 `HttpCache::Transaction` 对象来处理这个请求的缓存逻辑。
5. **`SetRequest` 被调用:**  解析请求头，可能包含缓存控制相关的头信息。
6. **`BeginCacheRead` 或 `BeginCacheValidation`:** 如果缓存中存在该资源的条目，会尝试从缓存读取或进行验证。
7. **如果缓存未命中或需要验证，则 `DoSendRequest` 被调用:**  发送真正的网络请求到服务器。
8. **`DoSendRequestComplete` 和 `DoSuccessfulSendRequest`:**  接收并处理服务器的响应头。
9. **`DoOverwriteCachedResponse` 和 `DoCacheWriteResponse`:** 如果响应需要被缓存，则将响应写入缓存。
10. **`DoNetworkReadCacheWrite`:**  如果响应体也需要被缓存，则从网络读取响应体并写入缓存。

**JavaScript 的 `fetch` API 的 `cache` 选项与此代码相关：**

- **`cache: 'default'`:**  浏览器根据 HTTP 缓存头进行缓存，这段代码会参与处理。
- **`cache: 'no-store'`:**  强制不缓存，会绕过大部分缓存逻辑。
- **`cache: 'reload'`:**  强制从服务器获取资源，会跳过缓存读取，但响应仍然可能被缓存。
- **`cache: 'no-cache'`:**  在读取缓存前强制进行验证。
- **`cache: 'force-cache'`:**  强制从缓存读取，忽略过期时间。
- **`cache: 'only-if-cached'`:**  只在缓存中存在时读取，否则请求失败。在 `BeginCacheRead` 函数中可以看到，对于 `response_.headers->response_code() == HTTP_PARTIAL_CONTENT || partial_` 的情况，如果使用了 `only-if-cached`，则会返回 `ERR_CACHE_MISS`。

**逻辑推理、假设输入与输出**

**假设输入:**

- **场景 1:** 缓存中存在一个已过期的 `image.png` 资源，请求头中没有缓存控制指令。
- **场景 2:** 缓存中不存在 `style.css` 资源。
- **场景 3:**  JavaScript 使用 `fetch` 请求一个很大的视频文件，并带有 `Range: bytes=0-1023` 请求头。

**逻辑推理与输出:**

- **场景 1:**
    - **输入:**  请求 `image.png`，缓存中存在过期条目。
    - **代码路径:**  `BeginCacheValidation` 会判断需要验证 -> `DoSendRequest` 发送带有条件头的请求（例如 `If-Modified-Since`）。
    - **假设服务器返回 `304 Not Modified`:**
        - **代码路径:** `DoSuccessfulSendRequest` 识别出 `304` -> `DoUpdateCachedResponse` 更新缓存条目的元数据 ->  最终从缓存读取数据。
        - **输出:**  浏览器使用缓存中的 `image.png`，并更新了缓存条目的有效期。
    - **假设服务器返回 `200 OK` 和新的图片数据:**
        - **代码路径:** `DoSuccessfulSendRequest` 识别出 `200` -> `DoOverwriteCachedResponse` -> `DoCacheWriteResponse` 将新的图片数据写入缓存。
        - **输出:** 浏览器使用新的 `image.png`，缓存中的条目被更新。

- **场景 2:**
    - **输入:** 请求 `style.css`，缓存中不存在条目。
    - **代码路径:** `BeginCacheRead` 发现缓存未命中 -> `DoSendRequest` 发送网络请求。
    - **假设服务器返回 `200 OK` 和 CSS 数据:**
        - **代码路径:** `DoSuccessfulSendRequest` 识别出 `200` -> `DoOverwriteCachedResponse` -> `DoCacheWriteResponse` 将 CSS 数据写入缓存。
        - **输出:** 浏览器下载 `style.css` 并渲染页面，`style.css` 被缓存。

- **场景 3:**
    - **输入:**  请求大视频文件的一部分，带有 `Range` 头。
    - **代码路径:** `SetRequest` 解析 `Range` 头，创建 `PartialData` 对象 -> `BeginCacheRead` 或 `BeginCacheValidation` 可能会检查缓存中是否已存在部分内容。
    - **假设缓存中没有该视频的任何内容:**
        - **代码路径:** `DoSendRequest` 发送带有 `Range` 头的网络请求。
        - **代码路径:** `DoSuccessfulSendRequest` 识别出 `206` -> `DoOverwriteCachedResponse` -> `DoCacheWriteResponse` 写入接收到的部分数据。
        - **代码路径:** `DoNetworkReadCacheWrite` 继续读取并写入后续的数据块，直到完成请求或用户停止播放。
        - **输出:** 浏览器开始播放视频，缓存中存储了部分视频数据。

**用户或编程常见的使用错误**

1. **服务器缓存配置错误:**
   - 服务器没有设置正确的 `Cache-Control` 或 `Expires` 头，导致浏览器无法正确缓存资源或缓存过期时间不合理。
   - 例如，服务器返回 `Cache-Control: no-cache`，即使资源内容没有变化，浏览器每次都会请求服务器进行验证。

2. **强制刷新导致的意外行为:**
   - 用户在浏览器中执行强制刷新（通常是 Ctrl+Shift+R 或 Cmd+Shift+R），这会发送带有 `Cache-Control: no-cache` 或 `Pragma: no-cache` 的请求，导致缓存被绕过。开发者可能会误以为是缓存没有生效。

3. **不理解 `Vary` 头的含义:**
   - 服务器使用 `Vary` 头指示响应可能依赖于某些请求头。如果开发者没有正确配置 `Vary` 头，可能导致缓存的响应与实际请求不匹配。
   - 例如，服务器对于不同的 `Accept-Language` 返回不同的内容，但 `Vary` 头中没有包含 `Accept-Language`，可能导致用户看到错误的语言版本。

4. **在需要缓存的场景下禁用缓存:**
   - 开发者在开发环境中可能会禁用缓存，以便每次都能看到最新的更改，但在生产环境中忘记启用，导致用户每次都需要重新下载资源，降低性能。

5. **错误地使用 `fetch` API 的 `cache` 选项:**
   - 例如，在需要获取最新数据的场景下使用了 `cache: 'force-cache'`，导致使用了过期的缓存数据。
   - 又如，在需要确保缓存存在的情况下使用了 `cache: 'only-if-cached'`，但缓存可能因为某些原因被清空，导致请求失败。

**用户操作是如何一步步的到达这里，作为调试线索**

假设用户在浏览器中访问了一个包含图片的网页，并且该图片之前已经被缓存过，但可能已经过期。

1. **用户在地址栏输入网址或点击链接:**  浏览器开始加载页面。
2. **解析 HTML 并遇到 `<img>` 标签:** 浏览器发现需要加载图片资源。
3. **网络栈发起对图片资源的请求:**  创建一个 `HttpCache::Transaction` 对象来处理该请求。
4. **`SetRequest` 被调用:**  解析请求头。
5. **`BeginCacheRead` 被调用:**  检查缓存中是否存在该图片资源。
6. **发现缓存条目，但可能已过期:** `RequiresValidation()` 函数会根据缓存头判断是否需要验证。
7. **`BeginCacheValidation` 被调用 (如果需要验证):**  准备发起条件 GET 请求。
8. **`TransitionToState(STATE_SEND_REQUEST)`:**  状态机进入发送请求的状态。
9. **`DoSendRequest` 被调用:**  创建并发送带有条件头的网络请求。
10. **网络层发送请求到服务器:**
11. **服务器处理请求并返回响应头:**
12. **网络层接收响应头:**
13. **`DoSendRequestComplete` 被调用:**  处理网络请求完成的结果。
14. **`DoSuccessfulSendRequest` 被调用:**  处理成功的请求，检查响应头。
15. **如果服务器返回 `304 Not Modified`:**
    - `UpdateCacheEntryStatus(CacheEntryStatus::ENTRY_VALIDATED)`
    - `TransitionToState(STATE_UPDATE_CACHED_RESPONSE)`
    - `DoUpdateCachedResponse` 更新缓存条目的元数据。
16. **如果服务器返回 `200 OK` 和新的图片数据:**
    - `UpdateCacheEntryStatus(CacheEntryStatus::ENTRY_UPDATED)`
    - `TransitionToState(STATE_OVERWRITE_CACHED_RESPONSE)`
    - `DoOverwriteCachedResponse` 准备覆盖缓存。
    - `DoCacheWriteResponse` 将新的图片数据写入缓存。

**调试线索:**

- **Chrome 的 `chrome://net-export/` (网络事件记录):** 可以记录详细的网络事件，包括缓存的命中、未命中、验证等信息，可以看到请求头和响应头，以及各个阶段的耗时。
- **Chrome 开发者工具 -> Network 面板:**  可以查看请求的状态码、Headers、Timing 等信息，可以判断资源是否从缓存加载，以及缓存的控制策略。
- **Chrome 开发者工具 -> Application 面板 -> Cache storage / HTTP cache:**  可以查看当前网站的缓存内容，包括资源的 URL、大小、过期时间等。
- **在 `net/http/http_cache_transaction.cc` 中添加断点:**  如果需要深入了解代码执行流程，可以在关键函数（如 `DoSendRequestComplete`, `DoSuccessfulSendRequest`, `BeginCacheRead`, `BeginCacheValidation` 等）设置断点，查看变量的值和状态转换。
- **查看 NetLog:** 代码中多次调用 `net_log_.AddEvent` 等方法，这些日志信息可以通过 `chrome://net-internals/#events` 查看，可以帮助理解缓存决策的过程。

希望以上分析能够帮助你理解 `net/http/http_cache_transaction.cc` 文件第三部分的功能。

Prompt: 
```
这是目录为net/http/http_cache_transaction.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共5部分，请归纳一下它的功能

"""
g information, if any, is now obsolete.
  network_transaction_info_.old_network_trans_load_timing.reset();
  network_transaction_info_.old_remote_endpoint = IPEndPoint();

  if (websocket_handshake_stream_base_create_helper_) {
    network_trans_->SetWebSocketHandshakeStreamCreateHelper(
        websocket_handshake_stream_base_create_helper_);
  }

  TransitionToState(STATE_SEND_REQUEST_COMPLETE);
  rv = network_trans_->Start(request_, io_callback_, net_log_);
  if (rv != ERR_IO_PENDING && waiting_for_cache_io_) {
    // queue the state transition until the HttpCache transaction completes
    DCHECK(!pending_io_result_);
    pending_io_result_ = rv;
    rv = ERR_IO_PENDING;
  }
  return rv;
}

int HttpCache::Transaction::DoSendRequestComplete(int result) {
  TRACE_EVENT_INSTANT("net", "HttpCacheTransaction::DoSendRequestComplete",
                      perfetto::Track(trace_id_), "result", result, "elapsed",
                      base::TimeTicks::Now() - send_request_since_);
  if (!cache_.get()) {
    TransitionToState(STATE_FINISH_HEADERS);
    return ERR_UNEXPECTED;
  }

  // If we tried to conditionalize the request and failed, we know
  // we won't be reading from the cache after this point.
  if (couldnt_conditionalize_request_) {
    mode_ = WRITE;
  }

  if (result == OK) {
    TransitionToState(STATE_SUCCESSFUL_SEND_REQUEST);
    return OK;
  }

  const HttpResponseInfo* response = network_trans_->GetResponseInfo();
  response_.network_accessed = response->network_accessed;
  response_.proxy_chain = response->proxy_chain;
  response_.restricted_prefetch = response->restricted_prefetch;
  response_.resolve_error_info = response->resolve_error_info;

  // Do not record requests that have network errors or restarts.
  UpdateCacheEntryStatus(CacheEntryStatus::ENTRY_OTHER);
  if (IsCertificateError(result)) {
    // If we get a certificate error, then there is a certificate in ssl_info,
    // so GetResponseInfo() should never return NULL here.
    DCHECK(response);
    response_.ssl_info = response->ssl_info;
  } else if (result == ERR_SSL_CLIENT_AUTH_CERT_NEEDED) {
    DCHECK(response);
    response_.cert_request_info = response->cert_request_info;
  } else if (result == ERR_INCONSISTENT_IP_ADDRESS_SPACE) {
    DoomInconsistentEntry();
  } else if (response_.was_cached) {
    DoneWithEntry(/*entry_is_complete=*/true);
  }

  TransitionToState(STATE_FINISH_HEADERS);
  return result;
}

// We received the response headers and there is no error.
int HttpCache::Transaction::DoSuccessfulSendRequest() {
  DCHECK(!new_response_);
  const HttpResponseInfo* new_response = network_trans_->GetResponseInfo();
  TRACE_EVENT_INSTANT("net", "HttpCacheTransaction::DoSuccessfulSendRequest",
                      perfetto::Track(trace_id_), "response_code",
                      new_response->headers->response_code());

  if (new_response->headers->response_code() == HTTP_UNAUTHORIZED ||
      new_response->headers->response_code() ==
          HTTP_PROXY_AUTHENTICATION_REQUIRED) {
    SetAuthResponse(*new_response);
    if (!reading_) {
      TransitionToState(STATE_FINISH_HEADERS);
      return OK;
    }

    // We initiated a second request the caller doesn't know about. We should be
    // able to authenticate this request because we should have authenticated
    // this URL moments ago.
    if (IsReadyToRestartForAuth()) {
      TransitionToState(STATE_SEND_REQUEST_COMPLETE);
      // In theory we should check to see if there are new cookies, but there
      // is no way to do that from here.
      return network_trans_->RestartWithAuth(AuthCredentials(), io_callback_);
    }

    // We have to perform cleanup at this point so that at least the next
    // request can succeed.  We do not retry at this point, because data
    // has been read and we have no way to gather credentials.  We would
    // fail again, and potentially loop.  This can happen if the credentials
    // expire while chrome is suspended.
    if (entry_) {
      DoomPartialEntry(false);
    }
    mode_ = NONE;
    partial_.reset();
    ResetNetworkTransaction();
    TransitionToState(STATE_FINISH_HEADERS);
    return ERR_CACHE_AUTH_FAILURE_AFTER_READ;
  }

  new_response_ = new_response;
  if (!ValidatePartialResponse() && !auth_response_.headers.get()) {
    // Something went wrong with this request and we have to restart it.
    // If we have an authentication response, we are exposed to weird things
    // hapenning if the user cancels the authentication before we receive
    // the new response.
    net_log_.AddEvent(NetLogEventType::HTTP_CACHE_RE_SEND_PARTIAL_REQUEST);
    UpdateCacheEntryStatus(CacheEntryStatus::ENTRY_OTHER);
    SetResponse(HttpResponseInfo());
    ResetNetworkTransaction();
    new_response_ = nullptr;
    TransitionToState(STATE_SEND_REQUEST);
    return OK;
  }

  if (handling_206_ && mode_ == READ_WRITE && !truncated_ && !is_sparse_) {
    // We have stored the full entry, but it changed and the server is
    // sending a range. We have to delete the old entry.
    UpdateCacheEntryStatus(CacheEntryStatus::ENTRY_OTHER);
    DoneWithEntry(false);
  }

  if (mode_ == WRITE &&
      cache_entry_status_ != CacheEntryStatus::ENTRY_CANT_CONDITIONALIZE) {
    UpdateCacheEntryStatus(CacheEntryStatus::ENTRY_NOT_IN_CACHE);
  }

  // Invalidate any cached GET with a successful PUT, DELETE, or PATCH.
  if (mode_ == WRITE &&
      (method_ == "PUT" || method_ == "DELETE" || method_ == "PATCH")) {
    if (NonErrorResponse(new_response_->headers->response_code()) &&
        (entry_ && !entry_->IsDoomed())) {
      int ret = cache_->DoomEntry(cache_key_, nullptr);
      DCHECK_EQ(OK, ret);
    }
    // Do not invalidate the entry if the request failed.
    DoneWithEntry(true);
  }

  // Invalidate any cached GET with a successful POST. If the network isolation
  // key isn't populated with the split cache active, there will be nothing to
  // invalidate in the cache.
  if (!(effective_load_flags_ & LOAD_DISABLE_CACHE) && method_ == "POST" &&
      NonErrorResponse(new_response_->headers->response_code()) &&
      (!HttpCache::IsSplitCacheEnabled() ||
       request_->network_isolation_key.IsFullyPopulated())) {
    cache_->DoomMainEntryForUrl(request_->url, request_->network_isolation_key,
                                request_->is_subframe_document_resource,
                                request_->is_main_frame_navigation,
                                request_->initiator);
  }

  if (new_response_->headers->response_code() ==
          HTTP_REQUESTED_RANGE_NOT_SATISFIABLE &&
      (method_ == "GET" || method_ == "POST")) {
    // If there is an active entry it may be destroyed with this transaction.
    SetResponse(*new_response_);
    TransitionToState(STATE_FINISH_HEADERS);
    return OK;
  }

  // Are we expecting a response to a conditional query?
  if (mode_ == READ_WRITE || mode_ == UPDATE) {
    if (new_response->headers->response_code() == HTTP_NOT_MODIFIED ||
        handling_206_) {
      UpdateCacheEntryStatus(CacheEntryStatus::ENTRY_VALIDATED);
      TransitionToState(STATE_UPDATE_CACHED_RESPONSE);
      return OK;
    }
    UpdateCacheEntryStatus(CacheEntryStatus::ENTRY_UPDATED);
    mode_ = WRITE;
  }

  TransitionToState(STATE_OVERWRITE_CACHED_RESPONSE);
  return OK;
}

// We received 304 or 206 and we want to update the cached response headers.
int HttpCache::Transaction::DoUpdateCachedResponse() {
  TRACE_EVENT_INSTANT("net", "HttpCacheTransaction::DoUpdateCachedResponse",
                      perfetto::Track(trace_id_));
  int rv = OK;
  // Update the cached response based on the headers and properties of
  // new_response_.
  response_.headers->Update(*new_response_->headers.get());
  response_.stale_revalidate_timeout = base::Time();
  response_.response_time = new_response_->response_time;
  if (new_response_->headers->response_code() != net::HTTP_NOT_MODIFIED) {
    response_.original_response_time = new_response_->response_time;
  }
  response_.request_time = new_response_->request_time;
  response_.network_accessed = new_response_->network_accessed;
  response_.unused_since_prefetch = new_response_->unused_since_prefetch;
  response_.restricted_prefetch = new_response_->restricted_prefetch;
  response_.ssl_info = new_response_->ssl_info;
  response_.dns_aliases = new_response_->dns_aliases;

  // If the new response didn't have a vary header, we continue to use the
  // header from the stored response per the effect of headers->Update().
  // Update the data with the new/updated request headers.
  response_.vary_data.Init(*request_, *response_.headers);

  if (UpdateAndReportCacheability(*response_.headers)) {
    if (!entry_->IsDoomed()) {
      int ret = cache_->DoomEntry(cache_key_, nullptr);
      DCHECK_EQ(OK, ret);
    }
    TransitionToState(STATE_UPDATE_CACHED_RESPONSE_COMPLETE);
  } else {
    // If we are already reading, we already updated the headers for this
    // request; doing it again will change Content-Length.
    if (!reading_) {
      TransitionToState(STATE_CACHE_WRITE_UPDATED_RESPONSE);
      rv = OK;
    } else {
      TransitionToState(STATE_UPDATE_CACHED_RESPONSE_COMPLETE);
    }
  }

  return rv;
}

int HttpCache::Transaction::DoCacheWriteUpdatedResponse() {
  TRACE_EVENT_INSTANT("net",
                      "HttpCacheTransaction::DoCacheWriteUpdatedResponse",
                      perfetto::Track(trace_id_));
  TransitionToState(STATE_CACHE_WRITE_UPDATED_RESPONSE_COMPLETE);
  return WriteResponseInfoToEntry(response_, false);
}

int HttpCache::Transaction::DoCacheWriteUpdatedResponseComplete(int result) {
  TRACE_EVENT_INSTANT(
      "net", "HttpCacheTransaction::DoCacheWriteUpdatedResponseComplete",
      perfetto::Track(trace_id_), "result", result);
  TransitionToState(STATE_UPDATE_CACHED_RESPONSE_COMPLETE);
  return OnWriteResponseInfoToEntryComplete(result);
}

int HttpCache::Transaction::DoUpdateCachedResponseComplete(int result) {
  TRACE_EVENT_INSTANT("net",
                      "HttpCacheTransaction::DoUpdateCachedResponseComplete",
                      perfetto::Track(trace_id_), "result", result);
  if (mode_ == UPDATE) {
    DCHECK(!handling_206_);
    // We got a "not modified" response and already updated the corresponding
    // cache entry above.
    //
    // By stopping to write to the cache now, we make sure that the 304 rather
    // than the cached 200 response, is what will be returned to the user.
    UpdateSecurityHeadersBeforeForwarding();
    DoneWithEntry(true);
  } else if (entry_ && !handling_206_) {
    DCHECK_EQ(READ_WRITE, mode_);
    if ((!partial_ && !entry_->IsWritingInProgress()) ||
        (partial_ && partial_->IsLastRange())) {
      mode_ = READ;
    }
    // We no longer need the network transaction, so destroy it.
    if (network_trans_) {
      ResetNetworkTransaction();
    }
  } else if (entry_ && handling_206_ && truncated_ &&
             partial_->initial_validation()) {
    // We just finished the validation of a truncated entry, and the server
    // is willing to resume the operation. Now we go back and start serving
    // the first part to the user.
    if (network_trans_) {
      ResetNetworkTransaction();
    }
    new_response_ = nullptr;
    TransitionToState(STATE_START_PARTIAL_CACHE_VALIDATION);
    partial_->SetRangeToStartDownload();
    return OK;
  }
  TransitionToState(STATE_OVERWRITE_CACHED_RESPONSE);
  return OK;
}

int HttpCache::Transaction::DoOverwriteCachedResponse() {
  TRACE_EVENT_INSTANT("net", "HttpCacheTransaction::DoOverwriteCachedResponse",
                      perfetto::Track(trace_id_));
  if (mode_ & READ) {
    TransitionToState(STATE_PARTIAL_HEADERS_RECEIVED);
    return OK;
  }

  // We change the value of Content-Length for partial content.
  if (handling_206_ && partial_) {
    partial_->FixContentLength(new_response_->headers.get());
  }

  SetResponse(*new_response_);

  if (method_ == "HEAD") {
    // This response is replacing the cached one.
    DoneWithEntry(false);
    new_response_ = nullptr;
    TransitionToState(STATE_FINISH_HEADERS);
    return OK;
  }

  if (handling_206_ && !CanResume(false)) {
    // There is no point in storing this resource because it will never be used.
    // This may change if we support LOAD_ONLY_FROM_CACHE with sparse entries.
    DoneWithEntry(false);
    if (partial_) {
      partial_->FixResponseHeaders(response_.headers.get(), true);
    }
    TransitionToState(STATE_PARTIAL_HEADERS_RECEIVED);
    return OK;
  }
  // Mark the response with browser_run_id before it gets written.
  if (initial_request_->browser_run_id.has_value()) {
    response_.browser_run_id = initial_request_->browser_run_id;
  }

  TransitionToState(STATE_CACHE_WRITE_RESPONSE);
  return OK;
}

int HttpCache::Transaction::DoCacheWriteResponse() {
  TRACE_EVENT_INSTANT("net", "HttpCacheTransaction::DoCacheWriteResponse",
                      perfetto::Track(trace_id_));
  DCHECK(response_.headers);
  // Invalidate any current entry with a successful response if this transaction
  // cannot write to this entry. This transaction then continues to read from
  // the network without writing to the backend.
  bool is_match = response_.headers->response_code() == HTTP_NOT_MODIFIED;
  if (entry_ && !entry_->CanTransactionWriteResponseHeaders(
                    this, partial_ != nullptr, is_match)) {
    done_headers_create_new_entry_ = true;

    // The transaction needs to overwrite this response. Doom the current entry,
    // create a new one (by going to STATE_INIT_ENTRY), and then jump straight
    // to writing out the response, bypassing the headers checks. The mode_ is
    // set to WRITE in order to doom any other existing entries that might exist
    // so that this transaction can go straight to writing a response.
    mode_ = WRITE;
    TransitionToState(STATE_INIT_ENTRY);
    cache_->DoomEntryValidationNoMatch(std::move(entry_));
    entry_.reset();
    return OK;
  }

  TransitionToState(STATE_CACHE_WRITE_RESPONSE_COMPLETE);
  return WriteResponseInfoToEntry(response_, truncated_);
}

int HttpCache::Transaction::DoCacheWriteResponseComplete(int result) {
  TRACE_EVENT_INSTANT("net",
                      "HttpCacheTransaction::DoCacheWriteResponseComplete",
                      perfetto::Track(trace_id_), "result", result);
  TransitionToState(STATE_TRUNCATE_CACHED_DATA);
  return OnWriteResponseInfoToEntryComplete(result);
}

int HttpCache::Transaction::DoTruncateCachedData() {
  TRACE_EVENT_INSTANT("net", "HttpCacheTransaction::DoTruncateCachedData",
                      perfetto::Track(trace_id_));
  TransitionToState(STATE_TRUNCATE_CACHED_DATA_COMPLETE);
  if (!entry_) {
    return OK;
  }
  net_log_.BeginEvent(NetLogEventType::HTTP_CACHE_WRITE_DATA);
  BeginDiskCacheAccessTimeCount();
  // Truncate the stream.
  return entry_->GetEntry()->WriteData(kResponseContentIndex, /*offset=*/0,
                                       /*buf=*/nullptr, /*buf_len=*/0,
                                       io_callback_, /*truncate=*/true);
}

int HttpCache::Transaction::DoTruncateCachedDataComplete(int result) {
  TRACE_EVENT_INSTANT("net",
                      "HttpCacheTransaction::DoTruncateCachedDataComplete",
                      perfetto::Track(trace_id_), "result", result);
  EndDiskCacheAccessTimeCount(DiskCacheAccessType::kWrite);
  if (entry_) {
    net_log_.EndEventWithNetErrorCode(NetLogEventType::HTTP_CACHE_WRITE_DATA,
                                      result);
  }

  TransitionToState(STATE_PARTIAL_HEADERS_RECEIVED);
  return OK;
}

int HttpCache::Transaction::DoPartialHeadersReceived() {
  TRACE_EVENT_INSTANT("net", "HttpCacheTransaction::DoPartialHeadersReceived",
                      perfetto::Track(trace_id_));
  new_response_ = nullptr;

  if (partial_ && mode_ != NONE && !reading_) {
    // We are about to return the headers for a byte-range request to the user,
    // so let's fix them.
    partial_->FixResponseHeaders(response_.headers.get(), true);
  }
  TransitionToState(STATE_FINISH_HEADERS);
  return OK;
}

int HttpCache::Transaction::DoHeadersPhaseCannotProceed(int result) {
  // If its the Start state machine and it cannot proceed due to a cache
  // failure, restart this transaction.
  DCHECK(!reading_);

  // Reset before invoking SetRequest() which can reset the request info sent to
  // network transaction.
  if (network_trans_) {
    network_trans_.reset();
  }

  new_response_ = nullptr;

  SetRequest(net_log_);

  entry_.reset();
  new_entry_.reset();
  last_disk_cache_access_start_time_ = TimeTicks();

  // TODO(crbug.com/40772202): This should probably clear `response_`,
  // too, once things are fixed so it's safe to do so.

  // Bypass the cache for timeout scenario.
  if (result == ERR_CACHE_LOCK_TIMEOUT) {
    effective_load_flags_ |= LOAD_DISABLE_CACHE;
  }

  TransitionToState(STATE_GET_BACKEND);
  return OK;
}

int HttpCache::Transaction::DoFinishHeaders(int result) {
  TRACE_EVENT_INSTANT("net", "HttpCacheTransaction::DoFinishHeaders",
                      perfetto::Track(trace_id_), "result", result);
  if (!cache_.get() || !entry_ || result != OK) {
    TransitionToState(STATE_NONE);
    return result;
  }

  TransitionToState(STATE_FINISH_HEADERS_COMPLETE);

  // If it was an auth failure, this transaction should continue to be
  // headers_transaction till consumer takes an action, so no need to do
  // anything now.
  // TODO(crbug.com/40529460). See the issue for a suggestion for cleaning the
  // state machine to be able to remove this condition.
  if (auth_response_.headers.get()) {
    return OK;
  }

  // If the transaction needs to wait because another transaction is still
  // writing the response body, it will return ERR_IO_PENDING now and the
  // cache_io_callback_ will be invoked when the wait is done.
  int rv = cache_->DoneWithResponseHeaders(entry_, this, partial_ != nullptr);
  DCHECK(!reading_ || rv == OK) << "Expected OK, but got " << rv;

  if (rv == ERR_IO_PENDING) {
    DCHECK(entry_lock_waiting_since_.is_null());
    entry_lock_waiting_since_ = TimeTicks::Now();
    AddCacheLockTimeoutHandler(entry_.get());
  }
  return rv;
}

int HttpCache::Transaction::DoFinishHeadersComplete(int rv) {
  TRACE_EVENT_INSTANT("net", "HttpCacheTransaction::DoFinishHeadersComplete",
                      perfetto::Track(trace_id_), "result", rv);
  entry_lock_waiting_since_ = TimeTicks();
  if (rv == ERR_CACHE_RACE || rv == ERR_CACHE_LOCK_TIMEOUT) {
    TransitionToState(STATE_HEADERS_PHASE_CANNOT_PROCEED);
    return rv;
  }

  if (network_trans_ && InWriters()) {
    entry_->writers()->SetNetworkTransaction(this, std::move(network_trans_));
    moved_network_transaction_to_writers_ = true;
  }

  // If already reading, that means it is a partial request coming back to the
  // headers phase, continue to the appropriate reading state.
  if (reading_) {
    int reading_state_rv = TransitionToReadingState();
    DCHECK_EQ(OK, reading_state_rv);
    return OK;
  }

  TransitionToState(STATE_NONE);
  return rv;
}

int HttpCache::Transaction::DoNetworkReadCacheWrite() {
  TRACE_EVENT_INSTANT("net", "HttpCacheTransaction::DoNetworkReadCacheWrite",
                      perfetto::Track(trace_id_), "read_offset", read_offset_,
                      "read_buf_len", read_buf_len_);
  DCHECK(InWriters());
  TransitionToState(STATE_NETWORK_READ_CACHE_WRITE_COMPLETE);
  return entry_->writers()->Read(read_buf_, read_buf_len_, io_callback_, this);
}

int HttpCache::Transaction::DoNetworkReadCacheWriteComplete(int result) {
  TRACE_EVENT_INSTANT("net",
                      "HttpCacheTransaction::DoNetworkReadCacheWriteComplete",
                      perfetto::Track(trace_id_), "result", result);
  if (!cache_.get()) {
    TransitionToState(STATE_NONE);
    return ERR_UNEXPECTED;
  }
  // |result| will be error code in case of network read failure and |this|
  // cannot proceed further, so set entry_ to null. |result| will not be error
  // in case of cache write failure since |this| can continue to read from the
  // network. If response is completed, then also set entry to null.
  if (result < 0) {
    // We should have discovered this error in WriterAboutToBeRemovedFromEntry
    DCHECK_EQ(result, shared_writing_error_);
    DCHECK_EQ(NONE, mode_);
    DCHECK(!entry_);
    TransitionToState(STATE_NONE);
    return result;
  }

  if (partial_) {
    return DoPartialNetworkReadCompleted(result);
  }

  if (result == 0) {
    DCHECK_EQ(NONE, mode_);
    DCHECK(!entry_);
  } else {
    read_offset_ += result;
  }
  TransitionToState(STATE_NONE);
  return result;
}

int HttpCache::Transaction::DoPartialNetworkReadCompleted(int result) {
  DCHECK(partial_);

  // Go to the next range if nothing returned or return the result.
  // TODO(shivanisha) Simplify this condition if possible. It was introduced
  // in https://codereview.chromium.org/545101
  if (result != 0 || truncated_ ||
      !(partial_->IsLastRange() || mode_ == WRITE)) {
    partial_->OnNetworkReadCompleted(result);

    if (result == 0) {
      // We need to move on to the next range.
      if (network_trans_) {
        ResetNetworkTransaction();
      } else if (InWriters() && entry_->writers()->network_transaction()) {
        SaveNetworkTransactionInfo(*(entry_->writers()->network_transaction()));
        entry_->writers()->ResetNetworkTransaction();
      }
      TransitionToState(STATE_START_PARTIAL_CACHE_VALIDATION);
    } else {
      TransitionToState(STATE_NONE);
    }
    return result;
  }

  // Request completed.
  if (result == 0) {
    DoneWithEntry(true);
  }

  TransitionToState(STATE_NONE);
  return result;
}

int HttpCache::Transaction::DoNetworkRead() {
  TRACE_EVENT_INSTANT("net", "HttpCacheTransaction::DoNetworkRead",
                      perfetto::Track(trace_id_), "read_offset", read_offset_,
                      "read_buf_len", read_buf_len_);
  TransitionToState(STATE_NETWORK_READ_COMPLETE);
  return network_trans_->Read(read_buf_.get(), read_buf_len_, io_callback_);
}

int HttpCache::Transaction::DoNetworkReadComplete(int result) {
  TRACE_EVENT_INSTANT("net", "HttpCacheTransaction::DoNetworkReadComplete",
                      perfetto::Track(trace_id_), "result", result);

  if (!cache_.get()) {
    TransitionToState(STATE_NONE);
    return ERR_UNEXPECTED;
  }

  if (partial_) {
    return DoPartialNetworkReadCompleted(result);
  }

  TransitionToState(STATE_NONE);
  return result;
}

int HttpCache::Transaction::DoCacheReadData() {
  if (entry_) {
    DCHECK(InWriters() || entry_->TransactionInReaders(this));
  }

  TRACE_EVENT_INSTANT("net", "HttpCacheTransaction::DoCacheReadData",
                      perfetto::Track(trace_id_), "read_offset", read_offset_,
                      "read_buf_len", read_buf_len_);

  if (method_ == "HEAD") {
    TransitionToState(STATE_NONE);
    return 0;
  }

  DCHECK(entry_);
  TransitionToState(STATE_CACHE_READ_DATA_COMPLETE);

  net_log_.BeginEvent(NetLogEventType::HTTP_CACHE_READ_DATA);
  if (partial_) {
    return partial_->CacheRead(entry_->GetEntry(), read_buf_.get(),
                               read_buf_len_, io_callback_);
  }

  BeginDiskCacheAccessTimeCount();
  return entry_->GetEntry()->ReadData(kResponseContentIndex, read_offset_,
                                      read_buf_.get(), read_buf_len_,
                                      io_callback_);
}

int HttpCache::Transaction::DoCacheReadDataComplete(int result) {
  EndDiskCacheAccessTimeCount(DiskCacheAccessType::kRead);
  if (entry_) {
    DCHECK(InWriters() || entry_->TransactionInReaders(this));
  }

  TRACE_EVENT_INSTANT("net", "HttpCacheTransaction::DoCacheReadDataComplete",
                      perfetto::Track(trace_id_), "result", result);
  net_log_.EndEventWithNetErrorCode(NetLogEventType::HTTP_CACHE_READ_DATA,
                                    result);

  if (!cache_.get()) {
    TransitionToState(STATE_NONE);
    return ERR_UNEXPECTED;
  }

  if (partial_) {
    // Partial requests are confusing to report in histograms because they may
    // have multiple underlying requests.
    UpdateCacheEntryStatus(CacheEntryStatus::ENTRY_OTHER);
    return DoPartialCacheReadCompleted(result);
  }

  if (result > 0) {
    read_offset_ += result;
  } else if (result == 0) {  // End of file.
    DoneWithEntry(true);
  } else {
    return OnCacheReadError(result, false);
  }

  TransitionToState(STATE_NONE);
  return result;
}

//-----------------------------------------------------------------------------

void HttpCache::Transaction::SetRequest(const NetLogWithSource& net_log) {
  net_log_ = net_log;

  // Reset the variables that might get set in this function. This is done
  // because this function can be invoked multiple times for a transaction.
  cache_entry_status_ = CacheEntryStatus::ENTRY_UNDEFINED;
  external_validation_.Reset();
  range_requested_ = false;
  partial_.reset();

  request_ = initial_request_;
  custom_request_.reset();

  effective_load_flags_ = request_->load_flags;
  method_ = request_->method;

  if (cache_->mode() == DISABLE) {
    effective_load_flags_ |= LOAD_DISABLE_CACHE;
  }

  // Some headers imply load flags.  The order here is significant.
  //
  //   LOAD_DISABLE_CACHE   : no cache read or write
  //   LOAD_BYPASS_CACHE    : no cache read
  //   LOAD_VALIDATE_CACHE  : no cache read unless validation
  //
  // The former modes trump latter modes, so if we find a matching header we
  // can stop iterating kSpecialHeaders.
  static const struct {
    // RAW_PTR_EXCLUSION: Never allocated by PartitionAlloc (always points to
    // constexpr tables), so there is no benefit to using a raw_ptr, only cost.
    RAW_PTR_EXCLUSION const HeaderNameAndValue* search;
    int load_flag;
  } kSpecialHeaders[] = {
      {kPassThroughHeaders, LOAD_DISABLE_CACHE},
      {kForceFetchHeaders, LOAD_BYPASS_CACHE},
      {kForceValidateHeaders, LOAD_VALIDATE_CACHE},
  };

  bool range_found = false;
  bool external_validation_error = false;
  bool special_headers = false;

  if (request_->extra_headers.HasHeader(HttpRequestHeaders::kRange)) {
    range_found = true;
  }

  for (const auto& special_header : kSpecialHeaders) {
    if (HeaderMatches(request_->extra_headers, special_header.search)) {
      effective_load_flags_ |= special_header.load_flag;
      special_headers = true;
      break;
    }
  }

  // Check for conditionalization headers which may correspond with a
  // cache validation request.
  for (size_t i = 0; i < std::size(kValidationHeaders); ++i) {
    const ValidationHeaderInfo& info = kValidationHeaders[i];
    if (std::optional<std::string> validation_value =
            request_->extra_headers.GetHeader(info.request_header_name);
        validation_value) {
      if (!external_validation_.values[i].empty() ||
          validation_value->empty()) {
        external_validation_error = true;
      }
      external_validation_.values[i] = std::move(validation_value).value();
      external_validation_.initialized = true;
    }
  }

  if (range_found || special_headers || external_validation_.initialized) {
    // Log the headers before request_ is modified.
    std::string empty;
    NetLogRequestHeaders(net_log_,
                         NetLogEventType::HTTP_CACHE_CALLER_REQUEST_HEADERS,
                         empty, &request_->extra_headers);
  }

  // We don't support ranges and validation headers.
  if (range_found && external_validation_.initialized) {
    LOG(WARNING) << "Byte ranges AND validation headers found.";
    effective_load_flags_ |= LOAD_DISABLE_CACHE;
  }

  // If there is more than one validation header, we can't treat this request as
  // a cache validation, since we don't know for sure which header the server
  // will give us a response for (and they could be contradictory).
  if (external_validation_error) {
    LOG(WARNING) << "Multiple or malformed validation headers found.";
    effective_load_flags_ |= LOAD_DISABLE_CACHE;
  }

  if (range_found && !(effective_load_flags_ & LOAD_DISABLE_CACHE)) {
    UpdateCacheEntryStatus(CacheEntryStatus::ENTRY_OTHER);
    partial_ = std::make_unique<PartialData>();
    if (method_ == "GET" && partial_->Init(request_->extra_headers)) {
      // We will be modifying the actual range requested to the server, so
      // let's remove the header here.
      // Note that custom_request_ is a shallow copy so will keep the same
      // pointer to upload data stream as in the original request.
      custom_request_ = std::make_unique<HttpRequestInfo>(*request_);
      custom_request_->extra_headers.RemoveHeader(HttpRequestHeaders::kRange);
      request_ = custom_request_.get();
      partial_->SetHeaders(custom_request_->extra_headers);
    } else {
      // The range is invalid or we cannot handle it properly.
      VLOG(1) << "Invalid byte range found.";
      effective_load_flags_ |= LOAD_DISABLE_CACHE;
      partial_.reset(nullptr);
    }
  }
}

bool HttpCache::Transaction::ShouldPassThrough() {
  bool cacheable = true;

  // We may have a null disk_cache if there is an error we cannot recover from,
  // like not enough disk space, or sharing violations.
  if (!cache_->disk_cache_.get()) {
    cacheable = false;
  } else if (effective_load_flags_ & LOAD_DISABLE_CACHE) {
    cacheable = false;
  } else if (method_ == "GET" || method_ == "HEAD") {
  } else if (method_ == "POST" && request_->upload_data_stream &&
             request_->upload_data_stream->identifier()) {
  } else if (method_ == "PUT" && request_->upload_data_stream) {
  }
  // DELETE and PATCH requests may result in invalidating the cache, so cannot
  // just pass through.
  else if (method_ == "DELETE" || method_ == "PATCH") {
  } else {
    cacheable = false;
  }

  return !cacheable;
}

int HttpCache::Transaction::BeginCacheRead() {
  // We don't support any combination of LOAD_ONLY_FROM_CACHE and byte ranges.
  // It's possible to trigger this from JavaScript using the Fetch API with
  // `cache: 'only-if-cached'` so ideally we should support it.
  // TODO(ricea): Correctly read from the cache in this case.
  if (response_.headers->response_code() == HTTP_PARTIAL_CONTENT || partial_) {
    TransitionToState(STATE_FINISH_HEADERS);
    return ERR_CACHE_MISS;
  }

  // We don't have the whole resource.
  if (truncated_) {
    TransitionToState(STATE_FINISH_HEADERS);
    return ERR_CACHE_MISS;
  }

  if (RequiresValidation() != VALIDATION_NONE) {
    TransitionToState(STATE_FINISH_HEADERS);
    return ERR_CACHE_MISS;
  }

  if (method_ == "HEAD") {
    FixHeadersForHead();
  }

  TransitionToState(STATE_FINISH_HEADERS);
  return OK;
}

int HttpCache::Transaction::BeginCacheValidation() {
  DCHECK_EQ(mode_, READ_WRITE);

  ValidationType required_validation = RequiresValidation();

  bool skip_validation = (required_validation == VALIDATION_NONE);
  bool needs_stale_while_revalidate_cache_update = false;

  if ((effective_load_flags_ & LOAD_SUPPORT_ASYNC_REVALIDATION) &&
      required_validation == VALIDATION_ASYNCHRONOUS) {
    DCHECK_EQ(request_->method, "GET");
    skip_validation = true;
    response_.async_revalidation_requested = true;
    needs_stale_while_revalidate_cache_update =
        response_.stale_revalidate_timeout.is_null();
  }

  if (method_ == "HEAD" && (truncated_ || response_.headers->response_code() ==
                                              HTTP_PARTIAL_CONTENT)) {
    DCHECK(!partial_);
    if (skip_validation) {
      DCHECK(!reading_);
      TransitionToState(STATE_CONNECTED_CALLBACK);
      return OK;
    }

    // Bail out!
    TransitionToState(STATE_SEND_REQUEST);
    mode_ = NONE;
    return OK;
  }

  if (truncated_) {
    // Truncated entries can cause partial gets, so we shouldn't record this
    // load in histograms.
    UpdateCacheEntryStatus(CacheEntryStatus::ENTRY_OTHER);
    skip_validation = !partial_->initial_validation();
  }

  // If this is the first request (!reading_) of a 206 entry (is_sparse_) that
  // doesn't actually cover the entire file (which with !reading would require
  // partial->IsLastRange()), and the user is requesting the whole thing
  // (!partial_->range_requested()), make sure to validate the first chunk,
  // since afterwards it will be too late if it's actually out-of-date (or the
  // server bungles invalidation). This is limited to the whole-file request
  // as a targeted fix for https://crbug.com/888742 while avoiding extra
  // requests in other cases, but the problem can occur more generally as well;
  // it's just a lot less likely with applications actively using ranges.
  // See https://crbug.com/902724 for the more general case.
  bool first_read_of_full_from_partial =
      is_sparse_ && !reading_ &&
      (partial
"""


```