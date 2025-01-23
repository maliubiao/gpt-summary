Response:
The user wants to understand the functionality of the `QuicChromiumClientSession::OnNetworkDisconnectedV2`, `QuicChromiumClientSession::OnNetworkMadeDefault`, `QuicChromiumClientSession::MigrateNetworkImmediately`, `QuicChromiumClientSession::FinishMigrateNetworkImmediately`, `QuicChromiumClientSession::OnWriteError`, `QuicChromiumClientSession::OnWriteUnblocked`, `QuicChromiumClientSession::OnPathDegrading`, `QuicChromiumClientSession::OnForwardProgressMadeAfterPathDegrading`, `QuicChromiumClientSession::OnKeyUpdate`, `QuicChromiumClientSession::OnProofValid`, `QuicChromiumClientSession::OnProofVerifyDetailsAvailable`, `QuicChromiumClientSession::StartReading`, `QuicChromiumClientSession::CloseSessionOnError`, `QuicChromiumClientSession::CloseSessionOnErrorLater`, `QuicChromiumClientSession::NotifyAllStreamsOfError`, `QuicChromiumClientSession::CloseAllHandles`, `QuicChromiumClientSession::CancelAllRequests`, `QuicChromiumClientSession::NotifyRequestsOfConfirmation`, `QuicChromiumClientSession::MaybeMigrateToDifferentPortOnPathDegrading`, `QuicChromiumClientSession::MaybeMigrateToAlternateNetworkOnPathDegrading`, `QuicChromiumClientSession::MaybeStartProbing`, `QuicChromiumClientSession::CreateContextForMultiPortPath`, `QuicChromiumClientSession::FinishCreateContextForMultiPortPath`, `QuicChromiumClientSession::MigrateToMultiPortPath`, `QuicChromiumClientSession::StartProbing`, `QuicChromiumClientSession::FinishStartProbing`, `QuicChromiumClientSession::StartMigrateBackToDefaultNetworkTimer`, `QuicChromiumClientSession::CancelMigrateBackToDefaultNetworkTimer`, `QuicChromiumClientSession::TryMigrateBackToDefaultNetwork`, `QuicChromiumClientSession::FinishTryMigrateBackToDefaultNetwork`, `QuicChromiumClientSession::MaybeRetryMigrateBackToDefaultNetwork`, `QuicChromiumClientSession::CheckIdleTimeExceedsIdleMigrationPeriod`, `QuicChromiumClientSession::ResetNonMigratableStreams`, `QuicChromiumClientSession::LogMetricsOnNetworkDisconnected`, and `QuicChromiumClientSession::LogMetricsOnNetworkMadeDefault` methods in the provided C++ code snippet from `net/quic/quic_chromium_client_session.cc`.

For each method, I need to:
1. Describe its functionality.
2. Explain its relationship with JavaScript, if any, and provide examples.
3. Offer examples of logical reasoning with input and output.
4. Highlight common user or programming errors.
5. Explain how a user's actions might lead to the execution of this code for debugging purposes.
6. Provide a summary of the functionality covered in this part of the code.

**Method-by-Method Analysis:**

*   **`OnNetworkDisconnectedV2`**: Handles network disconnection events, potentially triggering connection migration.
*   **`OnNetworkMadeDefault`**: Handles events where a network becomes the default, potentially triggering migration back to the default network.
*   **`MigrateNetworkImmediately`**: Initiates immediate connection migration to a specified network.
*   **`FinishMigrateNetworkImmediately`**:  Handles the result of an immediate network migration.
*   **`OnWriteError`**: Handles write errors on the connection.
*   **`OnWriteUnblocked`**: Handles the event when the connection is no longer blocked for writing.
*   **`OnPathDegrading`**: Handles events indicating network path degradation, potentially triggering migration.
*   **`OnForwardProgressMadeAfterPathDegrading`**: Notifies observers that forward progress has been made after path degradation.
*   **`OnKeyUpdate`**: Handles QUIC key update events.
*   **`OnProofValid`**: Handles events where the server's proof is valid.
*   **`OnProofVerifyDetailsAvailable`**: Handles the availability of proof verification details.
*   **`StartReading`**: Starts reading data from the underlying sockets.
*   **`CloseSessionOnError`**: Closes the session immediately due to an error.
*   **`CloseSessionOnErrorLater`**: Closes the session later due to an error.
*   **`NotifyAllStreamsOfError`**: Notifies all active streams of an error.
*   **`CloseAllHandles`**: Closes all associated handles for the session.
*   **`CancelAllRequests`**: Cancels all pending stream requests.
*   **`NotifyRequestsOfConfirmation`**: Notifies waiting requests that the session is confirmed.
*   **`MaybeMigrateToDifferentPortOnPathDegrading`**: Attempts to migrate to a different port on the same network during path degradation.
*   **`MaybeMigrateToAlternateNetworkOnPathDegrading`**: Attempts to migrate to an alternate network during path degradation.
*   **`MaybeStartProbing`**:  Conditionally initiates path probing on a different network.
*   **`CreateContextForMultiPortPath`**: Creates the necessary context for multi-port QUIC connections.
*   **`FinishCreateContextForMultiPortPath`**: Completes the setup for multi-port QUIC connections.
*   **`MigrateToMultiPortPath`**: Initiates migration to a multi-port path.
*   **`StartProbing`**: Starts probing a specific network path.
*   **`FinishStartProbing`**: Completes the process of starting network path probing.
*   **`StartMigrateBackToDefaultNetworkTimer`**: Starts a timer to trigger migration back to the default network.
*   **`CancelMigrateBackToDefaultNetworkTimer`**: Cancels the timer for migrating back to the default network.
*   **`TryMigrateBackToDefaultNetwork`**: Attempts to migrate back to the default network.
*   **`FinishTryMigrateBackToDefaultNetwork`**: Handles the result of attempting to migrate back to the default network.
*   **`MaybeRetryMigrateBackToDefaultNetwork`**:  Potentially retries migrating back to the default network.
*   **`CheckIdleTimeExceedsIdleMigrationPeriod`**: Checks if the session has been idle for too long and should be closed.
*   **`ResetNonMigratableStreams`**: Resets streams that cannot be migrated to certain networks.
*   **`LogMetricsOnNetworkDisconnected`**: Logs metrics when a network is disconnected.
*   **`LogMetricsOnNetworkMadeDefault`**: Logs metrics when a network becomes the default.
这是 `net/quic/quic_chromium_client_session.cc` 源代码文件的第 4 部分，主要负责处理网络连接状态变化、连接迁移、错误处理、以及与底层 socket 的交互。以下是该部分代码功能的详细解释：

**功能归纳:**

本部分代码主要负责 **QUIC 客户端会话的生命周期管理和连接迁移策略**。它监听网络状态变化（断开连接、成为默认网络），并在合适的时机触发连接迁移。同时，它也处理连接过程中出现的错误，并管理底层的 socket 连接。  核心目标是保持连接的稳定性和可靠性，即使在网络环境发生变化的情况下。

**各方法功能详解:**

*   **`void QuicChromiumClientSession::OnNetworkDisconnectedV2(handles::NetworkHandle disconnected_network)`**
    *   **功能:**  当底层网络连接断开时被调用。它检查是否启用了网络变化时的会话迁移，如果启用，则尝试迁移到其他可用网络。
    *   **与 Javascript 的关系:** 间接相关。JavaScript 发起的网络请求最终会使用到这个连接。网络断开可能导致 JavaScript 请求失败。例如，一个 XMLHttpRequest 请求可能因为连接断开而触发 `onerror` 事件。
    *   **逻辑推理:**
        *   **假设输入:**  `disconnected_network` 是当前连接正在使用的网络句柄。
        *   **预期输出:** 如果找到可用的替代网络，会启动迁移到该网络的操作。如果找不到，会关闭连接（如果握手未完成）。
    *   **用户/编程常见错误:**
        *   用户错误：在网络不稳定的环境下使用应用，导致频繁的网络断开。
        *   编程错误：服务端或客户端配置错误，导致连接在网络切换时无法正常迁移。
    *   **用户操作到达此处的步骤 (调试线索):**
        1. 用户正在使用一个依赖网络的应用（例如，浏览网页、使用在线应用）。
        2. 用户的设备从一个 Wi-Fi 网络切换到另一个 Wi-Fi 网络，或者从 Wi-Fi 切换到移动数据网络，或者移动数据网络信号丢失。
        3. 底层网络库检测到网络断开事件。
        4. Chromium 网络栈将此事件传递给 `QuicChromiumClientSession::OnNetworkDisconnectedV2`。

*   **`void QuicChromiumClientSession::OnNetworkMadeDefault(handles::NetworkHandle new_network)`**
    *   **功能:** 当一个网络被操作系统设置为默认网络时被调用。它会尝试迁移回该默认网络，以确保连接使用最佳的网络。
    *   **与 Javascript 的关系:** 间接相关。当网络恢复或切换到更稳定的网络时，可以提高 JavaScript 发起的网络请求的成功率和速度。
    *   **逻辑推理:**
        *   **假设输入:** `new_network` 是新成为默认网络的网络句柄。
        *   **预期输出:** 如果当前连接不在该默认网络上，则会启动迁移回默认网络的流程。
    *   **用户/编程常见错误:**
        *   用户错误：手动更改设备的默认网络设置。
        *   编程错误：某些网络配置可能导致频繁的默认网络切换，触发不必要的迁移。
    *   **用户操作到达此处的步骤 (调试线索):**
        1. 用户正在使用一个依赖网络的应用。
        2. 用户的设备连接到一个新的 Wi-Fi 网络，并且该网络被操作系统设置为默认网络。
        3. 操作系统通知 Chromium 网络栈新的默认网络。
        4. Chromium 网络栈将此事件传递给 `QuicChromiumClientSession::OnNetworkMadeDefault`。

*   **`void QuicChromiumClientSession::MigrateNetworkImmediately(handles::NetworkHandle network)`**
    *   **功能:** 立即将 QUIC 连接迁移到指定的网络。这通常发生在网络断开或路径质量下降的情况下。
    *   **与 Javascript 的关系:** 间接相关。迁移成功可以避免因网络问题导致的 JavaScript 请求失败。
    *   **逻辑推理:**
        *   **假设输入:** `network` 是要迁移到的目标网络句柄。
        *   **预期输出:** 启动到目标网络的迁移过程。如果迁移失败，可能会关闭连接。
    *   **用户/编程常见错误:**
        *   编程错误：在不应该迁移的情况下调用此方法，例如，迁移配置不当。
    *   **用户操作到达此处的步骤 (调试线索):**
        1. 前面的 `OnNetworkDisconnectedV2` 方法判断需要立即迁移。
        2. 前面的 `OnPathDegrading` 方法判断需要立即迁移。
        3. 其他内部逻辑判断需要立即迁移到特定网络。

*   **`void QuicChromiumClientSession::FinishMigrateNetworkImmediately(handles::NetworkHandle network, MigrationResult result)`**
    *   **功能:**  在 `MigrateNetworkImmediately` 调用完成后被调用，处理迁移的结果（成功或失败）。
    *   **与 Javascript 的关系:** 间接相关。迁移结果会影响后续 JavaScript 发起的网络请求是否能够成功。
    *   **逻辑推理:**
        *   **假设输入:** `network` 是尝试迁移到的网络句柄，`result` 是迁移的结果（成功或失败）。
        *   **预期输出:** 如果迁移成功，并且当前不在默认网络，则启动定时器尝试迁移回默认网络。
    *   **用户/编程常见错误:**
        *   编程错误：在迁移失败的情况下，没有正确处理错误状态。

*   **`void QuicChromiumClientSession::OnWriteError(int error_code)`**
    *   **功能:** 当向底层 socket 写入数据时发生错误时被调用。它将错误传递给 QUIC 连接层进行处理。
    *   **与 Javascript 的关系:** 间接相关。写入错误可能导致 JavaScript 发起的网络请求失败。
    *   **逻辑推理:**
        *   **假设输入:** `error_code` 是写入操作返回的错误码。
        *   **预期输出:** QUIC 连接层会根据错误码采取相应的措施，例如重传数据或关闭连接。
    *   **用户/编程常见错误:**
        *   用户错误：网络连接不稳定，导致写入错误。
        *   编程错误：底层 socket 实现存在 bug，导致写入错误。
    *   **用户操作到达此处的步骤 (调试线索):**
        1. JavaScript 发起一个网络请求。
        2. Chromium 网络栈尝试通过 QUIC 连接发送数据。
        3. 底层 socket 的写入操作返回错误。
        4. Chromium 网络栈将此错误传递给 `QuicChromiumClientSession::OnWriteError`。

*   **`void QuicChromiumClientSession::OnWriteUnblocked()`**
    *   **功能:** 当之前被阻塞的 socket 写入操作变得可用时被调用。它会通知 QUIC 连接层可以继续发送数据。
    *   **与 Javascript 的关系:** 间接相关。写入操作恢复后，可以继续发送 JavaScript 发起的网络请求。
    *   **逻辑推理:**
        *   **预期输出:** QUIC 连接层会尝试发送之前被阻塞的数据包。
    *   **用户操作到达此处的步骤 (调试线索):**
        1. 由于网络拥塞或其他原因，socket 写入被阻塞。
        2. 阻塞状态解除。
        3. Chromium 网络栈接收到 socket 可写的通知。
        4. Chromium 网络栈调用 `QuicChromiumClientSession::OnWriteUnblocked`。

*   **`void QuicChromiumClientSession::OnPathDegrading()`**
    *   **功能:** 当检测到网络路径质量下降时被调用。它会通知观察者，并根据配置尝试迁移到不同的端口或网络。
    *   **与 Javascript 的关系:** 间接相关。路径质量下降可能导致 JavaScript 发起的网络请求延迟或失败。连接迁移可以缓解这个问题。
    *   **逻辑推理:**
        *   **预期输出:** 如果配置允许，可能会触发端口迁移或网络迁移。
    *   **用户操作到达此处的步骤 (调试线索):**
        1. 用户正在使用网络应用，网络连接质量变差（例如，延迟增加，丢包率上升）。
        2. QUIC 连接层的探测机制检测到路径质量下降。
        3. Chromium 网络栈调用 `QuicChromiumClientSession::OnPathDegrading`。

*   **`void QuicChromiumClientSession::OnForwardProgressMadeAfterPathDegrading()`**
    *   **功能:** 当在路径质量下降后，连接又能够正常发送和接收数据时被调用。它通知观察者路径恢复正常。
    *   **与 Javascript 的关系:**  间接相关。表示之前可能受影响的 JavaScript 网络请求可以恢复正常。
    *   **用户操作到达此处的步骤 (调试线索):**
        1. 之前调用了 `OnPathDegrading`。
        2. QUIC 连接层检测到网络路径恢复正常。
        3. Chromium 网络栈调用 `QuicChromiumClientSession::OnForwardProgressMadeAfterPathDegrading`。

*   **`void QuicChromiumClientSession::OnKeyUpdate(quic::KeyUpdateReason reason)`**
    *   **功能:** 当 QUIC 连接进行密钥更新时被调用。
    *   **与 Javascript 的关系:** 无直接关系，这是一个底层的安全协议操作。
    *   **逻辑推理:**
        *   **假设输入:** `reason` 指示密钥更新的原因。
        *   **预期输出:** 记录密钥更新事件和原因。
    *   **用户操作到达此处的步骤 (调试线索):**
        1. QUIC 连接按照协议规定执行密钥更新。
        2. Chromium 网络栈调用 `QuicChromiumClientSession::OnKeyUpdate`。

*   **`void QuicChromiumClientSession::OnProofValid(const quic::QuicCryptoClientConfig::CachedState& cached)`**
    *   **功能:** 当服务器提供的身份验证信息被验证通过时调用。它会将验证通过的信息缓存起来。
    *   **与 Javascript 的关系:** 间接相关。确保连接的安全性，保障用户数据不被窃取。
    *   **逻辑推理:**
        *   **假设输入:** `cached` 包含服务器验证通过的配置信息。
        *   **预期输出:** 将服务器配置等信息保存到本地缓存。
    *   **用户操作到达此处的步骤 (调试线索):**
        1. 客户端首次连接到服务器或之前的缓存信息过期。
        2. 服务器发送身份验证信息。
        3. 客户端验证服务器的身份。
        4. 如果验证成功，Chromium 网络栈调用 `QuicChromiumClientSession::OnProofValid`。

*   **`void QuicChromiumClientSession::OnProofVerifyDetailsAvailable(const quic::ProofVerifyDetails& verify_details)`**
    *   **功能:** 当服务器身份验证的详细信息可用时调用。它会将验证结果存储起来。
    *   **与 Javascript 的关系:** 间接相关。提供了更详细的证书验证信息，可能用于安全策略的判断。
    *   **逻辑推理:**
        *   **假设输入:** `verify_details` 包含证书验证的详细信息。
        *   **预期输出:**  存储证书验证结果。
    *   **用户操作到达此处的步骤 (调试线索):**
        1. 客户端在验证服务器身份的过程中。
        2. 底层的证书验证库提供了验证的详细信息。
        3. Chromium 网络栈调用 `QuicChromiumClientSession::OnProofVerifyDetailsAvailable`。

*   **`void QuicChromiumClientSession::StartReading()`**
    *   **功能:** 启动从底层 socket 读取数据的操作。
    *   **与 Javascript 的关系:** 间接相关。只有读取到数据，才能响应 JavaScript 发起的网络请求。
    *   **预期输出:** 开始监听 socket 上的数据。
    *   **用户操作到达此处的步骤 (调试线索):**
        1. QUIC 会话建立成功后。
        2. 在连接迁移后需要重新开始读取数据。
        3. 其他需要开始接收数据的场景。

*   **`void QuicChromiumClientSession::CloseSessionOnError(int net_error, quic::QuicErrorCode quic_error, quic::ConnectionCloseBehavior behavior)`**
    *   **功能:**  立即关闭 QUIC 会话，并通知所有相关的 stream 和观察者发生了错误。
    *   **与 Javascript 的关系:** 直接相关。会直接导致 JavaScript 发起的网络请求失败，并可能触发 `onerror` 事件。
    *   **逻辑推理:**
        *   **假设输入:** `net_error` 是网络层面的错误码，`quic_error` 是 QUIC 协议层面的错误码，`behavior` 指示关闭行为。
        *   **预期输出:** 关闭底层的 QUIC 连接和 socket，并通知所有相关的组件。
    *   **用户/编程常见错误:**
        *   用户错误：网络环境恶劣，导致连接错误。
        *   编程错误：QUIC 协议实现错误或配置错误，导致连接异常关闭。
    *   **用户操作到达此处的步骤 (调试线索):**
        1. 在连接过程中发生了不可恢复的错误（例如，协议错误、严重的网络错误）。
        2. QUIC 连接层判断需要关闭连接。
        3. Chromium 网络栈调用 `QuicChromiumClientSession::CloseSessionOnError`。

*   **`void QuicChromiumClientSession::CloseSessionOnErrorLater(int net_error, quic::QuicErrorCode quic_error, quic::ConnectionCloseBehavior behavior)`**
    *   **功能:** 延迟关闭 QUIC 会话，并通知所有相关的 stream 和观察者发生了错误。与 `CloseSessionOnError` 的区别在于它是异步的。
    *   **与 Javascript 的关系:** 直接相关，类似于 `CloseSessionOnError`。
    *   **逻辑推理:** 类似 `CloseSessionOnError`。
    *   **用户/编程常见错误:** 类似 `CloseSessionOnError`。
    *   **用户操作到达此处的步骤 (调试线索):**
        1. 在连接过程中发生错误，但可以选择稍后关闭连接（例如，等待某些操作完成）。
        2. QUIC 连接层判断需要延迟关闭连接。
        3. Chromium 网络栈调用 `QuicChromiumClientSession::CloseSessionOnErrorLater`。

*   **`void QuicChromiumClientSession::NotifyAllStreamsOfError(int net_error)`**
    *   **功能:** 通知所有活跃的 QUIC 流会话发生了错误。
    *   **与 Javascript 的关系:** 直接相关。会通知到正在处理的 JavaScript 网络请求，导致请求失败。
    *   **逻辑推理:**
        *   **假设输入:** `net_error` 是发生的网络错误码。
        *   **预期输出:** 所有活跃的 QUIC 流都会收到错误通知。
    *   **用户操作到达此处的步骤 (调试线索):**
        1. `CloseSessionOnError` 或 `CloseSessionOnErrorLater` 被调用。
        2. 作为关闭流程的一部分，需要通知所有 stream。

*   **`void QuicChromiumClientSession::CloseAllHandles(int net_error)`**
    *   **功能:** 关闭所有与当前 QUIC 会话关联的句柄（Handle）。这些句柄可能对应于上层的网络请求。
    *   **与 Javascript 的关系:** 直接相关。关闭句柄意味着上层的网络请求完成（失败）。
    *   **逻辑推理:**
        *   **假设输入:** `net_error` 是导致会话关闭的错误码。
        *   **预期输出:** 所有注册到此会话的句柄都会被通知会话已关闭。
    *   **用户操作到达此处的步骤 (调试线索):**
        1. `CloseSessionOnError` 或 `CloseSessionOnErrorLater` 被调用。
        2. 作为关闭流程的一部分，需要关闭所有相关的句柄。

*   **`void QuicChromiumClientSession::CancelAllRequests(int net_error)`**
    *   **功能:** 取消所有正在等待创建 QUIC 流的请求。
    *   **与 Javascript 的关系:** 直接相关。取消请求意味着 JavaScript 发起的网络请求将不会被执行。
    *   **逻辑推理:**
        *   **假设输入:** `net_error` 是导致请求被取消的错误码。
        *   **预期输出:** 所有等待中的流创建请求都会被标记为失败。
    *   **用户操作到达此处的步骤 (调试线索):**
        1. 在会话创建或连接建立过程中发生错误，导致无法继续创建新的流。
        2. Chromium 网络栈调用 `QuicChromiumClientSession::CancelAllRequests`。

*   **`void QuicChromiumClientSession::NotifyRequestsOfConfirmation(int net_error)`**
    *   **功能:** 通知所有等待会话确认的请求，会话已经确认或发生错误。
    *   **与 Javascript 的关系:** 间接相关。会话确认是建立连接的关键步骤，确认后才能正常处理 JavaScript 的网络请求。
    *   **逻辑推理:**
        *   **假设输入:** `net_error` 指示会话确认的结果（0 表示成功）。
        *   **预期输出:**  所有等待会话确认的回调函数都会被执行。
    *   **用户操作到达此处的步骤 (调试线索):**
        1. 会话握手完成（或失败）。
        2. 需要通知那些在握手完成前就发起的请求。

*   **`void QuicChromiumClientSession::MaybeMigrateToDifferentPortOnPathDegrading()`**
    *   **功能:** 当检测到路径质量下降时，尝试迁移到同一服务器的不同端口。
    *   **与 Javascript 的关系:** 间接相关。作为连接迁移的一种方式，可以提高网络请求的成功率。
    *   **逻辑推理:**
        *   **预期输出:** 如果条件允许，会启动到不同端口的探测过程。
    *   **用户操作到达此处的步骤 (调试线索):**
        1. `OnPathDegrading` 被调用。
        2. 配置允许端口迁移。

*   **`void QuicChromiumClientSession::MaybeMigrateToAlternateNetworkOnPathDegrading()`**
    *   **功能:** 当检测到路径质量下降时，尝试迁移到其他可用的网络（例如，从 Wi-Fi 切换到移动数据）。
    *   **与 Javascript 的关系:** 间接相关。与端口迁移类似，旨在提高网络连接的可靠性。
    *   **逻辑推理:**
        *   **预期输出:** 如果找到可用的替代网络，并且配置允许，会启动到该网络的探测过程。
    *   **用户操作到达此处的步骤 (调试线索):**
        1. `OnPathDegrading` 被调用。
        2. 配置允许网络迁移。

*   **`void QuicChromiumClientSession::MaybeStartProbing(ProbingCallback probing_callback, handles::NetworkHandle network, const quic::QuicSocketAddress& peer_address)`**
    *   **功能:**  有条件地启动对指定网络路径的探测，以验证其连通性，通常在尝试连接迁移时使用。
    *   **与 Javascript 的关系:** 间接相关。探测是连接迁移的前提，成功的迁移可以提高网络请求的成功率。
    *   **逻辑推理:**
        *   **假设输入:** `network` 是要探测的网络句柄，`peer_address` 是服务器地址。
        *   **预期输出:** 如果条件满足（例如，未禁用迁移，存在可迁移的流），则会启动探测过程。
    *   **用户操作到达此处的步骤 (调试线索):**
        1. `MaybeMigrateToDifferentPortOnPathDegrading` 或 `MaybeMigrateToAlternateNetworkOnPathDegrading` 被调用。
        2. 其他需要探测网络连通性的场景。

*   **`void QuicChromiumClientSession::CreateContextForMultiPortPath(std::unique_ptr<quic::MultiPortPathContextObserver> context_observer)`**
    *   **功能:** 为多端口 QUIC 连接创建必要的上下文信息，包括创建新的 socket。
    *   **与 Javascript 的关系:** 间接相关。多端口连接是 QUIC 的高级特性，旨在进一步提高连接的可靠性和性能，最终会影响到 JavaScript 发起的网络请求。
    *   **逻辑推理:**
        *   **预期输出:** 创建一个新的 socket，并配置相关的读写器。
    *   **用户操作到达此处的步骤 (调试线索):**
        1. 客户端和服务端都支持多端口 QUIC。
        2. 客户端决定尝试使用多端口连接。

*   **`void QuicChromiumClientSession::FinishCreateContextForMultiPortPath(std::unique_ptr<quic::MultiPortPathContextObserver> context_observer, std::unique_ptr<DatagramClientSocket> probing_socket, int rv)`**
    *   **功能:** 完成多端口连接上下文的创建，处理 socket 创建的结果。
    *   **与 Javascript 的关系:** 间接相关，是多端口连接建立过程的一部分。
    *   **逻辑推理:**
        *   **假设输入:** `rv` 是 socket 创建的结果。
        *   **预期输出:** 如果 socket 创建成功，则创建读写器并通知观察者。
    *   **用户操作到达此处的步骤 (调试线索):**
        1. `CreateContextForMultiPortPath` 被调用。
        2. 等待 socket 创建完成。

*   **`void QuicChromiumClientSession::MigrateToMultiPortPath(std::unique_ptr<quic::QuicPathValidationContext> context)`**
    *   **功能:**  执行到多端口路径的迁移。
    *   **与 Javascript 的关系:** 间接相关。迁移到多端口路径后，可以利用多个网络接口进行数据传输，提高性能和可靠性。
    *   **逻辑推理:**
        *   **预期输出:** 将连接迁移到新的 socket 上。
    *   **用户操作到达此处的步骤 (调试线索):**
        1. 多端口连接的上下文创建成功。
        2. 客户端决定迁移到多端口路径。

*   **`void QuicChromiumClientSession::StartProbing(ProbingCallback probing_callback, handles::NetworkHandle network, const quic::QuicSocketAddress& peer_address)`**
    *   **功能:**  启动对指定网络路径的探测，以验证其连通性。
    *   **与 Javascript 的关系:** 间接相关，是连接迁移的重要步骤。
    *   **逻辑推理:**
        *   **预期输出:** 创建一个新的 socket 并开始探测。
    *   **用户操作到达此处的步骤 (调试线索):**
        1. 需要验证特定网络路径的连通性。

*   **`void QuicChromiumClientSession::FinishStartProbing(ProbingCallback probing_callback, std::unique_ptr<DatagramClientSocket> probing_socket, handles::NetworkHandle network, const quic::QuicSocketAddress& peer_address, int rv)`**
    *   **功能:** 完成探测的启动过程，处理 socket 创建的结果，并启动路径验证。
    *   **与 Javascript 的关系:** 间接相关，是连接迁移流程的一部分。
    *   **逻辑推理:**
        *   **假设输入:** `rv` 是 socket 创建的结果。
        *   **预期输出:** 如果 socket 创建成功，则启动路径验证流程。
    *   **用户操作到达此处的步骤 (调试线索):**
        1. `StartProbing` 被调用。
        2. 等待 socket 创建完成。

*   **`void QuicChromiumClientSession::StartMigrateBackToDefaultNetworkTimer(base::TimeDelta delay)`**
    *   **功能:** 启动一个定时器，在指定延迟后尝试迁移回默认网络。
    *   **与 Javascript 的关系:** 间接相关。确保连接最终回到最佳网络，提高网络请求的性能。
    *   **逻辑推理:**
        *   **预期输出:** 启动一个定时器，并在到期后尝试迁移回默认网络。
    *   **用户操作到达此处的步骤 (调试线索):**
        1. 连接迁移到非默认网络后。
        2. 操作系统通知有新的默认网络可用。

*   **`void QuicChromiumClientSession::CancelMigrateBackToDefaultNetworkTimer()`**
    *   **功能:** 取消尝试迁移回默认网络的定时器。
    *   **与 Javascript 的关系:** 间接相关。如果连接已经回到默认网络，则不需要继续尝试。
    *   **预期输出:** 停止迁移回默认网络的定时器。
    *   **用户操作到达此处的步骤 (调试线索):**
        1. 在迁移回默认网络的定时器运行期间，连接已经通过其他方式回到默认网络。

*   **`void QuicChromiumClientSession::TryMigrateBackToDefaultNetwork(base::TimeDelta timeout)`**
    *   **功能:**  尝试迁移回默认网络。
    *   **与 Javascript 的关系:** 间接相关。将连接迁移回最佳网络，提高性能。
    *   **逻辑推理:**
        *   **预期输出:** 启动对默认网络的探测。
    *   **用户操作到达此处的步骤 (调试线索):**
        1. 迁移回默认网络的定时器到期。
        2. 其他需要尝试迁移回默认网络的场景。

*   **`void QuicChromiumClientSession::FinishTryMigrateBackToDefaultNetwork(base::TimeDelta timeout, ProbingResult result)`**
    *   **功能:** 处理尝试迁移回默认网络的结果。
    *   **与 Javascript 的关系:** 间接相关。根据迁移结果决定是否继续尝试。
    *   **逻辑推理:**
        *   **假设输入:** `result` 是探测结果。
        *   **预期输出:** 如果探测成功，则迁移回默认网络，否则可能继续尝试。
    *   **用户操作到达此处的步骤 (调试线索):**
        1. `TryMigrateBackToDefaultNetwork` 被调用。
        2. 等待探测结果。

*   **`void QuicChromiumClientSession::MaybeRetryMigrateBackToDefaultNetwork()`**
    *   **功能:**  有条件地重试迁移回默认网络。
    *   **与 Javascript 的关系:** 间接相关。确保最终连接到最佳网络。
    *   **逻辑推理:**
        *   **预期输出:** 如果尚未达到重试上限，则会再次尝试迁移回默认网络。
    *   **用户操作到达此处的步骤 (调试线索):**
        1. 尝试迁移回默认网络失败。
        2. 定时器到期触发重试。

*   **`bool QuicChromiumClientSession::CheckIdleTimeExceedsIdleMigrationPeriod()`**
    *   **功能:** 检查会话是否空闲时间过长，超过了空闲迁移的期限。
    *   **与 Javascript 的关系:** 无直接关系。这是一种优化策略，用于关闭长时间不活动的连接。
    *   **逻辑推理:**
        *   **预期输出:** 如果空闲时间过长，则返回 true，并可能关闭连接。
    *   **用户操作到达此处的步骤 (调试线索):**
        1. 会话建立后，长时间没有数据传输。
        2. 定时检查会话空闲时间。

*   **`void QuicChromiumClientSession::ResetNonMigratableStreams()`**
    *   **功能:** 重置那些不能迁移到特定网络的 QUIC 流。
    *   **与 Javascript 的关系:** 直接相关。会中断 JavaScript 发起的、不能迁移到目标网络的请求。
    *   **逻辑推理:**
        *   **预期输出:** 不能迁移的流会被重置。
    *   **用户操作到达此处的步骤 (调试线索):**
        1. 尝试迁移到不支持某些类型流的网络。

*   **`void QuicChromiumClientSession::LogMetricsOnNetworkDisconnected()`**
    *   **功能:** 当网络断开时记录相关的性能指标。
    *   **与 Javascript 的关系:** 无直接关系。用于性能分析和优化。
    *   **逻辑推理:**
        *   **预期输出:** 记录网络断开时的相关信息。
    *   **用户操作到达此处的步骤 (调试线索):**
        1. `OnNetworkDisconnectedV2` 被调用。

*   **`void QuicChromiumClientSession::LogMetricsOnNetworkMadeDefault()`**
    *   **功能:** 当一个网络成为默认网络时记录相关的性能指标。
    *   **与 Javascript 的关系:** 无直接关系，用于性能分析。
    *   **逻辑推理:**
        *   **预期输出:** 记录网络成为默认网络时的相关信息。
    *   **用户操作到达此处的步骤 (调试线索):**
        1. `OnNetworkMadeDefault` 被调用。

总而言之，这部分代码是 QUIC 客户端会话管理的核心，它确保了连接的稳定性和可靠性，并在网络环境变化时尝试进行智能的迁移，以提供最佳的网络体验。虽然与 JavaScript 没有直接的接口，但它所做的工作直接影响了 JavaScript 发起的网络请求的成功率和性能。

### 提示词
```
这是目录为net/quic/quic_chromium_client_session.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第4部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
iately.
    MigrateNetworkImmediately(network);
  } else {
    // The connection is path degrading.
    DCHECK(connection()->IsPathDegrading());
    MaybeMigrateToAlternateNetworkOnPathDegrading();
  }
}

void QuicChromiumClientSession::OnNetworkDisconnectedV2(
    handles::NetworkHandle disconnected_network) {
  LogMetricsOnNetworkDisconnected();
  net_log_.AddEventWithInt64Params(
      NetLogEventType::QUIC_SESSION_NETWORK_DISCONNECTED,
      "disconnected_network", disconnected_network);
  if (!migrate_session_on_network_change_v2_) {
    return;
  }
  net_log_.AddEventWithInt64Params(
      NetLogEventType::QUIC_CONNECTION_MIGRATION_ON_NETWORK_DISCONNECTED,
      "disconnected_network", disconnected_network);

  // Stop probing the disconnected network if there is one.
  auto* context = static_cast<QuicChromiumPathValidationContext*>(
      connection()->GetPathValidationContext());
  if (context && context->network() == disconnected_network &&
      context->peer_address() == peer_address()) {
    connection()->CancelPathValidation();
  }

  if (disconnected_network == default_network_) {
    DVLOG(1) << "Default network: " << default_network_ << " is disconnected.";
    default_network_ = handles::kInvalidNetworkHandle;
    current_migrations_to_non_default_network_on_write_error_ = 0;
  }

  // Ignore the signal if the current active network is not affected.
  if (GetCurrentNetwork() != disconnected_network) {
    DVLOG(1) << "Client's current default network is not affected by the "
             << "disconnected one.";
    return;
  }

  if (base::FeatureList::IsEnabled(
          features::kQuicMigrationIgnoreDisconnectSignalDuringProbing) &&
      current_migration_cause_ == ON_NETWORK_MADE_DEFAULT) {
    DVLOG(1) << "Ignoring a network disconnection signal because a "
                "connection migration is happening on the default network.";
    return;
  }

  current_migration_cause_ = ON_NETWORK_DISCONNECTED;
  LogHandshakeStatusOnMigrationSignal();
  if (!OneRttKeysAvailable()) {
    // Close the connection if handshake is not confirmed. Migration before
    // handshake is not allowed.
    CloseSessionOnErrorLater(
        ERR_NETWORK_CHANGED,
        quic::QUIC_CONNECTION_MIGRATION_HANDSHAKE_UNCONFIRMED,
        quic::ConnectionCloseBehavior::SILENT_CLOSE);
    return;
  }

  // Attempt to find alternative network.
  handles::NetworkHandle new_network =
      session_pool_->FindAlternateNetwork(disconnected_network);

  if (new_network == handles::kInvalidNetworkHandle) {
    OnNoNewNetwork();
    return;
  }

  // Current network is being disconnected, migrate immediately to the
  // alternative network.
  MigrateNetworkImmediately(new_network);
}

void QuicChromiumClientSession::OnNetworkMadeDefault(
    handles::NetworkHandle new_network) {
  LogMetricsOnNetworkMadeDefault();
  net_log_.AddEventWithInt64Params(
      NetLogEventType::QUIC_SESSION_NETWORK_MADE_DEFAULT, "new_default_network",
      new_network);

  if (!migrate_session_on_network_change_v2_) {
    return;
  }

  DCHECK_NE(handles::kInvalidNetworkHandle, new_network);
  net_log_.AddEventWithInt64Params(
      NetLogEventType::QUIC_CONNECTION_MIGRATION_ON_NETWORK_MADE_DEFAULT,
      "new_default_network", new_network);
  default_network_ = new_network;

  DVLOG(1) << "Network: " << new_network
           << " becomes default, old default: " << default_network_;
  current_migration_cause_ = ON_NETWORK_MADE_DEFAULT;
  current_migrations_to_non_default_network_on_write_error_ = 0;
  current_migrations_to_non_default_network_on_path_degrading_ = 0;

  // Simply cancel the timer to migrate back to the default network if session
  // is already on the default network.
  if (GetCurrentNetwork() == new_network) {
    CancelMigrateBackToDefaultNetworkTimer();
    HistogramAndLogMigrationFailure(MIGRATION_STATUS_ALREADY_MIGRATED,
                                    connection_id(),
                                    "Already migrated on the new network");
    return;
  }

  LogHandshakeStatusOnMigrationSignal();

  // Stay on the current network. Try to migrate back to default network
  // without any delay, which will start probing the new default network and
  // migrate to the new network immediately on success.
  StartMigrateBackToDefaultNetworkTimer(base::TimeDelta());
}

void QuicChromiumClientSession::MigrateNetworkImmediately(
    handles::NetworkHandle network) {
  // There is no choice but to migrate to |network|. If any error encountered,
  // close the session. When migration succeeds:
  // - if no longer on the default network, start timer to migrate back;
  // - otherwise, it's brought to default network, cancel the running timer to
  //   migrate back.

  DCHECK(migrate_session_on_network_change_v2_);

  if (!migrate_idle_session_ && !HasActiveRequestStreams()) {
    HistogramAndLogMigrationFailure(MIGRATION_STATUS_NO_MIGRATABLE_STREAMS,
                                    connection_id(), "No active streams");
    CloseSessionOnErrorLater(
        ERR_NETWORK_CHANGED,
        quic::QUIC_CONNECTION_MIGRATION_NO_MIGRATABLE_STREAMS,
        quic::ConnectionCloseBehavior::SILENT_CLOSE);
    return;
  }

  if (migrate_idle_session_ && CheckIdleTimeExceedsIdleMigrationPeriod()) {
    return;
  }

  // Do not migrate if connection migration is disabled.
  if (config()->DisableConnectionMigration()) {
    HistogramAndLogMigrationFailure(MIGRATION_STATUS_DISABLED_BY_CONFIG,
                                    connection_id(),
                                    "Migration disabled by config");
    CloseSessionOnErrorLater(ERR_NETWORK_CHANGED,
                             quic::QUIC_CONNECTION_MIGRATION_DISABLED_BY_CONFIG,
                             quic::ConnectionCloseBehavior::SILENT_CLOSE);
    return;
  }

  if (network == GetCurrentNetwork()) {
    HistogramAndLogMigrationFailure(MIGRATION_STATUS_ALREADY_MIGRATED,
                                    connection_id(),
                                    "Already bound to new network");
    return;
  }

  // Cancel probing on |network| if there is any.
  auto* context = static_cast<QuicChromiumPathValidationContext*>(
      connection()->GetPathValidationContext());
  if (context && context->network() == network &&
      context->peer_address() == peer_address()) {
    connection()->CancelPathValidation();
  }
  pending_migrate_network_immediately_ = true;
  Migrate(network, ToIPEndPoint(connection()->peer_address()),
          /*close_session_on_error=*/true,
          base::BindOnce(
              &QuicChromiumClientSession::FinishMigrateNetworkImmediately,
              weak_factory_.GetWeakPtr(), network));
}

void QuicChromiumClientSession::FinishMigrateNetworkImmediately(
    handles::NetworkHandle network,
    MigrationResult result) {
  pending_migrate_network_immediately_ = false;
  if (result == MigrationResult::FAILURE) {
    return;
  }

  if (network == default_network_) {
    CancelMigrateBackToDefaultNetworkTimer();
    return;
  }

  // TODO(zhongyi): reconsider this, maybe we just want to hear back
  // We are forced to migrate to |network|, probably |default_network_| is
  // not working, start to migrate back to default network after 1 secs.
  StartMigrateBackToDefaultNetworkTimer(
      base::Seconds(kMinRetryTimeForDefaultNetworkSecs));
}

void QuicChromiumClientSession::OnWriteError(int error_code) {
  DCHECK_NE(ERR_IO_PENDING, error_code);
  DCHECK_GT(0, error_code);
  connection()->OnWriteError(error_code);
}

void QuicChromiumClientSession::OnWriteUnblocked() {
  DCHECK(!connection()->writer()->IsWriteBlocked());

  // A new packet will be written after migration completes, unignore read
  // errors.
  if (ignore_read_error_) {
    ignore_read_error_ = false;
  }

  if (packet_) {
    DCHECK(send_packet_after_migration_);
    send_packet_after_migration_ = false;
    static_cast<QuicChromiumPacketWriter*>(connection()->writer())
        ->WritePacketToSocket(std::move(packet_));
    return;
  }

  // Unblock the connection, which may send queued packets.
  connection()->OnCanWrite();
  if (send_packet_after_migration_) {
    send_packet_after_migration_ = false;
    if (!connection()->writer()->IsWriteBlocked()) {
      connection()->SendPing();
    }
  }
}

void QuicChromiumClientSession::OnPathDegrading() {
  if (most_recent_path_degrading_timestamp_ == base::TimeTicks()) {
    most_recent_path_degrading_timestamp_ = tick_clock_->NowTicks();
  }

  handles::NetworkHandle current_network = GetCurrentNetwork();
  for (auto& observer : connectivity_observer_list_) {
    observer.OnSessionPathDegrading(this, current_network);
  }

  // Proxied sessions should not attempt migration when the path degrades, as
  // there is nowhere for such a session to migrate to. If the degradation is
  // due to degradation of the underlying session, then that session may attempt
  // migration.
  if (!session_key_.proxy_chain().is_direct()) {
    return;
  }

  if (!session_pool_ || connection()->multi_port_stats()) {
    return;
  }

  if (allow_port_migration_ && !migrate_session_early_v2_) {
    MaybeMigrateToDifferentPortOnPathDegrading();
    return;
  }

  MaybeMigrateToAlternateNetworkOnPathDegrading();
}

void QuicChromiumClientSession::OnForwardProgressMadeAfterPathDegrading() {
  handles::NetworkHandle current_network = GetCurrentNetwork();
  for (auto& observer : connectivity_observer_list_) {
    observer.OnSessionResumedPostPathDegrading(this, current_network);
  }
}

void QuicChromiumClientSession::OnKeyUpdate(quic::KeyUpdateReason reason) {
  net_log_.AddEventWithStringParams(NetLogEventType::QUIC_SESSION_KEY_UPDATE,
                                    "reason",
                                    quic::KeyUpdateReasonString(reason));

  base::UmaHistogramEnumeration("Net.QuicSession.KeyUpdate.Reason", reason);

  last_key_update_reason_ = reason;
}

void QuicChromiumClientSession::OnProofValid(
    const quic::QuicCryptoClientConfig::CachedState& cached) {
  DCHECK(cached.proof_valid());

  if (!server_info_) {
    return;
  }

  QuicServerInfo::State* state = server_info_->mutable_state();

  state->server_config = cached.server_config();
  state->source_address_token = cached.source_address_token();
  state->cert_sct = cached.cert_sct();
  state->chlo_hash = cached.chlo_hash();
  state->server_config_sig = cached.signature();
  state->certs = cached.certs();

  server_info_->Persist();
}

void QuicChromiumClientSession::OnProofVerifyDetailsAvailable(
    const quic::ProofVerifyDetails& verify_details) {
  const ProofVerifyDetailsChromium* verify_details_chromium =
      reinterpret_cast<const ProofVerifyDetailsChromium*>(&verify_details);
  cert_verify_result_ = std::make_unique<CertVerifyResult>(
      verify_details_chromium->cert_verify_result);
  logger_->OnCertificateVerified(*cert_verify_result_);
  pkp_bypassed_ = verify_details_chromium->pkp_bypassed;
  is_fatal_cert_error_ = verify_details_chromium->is_fatal_cert_error;
}

void QuicChromiumClientSession::StartReading() {
  for (auto& packet_reader : packet_readers_) {
    packet_reader->StartReading();
  }
}

void QuicChromiumClientSession::CloseSessionOnError(
    int net_error,
    quic::QuicErrorCode quic_error,
    quic::ConnectionCloseBehavior behavior) {
  base::UmaHistogramSparse("Net.QuicSession.CloseSessionOnError", -net_error);

  if (!callback_.is_null()) {
    std::move(callback_).Run(net_error);
  }

  NotifyAllStreamsOfError(net_error);

  net_log_.AddEventWithIntParams(NetLogEventType::QUIC_SESSION_CLOSE_ON_ERROR,
                                 "net_error", net_error);

  if (connection()->connected()) {
    connection()->CloseConnection(quic_error, "net error", behavior);
  }
  DCHECK(!connection()->connected());

  CloseAllHandles(net_error);
  NotifyFactoryOfSessionClosed();
}

void QuicChromiumClientSession::CloseSessionOnErrorLater(
    int net_error,
    quic::QuicErrorCode quic_error,
    quic::ConnectionCloseBehavior behavior) {
  base::UmaHistogramSparse("Net.QuicSession.CloseSessionOnError", -net_error);

  if (!callback_.is_null()) {
    std::move(callback_).Run(net_error);
  }
  NotifyAllStreamsOfError(net_error);
  net_log_.AddEventWithIntParams(NetLogEventType::QUIC_SESSION_CLOSE_ON_ERROR,
                                 "net_error", net_error);

  if (connection()->connected()) {
    connection()->CloseConnection(quic_error, "net error", behavior);
  }
  DCHECK(!connection()->connected());

  CloseAllHandles(net_error);
  NotifyFactoryOfSessionClosedLater();
}

void QuicChromiumClientSession::NotifyAllStreamsOfError(int net_error) {
  PerformActionOnActiveStreams([net_error](quic::QuicStream* stream) {
    static_cast<QuicChromiumClientStream*>(stream)->OnError(net_error);
    return true;
  });
}

void QuicChromiumClientSession::CloseAllHandles(int net_error) {
  while (!handles_.empty()) {
    Handle* handle = *handles_.begin();
    handles_.erase(handle);
    handle->OnSessionClosed(connection()->version(), net_error, error(),
                            source_, port_migration_detected_,
                            quic_connection_migration_attempted_,
                            quic_connection_migration_successful_,
                            GetConnectTiming(), WasConnectionEverUsed());
  }
}

void QuicChromiumClientSession::CancelAllRequests(int net_error) {
  UMA_HISTOGRAM_COUNTS_1000("Net.QuicSession.AbortedPendingStreamRequests",
                            stream_requests_.size());

  while (!stream_requests_.empty()) {
    StreamRequest* request = stream_requests_.front();
    stream_requests_.pop_front();
    request->OnRequestCompleteFailure(net_error);
  }
}

void QuicChromiumClientSession::NotifyRequestsOfConfirmation(int net_error) {
  // Post tasks to avoid reentrancy.
  for (auto& callback : waiting_for_confirmation_callbacks_) {
    task_runner_->PostTask(FROM_HERE,
                           base::BindOnce(std::move(callback), net_error));
  }

  waiting_for_confirmation_callbacks_.clear();
}

void QuicChromiumClientSession::MaybeMigrateToDifferentPortOnPathDegrading() {
  DCHECK(allow_port_migration_ && !migrate_session_early_v2_);

  current_migration_cause_ = CHANGE_PORT_ON_PATH_DEGRADING;

  // Migration before handshake confirmed is not allowed.
  if (!connection()->IsHandshakeConfirmed()) {
    HistogramAndLogMigrationFailure(
        MIGRATION_STATUS_PATH_DEGRADING_BEFORE_HANDSHAKE_CONFIRMED,
        connection_id(), "Path degrading before handshake confirmed");
    return;
  }

  if (config()->DisableConnectionMigration()) {
    HistogramAndLogMigrationFailure(MIGRATION_STATUS_DISABLED_BY_CONFIG,
                                    connection_id(),
                                    "Migration disabled by config");
    return;
  }

  net_log_.BeginEvent(NetLogEventType::QUIC_PORT_MIGRATION_TRIGGERED);

  if (!session_pool_) {
    return;
  }

  // Probe a different port, session will migrate to the probed port on success.
  // DoNothingAs is passed in for `probing_callback` as the return value of
  // StartProbing is not needed.
  StartProbing(base::DoNothingAs<void(ProbingResult)>(), default_network_,
               peer_address());
  net_log_.EndEvent(NetLogEventType::QUIC_PORT_MIGRATION_TRIGGERED);
}

void QuicChromiumClientSession::
    MaybeMigrateToAlternateNetworkOnPathDegrading() {
  net_log_.AddEvent(
      NetLogEventType::QUIC_CONNECTION_MIGRATION_ON_PATH_DEGRADING);

  current_migration_cause_ = CHANGE_NETWORK_ON_PATH_DEGRADING;

  if (!migrate_session_early_v2_) {
    HistogramAndLogMigrationFailure(MIGRATION_STATUS_PATH_DEGRADING_NOT_ENABLED,
                                    connection_id(),
                                    "Migration on path degrading not enabled");
    return;
  }

  if (GetCurrentNetwork() == default_network_ &&
      current_migrations_to_non_default_network_on_path_degrading_ >=
          max_migrations_to_non_default_network_on_path_degrading_) {
    HistogramAndLogMigrationFailure(
        MIGRATION_STATUS_ON_PATH_DEGRADING_DISABLED, connection_id(),
        "Exceeds maximum number of migrations on path degrading");
    return;
  }

  handles::NetworkHandle alternate_network =
      session_pool_->FindAlternateNetwork(GetCurrentNetwork());
  if (alternate_network == handles::kInvalidNetworkHandle) {
    HistogramAndLogMigrationFailure(MIGRATION_STATUS_NO_ALTERNATE_NETWORK,
                                    connection_id(),
                                    "No alternative network on path degrading");
    return;
  }

  LogHandshakeStatusOnMigrationSignal();

  if (!connection()->IsHandshakeConfirmed()) {
    HistogramAndLogMigrationFailure(
        MIGRATION_STATUS_PATH_DEGRADING_BEFORE_HANDSHAKE_CONFIRMED,
        connection_id(), "Path degrading before handshake confirmed");
    return;
  }

  net_log_.BeginEventWithStringParams(
      NetLogEventType::QUIC_CONNECTION_MIGRATION_TRIGGERED, "trigger",
      "PathDegrading");
  // Probe the alternative network, session will migrate to the probed
  // network and decide whether it wants to migrate back to the default
  // network on success. DoNothingAs is passed in for `probing_callback` as the
  // return value of MaybeStartProbing is not needed.
  MaybeStartProbing(base::DoNothingAs<void(ProbingResult)>(), alternate_network,
                    peer_address());
  net_log_.EndEvent(NetLogEventType::QUIC_CONNECTION_MIGRATION_TRIGGERED);
}

void QuicChromiumClientSession::MaybeStartProbing(
    ProbingCallback probing_callback,
    handles::NetworkHandle network,
    const quic::QuicSocketAddress& peer_address) {
  if (!session_pool_) {
    task_runner_->PostTask(
        FROM_HERE, base::BindOnce(std::move(probing_callback),
                                  ProbingResult::DISABLED_WITH_IDLE_SESSION));
    return;
  }

  CHECK_NE(handles::kInvalidNetworkHandle, network);

  if (!migrate_idle_session_ && !HasActiveRequestStreams()) {
    HistogramAndLogMigrationFailure(MIGRATION_STATUS_NO_MIGRATABLE_STREAMS,
                                    connection_id(), "No active streams");
    CloseSessionOnErrorLater(
        ERR_NETWORK_CHANGED,
        quic::QUIC_CONNECTION_MIGRATION_NO_MIGRATABLE_STREAMS,
        quic::ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
    task_runner_->PostTask(
        FROM_HERE, base::BindOnce(std::move(probing_callback),
                                  ProbingResult::DISABLED_WITH_IDLE_SESSION));
    return;
  }

  if (migrate_idle_session_ && CheckIdleTimeExceedsIdleMigrationPeriod()) {
    task_runner_->PostTask(
        FROM_HERE, base::BindOnce(std::move(probing_callback),
                                  ProbingResult::DISABLED_WITH_IDLE_SESSION));
    return;
  }

  if (config()->DisableConnectionMigration()) {
    DVLOG(1) << "Client disables probing network with connection migration "
             << "disabled by config";
    HistogramAndLogMigrationFailure(MIGRATION_STATUS_DISABLED_BY_CONFIG,
                                    connection_id(),
                                    "Migration disabled by config");
    task_runner_->PostTask(FROM_HERE,
                           base::BindOnce(std::move(probing_callback),
                                          ProbingResult::DISABLED_BY_CONFIG));
    return;
  }

  StartProbing(std::move(probing_callback), network, peer_address);
}

void QuicChromiumClientSession::CreateContextForMultiPortPath(
    std::unique_ptr<quic::MultiPortPathContextObserver> context_observer) {
  // Create and configure socket on default network
  std::unique_ptr<DatagramClientSocket> probing_socket =
      session_pool_->CreateSocket(net_log_.net_log(), net_log_.source());
  if (base::FeatureList::IsEnabled(net::features::kAsyncMultiPortPath)) {
    DatagramClientSocket* probing_socket_ptr = probing_socket.get();
    CompletionOnceCallback configure_callback = base::BindOnce(
        &QuicChromiumClientSession::FinishCreateContextForMultiPortPath,
        weak_factory_.GetWeakPtr(), std::move(context_observer),
        std::move(probing_socket));
    session_pool_->ConnectAndConfigureSocket(
        std::move(configure_callback), probing_socket_ptr,
        ToIPEndPoint(peer_address()), default_network_,
        session_key_.socket_tag());
    return;
  }

  if (session_pool_->ConfigureSocket(
          probing_socket.get(), ToIPEndPoint(peer_address()), default_network_,
          session_key_.socket_tag()) != OK) {
    return;
  }

  FinishCreateContextForMultiPortPath(std::move(context_observer),
                                      std::move(probing_socket), OK);
}

void QuicChromiumClientSession::FinishCreateContextForMultiPortPath(
    std::unique_ptr<quic::MultiPortPathContextObserver> context_observer,
    std::unique_ptr<DatagramClientSocket> probing_socket,
    int rv) {
  if (rv != OK) {
    context_observer->OnMultiPortPathContextAvailable(nullptr);
    return;
  }
  // Create new packet writer and reader on the probing socket.
  auto probing_writer = std::make_unique<QuicChromiumPacketWriter>(
      probing_socket.get(), task_runner_);
  auto probing_reader = std::make_unique<QuicChromiumPacketReader>(
      std::move(probing_socket), clock_, this, yield_after_packets_,
      yield_after_duration_, session_pool_->report_ecn(), net_log_);

  probing_reader->StartReading();
  path_validation_writer_delegate_.set_network(default_network_);
  path_validation_writer_delegate_.set_peer_address(peer_address());
  probing_writer->set_delegate(&path_validation_writer_delegate_);
  IPEndPoint local_address;
  probing_reader->socket()->GetLocalAddress(&local_address);
  context_observer->OnMultiPortPathContextAvailable(
      std::make_unique<QuicChromiumPathValidationContext>(
          ToQuicSocketAddress(local_address), peer_address(), default_network_,
          std::move(probing_writer), std::move(probing_reader)));
}

void QuicChromiumClientSession::MigrateToMultiPortPath(
    std::unique_ptr<quic::QuicPathValidationContext> context) {
  DCHECK_NE(nullptr, context);
  auto* chrome_context =
      static_cast<QuicChromiumPathValidationContext*>(context.get());
  std::unique_ptr<QuicChromiumPacketWriter> owned_writer =
      chrome_context->ReleaseWriter();
  // Remove |this| as the old packet writer's delegate. Write error on old
  // writers will be ignored.
  // Set |this| to listen on socket write events on the packet writer
  // that was used for probing.
  static_cast<QuicChromiumPacketWriter*>(connection()->writer())
      ->set_delegate(nullptr);
  owned_writer->set_delegate(this);

  if (!MigrateToSocket(
          chrome_context->self_address(), chrome_context->peer_address(),
          chrome_context->ReleaseReader(), std::move(owned_writer))) {
    LogMigrateToSocketStatus(false);
    return;
  }
  LogMigrateToSocketStatus(true);
  num_migrations_++;
}

void QuicChromiumClientSession::StartProbing(
    ProbingCallback probing_callback,
    handles::NetworkHandle network,
    const quic::QuicSocketAddress& peer_address) {
  // Check if probing manager is probing the same path.
  auto* existing_context = static_cast<QuicChromiumPathValidationContext*>(
      connection()->GetPathValidationContext());
  if (existing_context && existing_context->network() == network &&
      existing_context->peer_address() == peer_address) {
    task_runner_->PostTask(FROM_HERE,
                           base::BindOnce(std::move(probing_callback),
                                          ProbingResult::DISABLED_BY_CONFIG));
    return;
  }

  // Create and configure socket on |network|.
  std::unique_ptr<DatagramClientSocket> probing_socket =
      session_pool_->CreateSocket(net_log_.net_log(), net_log_.source());
  DatagramClientSocket* probing_socket_ptr = probing_socket.get();
  CompletionOnceCallback configure_callback =
      base::BindOnce(&QuicChromiumClientSession::FinishStartProbing,
                     weak_factory_.GetWeakPtr(), std::move(probing_callback),
                     std::move(probing_socket), network, peer_address);

  if (current_migration_cause_ != UNKNOWN_CAUSE &&
      !MidMigrationCallbackForTesting().is_null()) {
    std::move(MidMigrationCallbackForTesting()).Run();  // IN-TEST
  }

  session_pool_->ConnectAndConfigureSocket(
      std::move(configure_callback), probing_socket_ptr,
      ToIPEndPoint(peer_address), network, session_key_.socket_tag());

  return;
}

void QuicChromiumClientSession::FinishStartProbing(
    ProbingCallback probing_callback,
    std::unique_ptr<DatagramClientSocket> probing_socket,
    handles::NetworkHandle network,
    const quic::QuicSocketAddress& peer_address,
    int rv) {
  if (rv != OK) {
    HistogramAndLogMigrationFailure(MIGRATION_STATUS_INTERNAL_ERROR,
                                    connection_id(),
                                    "Socket configuration failed");
    task_runner_->PostTask(FROM_HERE,
                           base::BindOnce(std::move(probing_callback),
                                          ProbingResult::INTERNAL_ERROR));

    return;
  }
  // Create new packet writer and reader on the probing socket.
  auto probing_writer = std::make_unique<QuicChromiumPacketWriter>(
      probing_socket.get(), task_runner_);
  auto probing_reader = std::make_unique<QuicChromiumPacketReader>(
      std::move(probing_socket), clock_, this, yield_after_packets_,
      yield_after_duration_, session_pool_->report_ecn(), net_log_);

  probing_reader->StartReading();
  path_validation_writer_delegate_.set_network(network);
  path_validation_writer_delegate_.set_peer_address(peer_address);
  probing_writer->set_delegate(&path_validation_writer_delegate_);
  IPEndPoint local_address;
  probing_reader->socket()->GetLocalAddress(&local_address);
  auto context = std::make_unique<QuicChromiumPathValidationContext>(
      ToQuicSocketAddress(local_address), peer_address, network,
      std::move(probing_writer), std::move(probing_reader));
  switch (current_migration_cause_) {
    case CHANGE_PORT_ON_PATH_DEGRADING:
      ValidatePath(
          std::move(context),
          std::make_unique<PortMigrationValidationResultDelegate>(this),
          quic::PathValidationReason::kPortMigration);
      break;
    case ON_SERVER_PREFERRED_ADDRESS_AVAILABLE:
      ValidatePath(
          std::move(context),
          std::make_unique<ServerPreferredAddressValidationResultDelegate>(
              this),
          quic::PathValidationReason::kServerPreferredAddressMigration);
      break;
    default:
      ValidatePath(
          std::move(context),
          std::make_unique<ConnectionMigrationValidationResultDelegate>(this),
          quic::PathValidationReason::kConnectionMigration);
      break;
  }

  task_runner_->PostTask(FROM_HERE, base::BindOnce(std::move(probing_callback),
                                                   ProbingResult::PENDING));
}

void QuicChromiumClientSession::StartMigrateBackToDefaultNetworkTimer(
    base::TimeDelta delay) {
  if (current_migration_cause_ != ON_NETWORK_MADE_DEFAULT) {
    current_migration_cause_ = ON_MIGRATE_BACK_TO_DEFAULT_NETWORK;
  }

  CancelMigrateBackToDefaultNetworkTimer();
  // Post a task to try migrate back to default network after |delay|.
  migrate_back_to_default_timer_.Start(
      FROM_HERE, delay,
      base::BindOnce(
          &QuicChromiumClientSession::MaybeRetryMigrateBackToDefaultNetwork,
          weak_factory_.GetWeakPtr()));
}

void QuicChromiumClientSession::CancelMigrateBackToDefaultNetworkTimer() {
  retry_migrate_back_count_ = 0;
  migrate_back_to_default_timer_.Stop();
}

void QuicChromiumClientSession::TryMigrateBackToDefaultNetwork(
    base::TimeDelta timeout) {
  if (default_network_ == handles::kInvalidNetworkHandle) {
    DVLOG(1) << "Default network is not connected";
    return;
  }

  net_log_.AddEventWithInt64Params(
      NetLogEventType::QUIC_CONNECTION_MIGRATION_ON_MIGRATE_BACK, "retry_count",
      retry_migrate_back_count_);
  // Start probe default network immediately, if manager is probing
  // the same network, this will be a no-op. Otherwise, previous probe
  // will be cancelled and manager starts to probe |default_network_|
  // immediately.
  MaybeStartProbing(
      base::BindOnce(
          &QuicChromiumClientSession::FinishTryMigrateBackToDefaultNetwork,
          weak_factory_.GetWeakPtr(), timeout),
      default_network_, peer_address());
}

void QuicChromiumClientSession::FinishTryMigrateBackToDefaultNetwork(
    base::TimeDelta timeout,
    ProbingResult result) {
  if (result != ProbingResult::PENDING) {
    // Session is not allowed to migrate, mark session as going away, cancel
    // migrate back to default timer.
    NotifyFactoryOfSessionGoingAway();
    CancelMigrateBackToDefaultNetworkTimer();
    return;
  }

  retry_migrate_back_count_++;
  migrate_back_to_default_timer_.Start(
      FROM_HERE, timeout,
      base::BindOnce(
          &QuicChromiumClientSession::MaybeRetryMigrateBackToDefaultNetwork,
          weak_factory_.GetWeakPtr()));
}

void QuicChromiumClientSession::MaybeRetryMigrateBackToDefaultNetwork() {
  base::TimeDelta retry_migrate_back_timeout =
      base::Seconds(UINT64_C(1) << retry_migrate_back_count_);
  if (pending_migrate_session_on_write_error_) {
    StartMigrateBackToDefaultNetworkTimer(base::TimeDelta());
    return;
  }
  if (default_network_ == GetCurrentNetwork()) {
    // If session has been back on the default already by other direct
    // migration attempt, cancel migrate back now.
    CancelMigrateBackToDefaultNetworkTimer();
    return;
  }
  if (retry_migrate_back_timeout > max_time_on_non_default_network_) {
    // Mark session as going away to accept no more streams.
    NotifyFactoryOfSessionGoingAway();
    return;
  }
  TryMigrateBackToDefaultNetwork(retry_migrate_back_timeout);
}

bool QuicChromiumClientSession::CheckIdleTimeExceedsIdleMigrationPeriod() {
  if (!migrate_idle_session_) {
    return false;
  }

  if (HasActiveRequestStreams()) {
    return false;
  }

  // There are no active/drainning streams, check the last stream's finish time.
  if (tick_clock_->NowTicks() - most_recent_stream_close_time_ <
      idle_migration_period_) {
    // Still within the idle migration period.
    return false;
  }

  HistogramAndLogMigrationFailure(MIGRATION_STATUS_IDLE_MIGRATION_TIMEOUT,
                                  connection_id(),
                                  "Ilde migration period exceeded");
  CloseSessionOnErrorLater(ERR_NETWORK_CHANGED, quic::QUIC_NETWORK_IDLE_TIMEOUT,
                           quic::ConnectionCloseBehavior::SILENT_CLOSE);
  return true;
}

void QuicChromiumClientSession::ResetNonMigratableStreams() {
  // TODO(zhongyi): may close non-migratable draining streams as well to avoid
  // sending additional data on alternate networks.
  PerformActionOnActiveStreams([](quic::QuicStream* stream) {
    QuicChromiumClientStream* chrome_stream =
        static_cast<QuicChromiumClientStream*>(stream);
    if (!chrome_stream->can_migrate_to_cellular_network()) {
      // Close the stream in both direction by resetting the stream.
      // TODO(zhongyi): use a different error code to reset streams for
      // connection migration.
      chrome_stream->Reset(quic::QUIC_STREAM_CANCELLED);
    }
    return true;
  });
}

void QuicChromiumClientSession::LogMetricsOnNetworkDisconnected() {
  if (most_recent_path_degrading_timestamp_ != base::TimeTicks()) {
    most_recent_network_disconnected_timestamp_ = tick_clock_->NowTicks();
    base::TimeDelta degrading_duration =
        most_recent_network_disconnected_timestamp_ -
        most_recent_path_degrading_timestamp_;
    UMA_HISTOGRAM_CUSTOM_TIMES(
        "Net.QuicNetworkDegradingDurationTillDisconnected", degrading_duration,
        base::Milliseconds(1), base::Minutes(10), 100);
  }
  if (most_recent_write_error_timestamp_ != base::TimeTicks()) {
    base::TimeDelta write_error_to_disconnection_gap =
        most_recent_network_disconnected_timestamp_ -
        most_recent_write_error_timestamp_;
    UMA_HISTOGRAM_CUSTOM_TIMES(
        "Net.QuicNetworkGapBetweenWriteErrorAndDisconnection",
        write_error_to_disconnection_gap, base::Milliseconds(1),
        base::Minutes(10), 100);
    base::UmaHistogramSparse("Net.QuicSession.WriteError.NetworkDisconnected",
                             -most_recent_write_error_);
    most_recent_write_error_ = 0;
    most_recent_write_error_timestamp_ = base::TimeTicks();
  }
}

void QuicChromiumClientSession::LogMetricsOnNetworkMadeDefault() {
  if (most_recent_path_degrading_timestamp_ != base::TimeTicks()) {
    if (most_recent_network_disconnected_timestamp_ != base::TimeTicks()) {
      // NetworkDiscconected happens before NetworkMadeD
```