Response:
The user wants to understand the functionality of the provided C++ code snippet from `net/quic/quic_chromium_client_session.cc`.

Here's a breakdown of the thought process to generate the answer:

1. **Identify the core function:** The code snippet is part of the `QuicChromiumClientSession` class and appears within the `OnConnectionClosed` method. This method is called when the QUIC connection is closed.

2. **Analyze the code blocks:** The code is structured with `if` statements and UMA histogram logging. This suggests that the primary function is to record various statistics and events related to the connection closure.

3. **Categorize the logged metrics:**  Look at the histogram names and the conditions under which they are logged. Common themes emerge:
    * **Path Degradation:** Metrics related to forward progress after path degradation (`Net.QuicSession.NumForwardProgressMadeAfterPathDegrading`).
    * **Multi-Port Probing:** Metrics for multi-port connection attempts and successes/failures (`Net.QuicMultiPort.*`).
    * **Error Codes:** Recording connection close error codes (`RecordConnectionCloseErrorCode`).
    * **Public Reset:** Specific handling and logging of public reset errors, including whether it came from a Google server.
    * **Idle Timeout:** Metrics related to idle timeouts, including the number of streams waiting to write.
    * **Stream Close Errors:** Logging stream close error codes from both the server and client side.
    * **Handshake Timeouts:**  Tracking handshake timeouts and whether path degradation was detected.
    * **RTO (Retransmission Timeout):** Metrics related to retransmission timeouts.
    * **Network Idle Timeout:** More detailed logging when the connection closes due to idle timeout.
    * **Blackholing:**  Handling and logging scenarios where the connection might be blackholed.
    * **Crypto Retransmits:**  Recording the number of crypto retransmissions.
    * **Connection Duration:**  Logging the overall duration of the connection.
    * **Migrations:** Tracking the number of connection migrations.
    * **Key Updates:** Logging key update statistics.
    * **Undecryptable Packets:** Recording the number of undecryptable packets.
    * **QUIC Version:** Logging the QUIC version used.

4. **Identify related actions:** Besides logging, the code performs actions based on the closure reason:
    * **Notifying Observers:**  `connectivity_observer_list_` is iterated to inform observers about the closed session.
    * **Keeping Connection Alive:**  Logic to check if the connection should be kept alive despite an idle timeout, based on buffered data.
    * **Notifying Factory:** `NotifyFactoryOfSessionGoingAway()` and `NotifyFactoryOfSessionClosedLater()` signal the session pool about the closure.
    * **Closing Handles and Cancelling Requests:** `CloseAllHandles()` and `CancelAllRequests()` clean up resources and inform higher layers.
    * **Running Callback:**  If a callback is registered, it's executed.
    * **Closing Sockets:**  The code iterates through packet readers and closes associated sockets.

5. **Analyze JavaScript relevance:** Consider if any of these actions or metrics directly impact JavaScript execution in a web browser. While this C++ code doesn't directly execute JavaScript, it manages the underlying network connection. Therefore:
    * Network errors detected here (like timeouts or public resets) can manifest as network errors in the browser, affecting JavaScript's ability to fetch resources or communicate with the server.
    * Connection migrations, though transparent to JavaScript in ideal scenarios, can impact performance and might become visible as connection stalls if issues arise.

6. **Develop Example Scenarios (Hypothetical Input/Output):**
    * **Scenario 1 (Normal Closure):** Focus on a clean closure where most counts are zero, and the error code is `QUIC_NO_ERROR`.
    * **Scenario 2 (Idle Timeout):** Show how the counters for active streams and waiting streams would be populated if the connection times out due to inactivity.
    * **Scenario 3 (Public Reset):**  Demonstrate the logging of `is_from_google_server` and the packet content if a public reset is received.

7. **Identify User/Programming Errors:** Think about what actions by the user or programmer could lead to these closure scenarios:
    * **User Errors:** Closing the browser tab, poor network connectivity, network changes.
    * **Programming Errors:** Server-side issues leading to public resets, misconfigured timeouts, errors in stream management causing idle timeouts.

8. **Outline User Steps to Reach This Code:**  Trace back the likely user actions that trigger a network connection and its subsequent closure: opening a website, navigating, and then potentially closing the tab or encountering a network issue.

9. **Synthesize the Functionality Summary:** Combine the observations from the code analysis into a concise description of the code's purpose.

10. **Review and Refine:** Read through the generated answer, ensuring clarity, accuracy, and completeness. Make sure the examples and explanations are easy to understand. For example, initially, I might have just listed the histograms without explaining their meaning. Refinement involves adding context and explanations. Also, double-check if the answer addresses all parts of the prompt.

This structured approach helps in systematically understanding the code's functionality and its implications, even without deep expertise in the specific codebase.
```cpp
{
    UMA_HISTOGRAM_COUNTS_1000(
        "Net.QuicSession.NumForwardProgressMadeAfterPathDegrading",
        connection()->GetStats().num_forward_progress_after_path_degrading);
  }
  if (const quic::QuicConnection::MultiPortStats* multi_port_stats =
          connection()->multi_port_stats()) {
    UMA_HISTOGRAM_COUNTS_1000("Net.QuicMultiPort.NumProbeAttempts",
                              multi_port_stats->num_client_probing_attempts);
    UMA_HISTOGRAM_COUNTS_1000("Net.QuicMultiPort.NumSuccessfulProbes",
                              multi_port_stats->num_successful_probes);
    UMA_HISTOGRAM_COUNTS_1000(
        "Net.QuicMultiPort.NumMultiPortFailureWhenPathNotDegrading",
        multi_port_stats
            ->num_multi_port_probe_failures_when_path_not_degrading);
    size_t total_multi_port_probe_failures =
        multi_port_stats
            ->num_multi_port_probe_failures_when_path_not_degrading +
        multi_port_stats->num_multi_port_probe_failures_when_path_degrading;
    uint64_t srtt_ms =
        multi_port_stats->rtt_stats.smoothed_rtt().ToMilliseconds();
    if (connection()->GetStats().num_path_degrading > 0 &&
        total_multi_port_probe_failures > 0 && srtt_ms > 0) {
      base::UmaHistogramSparse(
          "Net.QuicMultiPort.AltPortRttWhenPathDegradingVsGeneral",
          static_cast<int>(
              multi_port_stats->rtt_stats_when_default_path_degrading
                  .smoothed_rtt()
                  .ToMilliseconds() *
              100 / srtt_ms));
      UMA_HISTOGRAM_COUNTS_1000(
          "Net.QuicMultiPort.NumMultiPortFailureWhenPathDegrading",
          multi_port_stats->num_multi_port_probe_failures_when_path_degrading);
      base::UmaHistogramPercentage(
          "Net.QuicMultiPort.AltPortFailureWhenPathDegradingVsGeneral",
          static_cast<int>(
              multi_port_stats
                  ->num_multi_port_probe_failures_when_path_degrading *
              100 / total_multi_port_probe_failures));
    }
  }

  RecordConnectionCloseErrorCode(frame, source, session_key_.host(),
                                 OneRttKeysAvailable(),
                                 !ech_config_list_.empty());
  if (OneRttKeysAvailable()) {
    handles::NetworkHandle current_network = GetCurrentNetwork();
    for (auto& observer : connectivity_observer_list_) {
      observer.OnSessionClosedAfterHandshake(this, current_network, source,
                                             frame.quic_error_code);
    }
  }

  const quic::QuicErrorCode error = frame.quic_error_code;
  const std::string& error_details = frame.error_details;

  if (source == quic::ConnectionCloseSource::FROM_SELF &&
      error == quic::QUIC_NETWORK_IDLE_TIMEOUT && ShouldKeepConnectionAlive()) {
    quic::QuicStreamCount streams_waiting_to_write = 0;
    PerformActionOnActiveStreams(
        [&streams_waiting_to_write](quic::QuicStream* stream) {
          if (stream->HasBufferedData()) {
            ++streams_waiting_to_write;
          }
          return true;
        });

    UMA_HISTOGRAM_COUNTS_100(
        "Net.QuicSession.NumStreamsWaitingToWriteOnIdleTimeout",
        streams_waiting_to_write);
    UMA_HISTOGRAM_COUNTS_100("Net.QuicSession.NumActiveStreamsOnIdleTimeout",
                             GetNumActiveStreams());
  }

  if (source == quic::ConnectionCloseSource::FROM_PEER) {
    if (error == quic::QUIC_PUBLIC_RESET) {
      // is_from_google_server will be true if the received EPID is
      // kEPIDGoogleFrontEnd or kEPIDGoogleFrontEnd0.
      const bool is_from_google_server =
          error_details.find(base::StringPrintf(
              "From %s", quic::kEPIDGoogleFrontEnd)) != std::string::npos;

      if (OneRttKeysAvailable()) {
        UMA_HISTOGRAM_BOOLEAN(
            "Net.QuicSession.ClosedByPublicReset.HandshakeConfirmed",
            is_from_google_server);
      } else {
        UMA_HISTOGRAM_BOOLEAN("Net.QuicSession.ClosedByPublicReset",
                              is_from_google_server);
      }

      if (is_from_google_server) {
        UMA_HISTOGRAM_COUNTS_100(
            "Net.QuicSession.NumMigrationsExercisedBeforePublicReset",
            packet_readers_.size() - 1);
      }

      base::UmaHistogramSparse(
          "Net.QuicSession.LastSentPacketContentBeforePublicReset",
          connection()
              ->sent_packet_manager()
              .unacked_packets()
              .GetLastPacketContent());

      const quic::QuicTime last_in_flight_packet_sent_time =
          connection()
              ->sent_packet_manager()
              .unacked_packets()
              .GetLastInFlightPacketSentTime();
      const quic::QuicTime handshake_completion_time =
          connection()->GetStats().handshake_completion_time;
      if (last_in_flight_packet_sent_time.IsInitialized() &&
          handshake_completion_time.IsInitialized() &&
          last_in_flight_packet_sent_time >= handshake_completion_time) {
        const quic::QuicTime::Delta delay =
            last_in_flight_packet_sent_time - handshake_completion_time;
        UMA_HISTOGRAM_LONG_TIMES_100(
            "Net.QuicSession."
            "LastInFlightPacketSentTimeFromHandshakeCompletionWithPublicReset",
            base::Milliseconds(delay.ToMilliseconds()));
      }

      UMA_HISTOGRAM_LONG_TIMES_100(
          "Net.QuicSession.ConnectionDurationWithPublicReset",
          tick_clock_->NowTicks() - connect_timing_.connect_end);
    }
    if (OneRttKeysAvailable()) {
      base::HistogramBase* histogram = base::SparseHistogram::FactoryGet(
          "Net.QuicSession.StreamCloseErrorCodeServer.HandshakeConfirmed",
          base::HistogramBase::kUmaTargetedHistogramFlag);
      size_t num_streams = GetNumActiveStreams();
      if (num_streams > 0) {
        histogram->AddCount(error, num_streams);
      }
    }
  } else {
    if (OneRttKeysAvailable()) {
      base::HistogramBase* histogram = base::SparseHistogram::FactoryGet(
          "Net.QuicSession.StreamCloseErrorCodeClient.HandshakeConfirmed",
          base::HistogramBase::kUmaTargetedHistogramFlag);
      size_t num_streams = GetNumActiveStreams();
      if (num_streams > 0) {
        histogram->AddCount(error, num_streams);
      }
    } else {
      if (error == quic::QUIC_HANDSHAKE_TIMEOUT) {
        UMA_HISTOGRAM_BOOLEAN(
            "Net.QuicSession.HandshakeTimeout.PathDegradingDetected",
            connection()->IsPathDegrading());
      }
    }
    if (error == quic::QUIC_TOO_MANY_RTOS) {
      UMA_HISTOGRAM_COUNTS_1000(
          "Net.QuicSession.ClosedByRtoAtClient.ReceivedPacketCount",
          connection()->GetStats().packets_received);
      UMA_HISTOGRAM_COUNTS_1000(
          "Net.QuicSession.ClosedByRtoAtClient.SentPacketCount",
          connection()->GetStats().packets_sent);
      UMA_HISTOGRAM_COUNTS_100(
          "Net.QuicSession."
          "MaxConsecutiveRtoWithForwardProgressAndBlackholeDetected",
          connection()->GetStats().max_consecutive_rto_with_forward_progress);
    }
  }

  if (error == quic::QUIC_NETWORK_IDLE_TIMEOUT) {
    UMA_HISTOGRAM_COUNTS_1M(
        "Net.QuicSession.ConnectionClose.NumOpenStreams.TimedOut",
        GetNumActiveStreams());
    if (OneRttKeysAvailable()) {
      if (GetNumActiveStreams() > 0) {
        UMA_HISTOGRAM_BOOLEAN(
            "Net.QuicSession.TimedOutWithOpenStreams.HasUnackedPackets",
            connection()->sent_packet_manager().HasInFlightPackets());
        UMA_HISTOGRAM_COUNTS_1M(
            "Net.QuicSession.TimedOutWithOpenStreams.ConsecutivePTOCount",
            connection()->sent_packet_manager().GetConsecutivePtoCount());
        base::UmaHistogramSparse(
            "Net.QuicSession.TimedOutWithOpenStreams.LocalPort",
            connection()->self_address().port());
      }
    } else {
      UMA_HISTOGRAM_COUNTS_1M(
          "Net.QuicSession.ConnectionClose.NumOpenStreams.HandshakeTimedOut",
          GetNumActiveStreams());
      UMA_HISTOGRAM_COUNTS_1M(
          "Net.QuicSession.ConnectionClose.NumTotalStreams.HandshakeTimedOut",
          num_total_streams_);
    }
  }

  if (OneRttKeysAvailable()) {
    // QUIC connections should not timeout while there are open streams,
    // since PING frames are sent to prevent timeouts. If, however, the
    // connection timed out with open streams then QUIC traffic has become
    // blackholed. Alternatively, if too many retransmission timeouts occur
    // then QUIC traffic has become blackholed.
    if (session_pool_ && (error == quic::QUIC_TOO_MANY_RTOS ||
                          (error == quic::QUIC_NETWORK_IDLE_TIMEOUT &&
                           GetNumActiveStreams() > 0))) {
      session_pool_->OnBlackholeAfterHandshakeConfirmed(this);
    }
    UMA_HISTOGRAM_COUNTS_100(
        "Net.QuicSession.CryptoRetransmitCount.HandshakeConfirmed",
        connection()->GetStats().crypto_retransmit_count);
    UMA_HISTOGRAM_COUNTS_100(
        "Net.QuicSession.MaxConsecutiveRtoWithForwardProgress",
        connection()->GetStats().max_consecutive_rto_with_forward_progress);
    UMA_HISTOGRAM_COUNTS_1000("Net.QuicSession.NumPingsSent",
                              connection()->GetStats().ping_frames_sent);
    UMA_HISTOGRAM_LONG_TIMES_100(
        "Net.QuicSession.ConnectionDuration",
        tick_clock_->NowTicks() - connect_timing_.connect_end);
    UMA_HISTOGRAM_COUNTS_100("Net.QuicSession.NumMigrations", num_migrations_);

    // KeyUpdates are used in TLS, but we no longer support pre-TLS QUIC.
    DCHECK(connection()->version().UsesTls());
    base::UmaHistogramCounts100("Net.QuicSession.KeyUpdate.PerConnection2",
                                connection()->GetStats().key_update_count);
    base::UmaHistogramCounts100(
        "Net.QuicSession.KeyUpdate.PotentialPeerKeyUpdateAttemptCount",
        connection()->PotentialPeerKeyUpdateAttemptCount());
    if (last_key_update_reason_ != quic::KeyUpdateReason::kInvalid) {
      std::string suffix =
          last_key_update_reason_ == quic::KeyUpdateReason::kRemote ? "Remote"
                                                                    : "Local";
      // These values are persisted to logs. Entries should not be renumbered
      // and numeric values should never be reused.
      enum class KeyUpdateSuccess {
        kInvalid = 0,
        kSuccess = 1,
        kFailedInitial = 2,
        kFailedNonInitial = 3,
        kMaxValue = kFailedNonInitial,
      };
      KeyUpdateSuccess value = KeyUpdateSuccess::kInvalid;
      if (connection()->HaveSentPacketsInCurrentKeyPhaseButNoneAcked()) {
        if (connection()->GetStats().key_update_count >= 2) {
          value = KeyUpdateSuccess::kFailedNonInitial;
        } else {
          value = KeyUpdateSuccess::kFailedInitial;
        }
      } else {
        value = KeyUpdateSuccess::kSuccess;
      }
      base::UmaHistogramEnumeration(
          "Net.QuicSession.KeyUpdate.Success." + suffix, value);
    }
  } else {
    if (error == quic::QUIC_PUBLIC_RESET) {
      RecordHandshakeFailureReason(HANDSHAKE_FAILURE_PUBLIC_RESET);
    } else if (connection()->GetStats().packets_received == 0) {
      RecordHandshakeFailureReason(HANDSHAKE_FAILURE_BLACK_HOLE);
      base::UmaHistogramSparse(
          "Net.QuicSession.ConnectionClose.HandshakeFailureBlackHole.QuicError",
          error);
    } else {
      RecordHandshakeFailureReason(HANDSHAKE_FAILURE_UNKNOWN);
      base::UmaHistogramSparse(
          "Net.QuicSession.ConnectionClose.HandshakeFailureUnknown.QuicError",
          error);
    }
    UMA_HISTOGRAM_COUNTS_100(
        "Net.QuicSession.CryptoRetransmitCount.HandshakeNotConfirmed",
        connection()->GetStats().crypto_retransmit_count);
  }

  base::UmaHistogramCounts1M(
      "Net.QuicSession.UndecryptablePacketsReceivedWithDecrypter",
      connection()->GetStats().num_failed_authentication_packets_received);
  base::UmaHistogramSparse("Net.QuicSession.QuicVersion",
                           connection()->transport_version());
  NotifyFactoryOfSessionGoingAway();
  quic::QuicSession::OnConnectionClosed(frame, source);

  if (!callback_.is_null()) {
    std::move(callback_).Run(ERR_QUIC_PROTOCOL_ERROR);
  }

  bool socket_found_in_writer = false;
  for (auto& packet_reader : packet_readers_) {
    packet_reader->CloseSocket();
    // If a writer exists that was not destroyed when the connection migrated,
    // then that writer may not be notified that its socket has been closed.
    // We know that the writer is a QuicChromiumPacketWriter since the packet
    // writer is set with the same type originally.
    socket_found_in_writer |=
        static_cast<QuicChromiumPacketWriter*>(connection()->writer())
            ->OnSocketClosed(packet_reader->socket());
  }
  CHECK(socket_found_in_writer);
  DCHECK(!HasActiveRequestStreams());
  CloseAllHandles(ERR_UNEXPECTED);
  CancelAllRequests(ERR_CONNECTION_CLOSED);
  NotifyRequestsOfConfirmation(ERR_CONNECTION_CLOSED);
  NotifyFactoryOfSessionClosedLater();
}
```

**功能列举:**

这段代码是 `QuicChromiumClientSession` 类的 `OnConnectionClosed` 方法的一部分，该方法在 QUIC 连接关闭时被调用。其主要功能是：

1. **记录连接关闭相关的统计信息 (Telemetry):**
   - 使用 `UMA_HISTOGRAM_*` 宏记录各种计数器、百分比、布尔值和时间信息到 Chrome 的 UMA (User Metrics Analysis) 系统，用于性能分析和调试。
   - 记录的内容包括：
     - 连接在路径降级后是否取得进展。
     - 多端口连接尝试和成功/失败的次数。
     - 路径降级时备用端口的 RTT (往返时延)。
     - 连接关闭的错误码。
     - 是否因 `PUBLIC_RESET` 关闭，以及是否来自 Google 服务器。
     - 连接因空闲超时关闭时，等待写入数据的流的数量。
     - 连接因空闲超时关闭时，活跃流的数量。
     - 在 `PUBLIC_RESET` 之前发送的最后一个数据包的内容和发送时间。
     - 连接时长。
     - 流关闭的错误码（区分服务器端和客户端）。
     - 握手超时时是否检测到路径降级。
     - 因过多 RTO (重传超时) 关闭时的发送和接收数据包数量。
     - 因网络空闲超时关闭时的活跃流数量。
     - 是否在有活跃流的情况下超时。
     - 加密重传的次数。
     - 发送的 PING 帧的数量。
     - 连接迁移的次数。
     - 密钥更新的统计信息。
     - 接收到的无法解密的包的数量。
     - 使用的 QUIC 版本。

2. **通知观察者 (Observers):**
   - 遍历 `connectivity_observer_list_`，调用每个观察者的 `OnSessionClosedAfterHandshake` 方法，通知它们会话已关闭。

3. **处理特定关闭原因:**
   - **网络空闲超时 (QUIC_NETWORK_IDLE_TIMEOUT):** 检查是否有流正在等待写入数据，并记录相关统计信息。
   - **公共重置 (QUIC_PUBLIC_RESET):** 判断是否来自 Google 服务器，并记录相关统计信息，包括迁移次数和最后发送的数据包内容。
   - **握手超时 (QUIC_HANDSHAKE_TIMEOUT):** 记录是否检测到路径降级。
   - **过多重传超时 (QUIC_TOO_MANY_RTOS):** 记录收发包数量和最大连续 RTO 次数。

4. **处理连接黑洞 (Blackhole):**
   - 如果连接在握手完成后，因过多 RTO 或在有活跃流的情况下空闲超时而关闭，则通知 `session_pool_`，认为可能遇到了网络黑洞。

5. **记录握手失败原因:**
   - 如果握手未完成就关闭，则根据错误码和接收到的数据包数量记录握手失败的原因 (`HANDSHAKE_FAILURE_PUBLIC_RESET`, `HANDSHAKE_FAILURE_BLACK_HOLE`, `HANDSHAKE_FAILURE_UNKNOWN`).

6. **通知工厂 (Factory):**
   - 调用 `NotifyFactoryOfSessionGoingAway()` 和 `NotifyFactoryOfSessionClosedLater()` 通知 `QuicSessionPool` 会话即将或已经关闭。

7. **执行回调 (Callback):**
   - 如果 `callback_` 不为空，则执行该回调，通常用于通知上层连接已关闭并可能传递错误信息。

8. **关闭套接字 (Socket):**
   - 遍历 `packet_readers_`，关闭所有关联的套接字。
   - 检查与连接关联的 `QuicChromiumPacketWriter` 是否已关闭相应的套接字。

9. **清理资源:**
   - 断言没有活跃的请求流 (`DCHECK(!HasActiveRequestStreams())`).
   - 调用 `CloseAllHandles(ERR_UNEXPECTED)` 关闭所有句柄。
   - 调用 `CancelAllRequests(ERR_CONNECTION_CLOSED)` 取消所有未完成的请求。
   - 调用 `NotifyRequestsOfConfirmation(ERR_CONNECTION_CLOSED)` 通知请求连接已关闭。

**与 JavaScript 的关系:**

这段 C++ 代码位于 Chromium 的网络栈中，直接管理着底层的 QUIC 连接。虽然 JavaScript 代码本身不直接调用这些 C++ 函数，但它通过浏览器提供的 API (例如 `fetch`, `XMLHttpRequest`, WebSockets over HTTP/3) 发起网络请求，这些请求最终会使用到这里的 QUIC 连接。

* **网络错误处理:** 当这里的代码检测到连接错误 (例如 `QUIC_NETWORK_IDLE_TIMEOUT`, `QUIC_PUBLIC_RESET`) 并关闭连接时，这些错误会向上层传递，最终可能导致 JavaScript 代码中的 `fetch` 操作失败或 WebSocket 连接断开，并触发相应的错误处理逻辑 (例如 `catch` 语句或 `onerror` 事件)。

**举例说明:**

假设一个 JavaScript 代码使用 `fetch` API 从服务器请求数据：

```javascript
fetch('https://example.com/data')
  .then(response => response.json())
  .then(data => console.log(data))
  .catch(error => console.error('网络请求失败:', error));
```

**假设输入与输出 (逻辑推理):**

* **假设输入:**
    * `source` 为 `quic::ConnectionCloseSource::FROM_PEER` (连接由对端关闭).
    * `frame.quic_error_code` 为 `quic::QUIC_PUBLIC_RESET`.
    * `frame.error_details` 包含 `"From kEPIDGoogleFrontEnd"` (表明来自 Google 服务器).
    * `OneRttKeysAvailable()` 返回 `true` (握手已完成).
    * `packet_readers_.size()` 为 3 (连接迁移过 2 次).
    * 连接建立时间 `connect_timing_.connect_end` 是 10 秒前.
    * 上一次发送数据包的时间在握手完成之后.

* **输出 (部分 UMA 记录):**
    * `UMA_HISTOGRAM_BOOLEAN("Net.QuicSession.ClosedByPublicReset.HandshakeConfirmed", true)`
    * `UMA_HISTOGRAM_COUNTS_100("Net.QuicSession.NumMigrationsExercisedBeforePublicReset", 2)`
    * `UMA_HISTOGRAM_LONG_TIMES_100("Net.QuicSession.ConnectionDurationWithPublicReset", base::Milliseconds(10000))`
    * `base::UmaHistogramSparse("Net.QuicSession.LastSentPacketContentBeforePublicReset", ...)` (记录最后发送的数据包内容)
    * `UMA_HISTOGRAM_LONG_TIMES_100("Net.QuicSession.LastInFlightPacketSentTimeFromHandshakeCompletionWithPublicReset", ...)` (记录延迟)

**用户或编程常见的使用错误:**

1. **服务端配置错误导致 `PUBLIC_RESET`:** 如果服务端配置不当或存在安全问题，可能会主动发送 `PUBLIC_RESET` 关闭连接。用户在不知情的情况下，会看到网络请求失败。

   * **用户操作:**  访问一个配置错误的网站。
   * **结果:**  JavaScript 的 `fetch` 会失败，并可能在控制台看到类似 "net::ERR_QUIC_PROTOCOL_ERROR" 的错误。

2. **网络环境不稳定导致连接超时:** 用户所处的网络环境不稳定，例如 Wi-Fi 信号弱或移动网络切换，可能导致连接长时间空闲，最终被 QUIC 层因超时而关闭。

   * **用户操作:**  在地铁或高速移动的环境下浏览网页。
   * **结果:**  JavaScript 发起的请求可能卡住，最终失败，并可能在控制台看到类似 "net::ERR_CONNECTION_TIMED_OUT" 的错误。

3. **服务端过早关闭连接:**  服务端可能由于某些原因（例如负载过高、资源不足）主动关闭连接。

   * **用户操作:**  访问一个高负载的网站。
   * **结果:**  JavaScript 发起的请求可能意外中断。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户在浏览器地址栏输入网址并回车，或者点击网页上的链接。** 这会触发浏览器发起一个网络请求。
2. **如果目标网站支持 HTTP/3 (QUIC)，Chrome 会尝试与服务器建立 QUIC 连接。**
3. **在连接使用过程中，可能发生各种事件导致连接需要关闭：**
   - 服务器发送了 `PUBLIC_RESET` 帧。
   - 连接在一段时间内没有数据传输，触发了空闲超时。
   - 网络环境发生变化，导致连接中断。
   - 发生内部错误。
4. **无论哪种原因导致连接关闭，QUIC 连接层都会调用 `OnConnectionClosed` 方法。**
5. **`OnConnectionClosed` 方法会执行这段代码，记录各种统计信息，通知观察者，并进行清理工作。**
6. **最终，连接关闭的消息会传递到上层，影响 JavaScript 代码的网络请求结果。**

**功能归纳 (第 3 部分):**

这段代码片段是 `QuicChromiumClientSession::OnConnectionClosed` 方法的一部分，其核心功能是在 QUIC 连接关闭时进行详细的统计信息记录、错误处理和资源清理。它收集了连接关闭的各种指标，用于性能分析和问题排查，并通知相关的观察者和工厂类。同时，它也处理了特定类型的连接关闭错误，例如 `PUBLIC_RESET` 和网络空闲超时，并尝试识别网络黑洞等异常情况。这段代码是 QUIC 连接生命周期结束的关键环节，确保了连接关闭时的信息完整性和资源的正确释放。

### 提示词
```
这是目录为net/quic/quic_chromium_client_session.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
{
    UMA_HISTOGRAM_COUNTS_1000(
        "Net.QuicSession.NumForwardProgressMadeAfterPathDegrading",
        connection()->GetStats().num_forward_progress_after_path_degrading);
  }
  if (const quic::QuicConnection::MultiPortStats* multi_port_stats =
          connection()->multi_port_stats()) {
    UMA_HISTOGRAM_COUNTS_1000("Net.QuicMultiPort.NumProbeAttempts",
                              multi_port_stats->num_client_probing_attempts);
    UMA_HISTOGRAM_COUNTS_1000("Net.QuicMultiPort.NumSuccessfulProbes",
                              multi_port_stats->num_successful_probes);
    UMA_HISTOGRAM_COUNTS_1000(
        "Net.QuicMultiPort.NumMultiPortFailureWhenPathNotDegrading",
        multi_port_stats
            ->num_multi_port_probe_failures_when_path_not_degrading);
    size_t total_multi_port_probe_failures =
        multi_port_stats
            ->num_multi_port_probe_failures_when_path_not_degrading +
        multi_port_stats->num_multi_port_probe_failures_when_path_degrading;
    uint64_t srtt_ms =
        multi_port_stats->rtt_stats.smoothed_rtt().ToMilliseconds();
    if (connection()->GetStats().num_path_degrading > 0 &&
        total_multi_port_probe_failures > 0 && srtt_ms > 0) {
      base::UmaHistogramSparse(
          "Net.QuicMultiPort.AltPortRttWhenPathDegradingVsGeneral",
          static_cast<int>(
              multi_port_stats->rtt_stats_when_default_path_degrading
                  .smoothed_rtt()
                  .ToMilliseconds() *
              100 / srtt_ms));
      UMA_HISTOGRAM_COUNTS_1000(
          "Net.QuicMultiPort.NumMultiPortFailureWhenPathDegrading",
          multi_port_stats->num_multi_port_probe_failures_when_path_degrading);
      base::UmaHistogramPercentage(
          "Net.QuicMultiPort.AltPortFailureWhenPathDegradingVsGeneral",
          static_cast<int>(
              multi_port_stats
                  ->num_multi_port_probe_failures_when_path_degrading *
              100 / total_multi_port_probe_failures));
    }
  }

  RecordConnectionCloseErrorCode(frame, source, session_key_.host(),
                                 OneRttKeysAvailable(),
                                 !ech_config_list_.empty());
  if (OneRttKeysAvailable()) {
    handles::NetworkHandle current_network = GetCurrentNetwork();
    for (auto& observer : connectivity_observer_list_) {
      observer.OnSessionClosedAfterHandshake(this, current_network, source,
                                             frame.quic_error_code);
    }
  }

  const quic::QuicErrorCode error = frame.quic_error_code;
  const std::string& error_details = frame.error_details;

  if (source == quic::ConnectionCloseSource::FROM_SELF &&
      error == quic::QUIC_NETWORK_IDLE_TIMEOUT && ShouldKeepConnectionAlive()) {
    quic::QuicStreamCount streams_waiting_to_write = 0;
    PerformActionOnActiveStreams(
        [&streams_waiting_to_write](quic::QuicStream* stream) {
          if (stream->HasBufferedData()) {
            ++streams_waiting_to_write;
          }
          return true;
        });

    UMA_HISTOGRAM_COUNTS_100(
        "Net.QuicSession.NumStreamsWaitingToWriteOnIdleTimeout",
        streams_waiting_to_write);
    UMA_HISTOGRAM_COUNTS_100("Net.QuicSession.NumActiveStreamsOnIdleTimeout",
                             GetNumActiveStreams());
  }

  if (source == quic::ConnectionCloseSource::FROM_PEER) {
    if (error == quic::QUIC_PUBLIC_RESET) {
      // is_from_google_server will be true if the received EPID is
      // kEPIDGoogleFrontEnd or kEPIDGoogleFrontEnd0.
      const bool is_from_google_server =
          error_details.find(base::StringPrintf(
              "From %s", quic::kEPIDGoogleFrontEnd)) != std::string::npos;

      if (OneRttKeysAvailable()) {
        UMA_HISTOGRAM_BOOLEAN(
            "Net.QuicSession.ClosedByPublicReset.HandshakeConfirmed",
            is_from_google_server);
      } else {
        UMA_HISTOGRAM_BOOLEAN("Net.QuicSession.ClosedByPublicReset",
                              is_from_google_server);
      }

      if (is_from_google_server) {
        UMA_HISTOGRAM_COUNTS_100(
            "Net.QuicSession.NumMigrationsExercisedBeforePublicReset",
            packet_readers_.size() - 1);
      }

      base::UmaHistogramSparse(
          "Net.QuicSession.LastSentPacketContentBeforePublicReset",
          connection()
              ->sent_packet_manager()
              .unacked_packets()
              .GetLastPacketContent());

      const quic::QuicTime last_in_flight_packet_sent_time =
          connection()
              ->sent_packet_manager()
              .unacked_packets()
              .GetLastInFlightPacketSentTime();
      const quic::QuicTime handshake_completion_time =
          connection()->GetStats().handshake_completion_time;
      if (last_in_flight_packet_sent_time.IsInitialized() &&
          handshake_completion_time.IsInitialized() &&
          last_in_flight_packet_sent_time >= handshake_completion_time) {
        const quic::QuicTime::Delta delay =
            last_in_flight_packet_sent_time - handshake_completion_time;
        UMA_HISTOGRAM_LONG_TIMES_100(
            "Net.QuicSession."
            "LastInFlightPacketSentTimeFromHandshakeCompletionWithPublicReset",
            base::Milliseconds(delay.ToMilliseconds()));
      }

      UMA_HISTOGRAM_LONG_TIMES_100(
          "Net.QuicSession.ConnectionDurationWithPublicReset",
          tick_clock_->NowTicks() - connect_timing_.connect_end);
    }
    if (OneRttKeysAvailable()) {
      base::HistogramBase* histogram = base::SparseHistogram::FactoryGet(
          "Net.QuicSession.StreamCloseErrorCodeServer.HandshakeConfirmed",
          base::HistogramBase::kUmaTargetedHistogramFlag);
      size_t num_streams = GetNumActiveStreams();
      if (num_streams > 0) {
        histogram->AddCount(error, num_streams);
      }
    }
  } else {
    if (OneRttKeysAvailable()) {
      base::HistogramBase* histogram = base::SparseHistogram::FactoryGet(
          "Net.QuicSession.StreamCloseErrorCodeClient.HandshakeConfirmed",
          base::HistogramBase::kUmaTargetedHistogramFlag);
      size_t num_streams = GetNumActiveStreams();
      if (num_streams > 0) {
        histogram->AddCount(error, num_streams);
      }
    } else {
      if (error == quic::QUIC_HANDSHAKE_TIMEOUT) {
        UMA_HISTOGRAM_BOOLEAN(
            "Net.QuicSession.HandshakeTimeout.PathDegradingDetected",
            connection()->IsPathDegrading());
      }
    }
    if (error == quic::QUIC_TOO_MANY_RTOS) {
      UMA_HISTOGRAM_COUNTS_1000(
          "Net.QuicSession.ClosedByRtoAtClient.ReceivedPacketCount",
          connection()->GetStats().packets_received);
      UMA_HISTOGRAM_COUNTS_1000(
          "Net.QuicSession.ClosedByRtoAtClient.SentPacketCount",
          connection()->GetStats().packets_sent);
      UMA_HISTOGRAM_COUNTS_100(
          "Net.QuicSession."
          "MaxConsecutiveRtoWithForwardProgressAndBlackholeDetected",
          connection()->GetStats().max_consecutive_rto_with_forward_progress);
    }
  }

  if (error == quic::QUIC_NETWORK_IDLE_TIMEOUT) {
    UMA_HISTOGRAM_COUNTS_1M(
        "Net.QuicSession.ConnectionClose.NumOpenStreams.TimedOut",
        GetNumActiveStreams());
    if (OneRttKeysAvailable()) {
      if (GetNumActiveStreams() > 0) {
        UMA_HISTOGRAM_BOOLEAN(
            "Net.QuicSession.TimedOutWithOpenStreams.HasUnackedPackets",
            connection()->sent_packet_manager().HasInFlightPackets());
        UMA_HISTOGRAM_COUNTS_1M(
            "Net.QuicSession.TimedOutWithOpenStreams.ConsecutivePTOCount",
            connection()->sent_packet_manager().GetConsecutivePtoCount());
        base::UmaHistogramSparse(
            "Net.QuicSession.TimedOutWithOpenStreams.LocalPort",
            connection()->self_address().port());
      }
    } else {
      UMA_HISTOGRAM_COUNTS_1M(
          "Net.QuicSession.ConnectionClose.NumOpenStreams.HandshakeTimedOut",
          GetNumActiveStreams());
      UMA_HISTOGRAM_COUNTS_1M(
          "Net.QuicSession.ConnectionClose.NumTotalStreams.HandshakeTimedOut",
          num_total_streams_);
    }
  }

  if (OneRttKeysAvailable()) {
    // QUIC connections should not timeout while there are open streams,
    // since PING frames are sent to prevent timeouts. If, however, the
    // connection timed out with open streams then QUIC traffic has become
    // blackholed. Alternatively, if too many retransmission timeouts occur
    // then QUIC traffic has become blackholed.
    if (session_pool_ && (error == quic::QUIC_TOO_MANY_RTOS ||
                          (error == quic::QUIC_NETWORK_IDLE_TIMEOUT &&
                           GetNumActiveStreams() > 0))) {
      session_pool_->OnBlackholeAfterHandshakeConfirmed(this);
    }
    UMA_HISTOGRAM_COUNTS_100(
        "Net.QuicSession.CryptoRetransmitCount.HandshakeConfirmed",
        connection()->GetStats().crypto_retransmit_count);
    UMA_HISTOGRAM_COUNTS_100(
        "Net.QuicSession.MaxConsecutiveRtoWithForwardProgress",
        connection()->GetStats().max_consecutive_rto_with_forward_progress);
    UMA_HISTOGRAM_COUNTS_1000("Net.QuicSession.NumPingsSent",
                              connection()->GetStats().ping_frames_sent);
    UMA_HISTOGRAM_LONG_TIMES_100(
        "Net.QuicSession.ConnectionDuration",
        tick_clock_->NowTicks() - connect_timing_.connect_end);
    UMA_HISTOGRAM_COUNTS_100("Net.QuicSession.NumMigrations", num_migrations_);

    // KeyUpdates are used in TLS, but we no longer support pre-TLS QUIC.
    DCHECK(connection()->version().UsesTls());
    base::UmaHistogramCounts100("Net.QuicSession.KeyUpdate.PerConnection2",
                                connection()->GetStats().key_update_count);
    base::UmaHistogramCounts100(
        "Net.QuicSession.KeyUpdate.PotentialPeerKeyUpdateAttemptCount",
        connection()->PotentialPeerKeyUpdateAttemptCount());
    if (last_key_update_reason_ != quic::KeyUpdateReason::kInvalid) {
      std::string suffix =
          last_key_update_reason_ == quic::KeyUpdateReason::kRemote ? "Remote"
                                                                    : "Local";
      // These values are persisted to logs. Entries should not be renumbered
      // and numeric values should never be reused.
      enum class KeyUpdateSuccess {
        kInvalid = 0,
        kSuccess = 1,
        kFailedInitial = 2,
        kFailedNonInitial = 3,
        kMaxValue = kFailedNonInitial,
      };
      KeyUpdateSuccess value = KeyUpdateSuccess::kInvalid;
      if (connection()->HaveSentPacketsInCurrentKeyPhaseButNoneAcked()) {
        if (connection()->GetStats().key_update_count >= 2) {
          value = KeyUpdateSuccess::kFailedNonInitial;
        } else {
          value = KeyUpdateSuccess::kFailedInitial;
        }
      } else {
        value = KeyUpdateSuccess::kSuccess;
      }
      base::UmaHistogramEnumeration(
          "Net.QuicSession.KeyUpdate.Success." + suffix, value);
    }
  } else {
    if (error == quic::QUIC_PUBLIC_RESET) {
      RecordHandshakeFailureReason(HANDSHAKE_FAILURE_PUBLIC_RESET);
    } else if (connection()->GetStats().packets_received == 0) {
      RecordHandshakeFailureReason(HANDSHAKE_FAILURE_BLACK_HOLE);
      base::UmaHistogramSparse(
          "Net.QuicSession.ConnectionClose.HandshakeFailureBlackHole.QuicError",
          error);
    } else {
      RecordHandshakeFailureReason(HANDSHAKE_FAILURE_UNKNOWN);
      base::UmaHistogramSparse(
          "Net.QuicSession.ConnectionClose.HandshakeFailureUnknown.QuicError",
          error);
    }
    UMA_HISTOGRAM_COUNTS_100(
        "Net.QuicSession.CryptoRetransmitCount.HandshakeNotConfirmed",
        connection()->GetStats().crypto_retransmit_count);
  }

  base::UmaHistogramCounts1M(
      "Net.QuicSession.UndecryptablePacketsReceivedWithDecrypter",
      connection()->GetStats().num_failed_authentication_packets_received);
  base::UmaHistogramSparse("Net.QuicSession.QuicVersion",
                           connection()->transport_version());
  NotifyFactoryOfSessionGoingAway();
  quic::QuicSession::OnConnectionClosed(frame, source);

  if (!callback_.is_null()) {
    std::move(callback_).Run(ERR_QUIC_PROTOCOL_ERROR);
  }

  bool socket_found_in_writer = false;
  for (auto& packet_reader : packet_readers_) {
    packet_reader->CloseSocket();
    // If a writer exists that was not destroyed when the connection migrated,
    // then that writer may not be notified that its socket has been closed.
    // We know that the writer is a QuicChromiumPacketWriter since the packet
    // writer is set with the same type originally.
    socket_found_in_writer |=
        static_cast<QuicChromiumPacketWriter*>(connection()->writer())
            ->OnSocketClosed(packet_reader->socket());
  }
  CHECK(socket_found_in_writer);
  DCHECK(!HasActiveRequestStreams());
  CloseAllHandles(ERR_UNEXPECTED);
  CancelAllRequests(ERR_CONNECTION_CLOSED);
  NotifyRequestsOfConfirmation(ERR_CONNECTION_CLOSED);
  NotifyFactoryOfSessionClosedLater();
}

void QuicChromiumClientSession::OnSuccessfulVersionNegotiation(
    const quic::ParsedQuicVersion& version) {
  logger_->OnSuccessfulVersionNegotiation(version);
  quic::QuicSpdySession::OnSuccessfulVersionNegotiation(version);
}

int QuicChromiumClientSession::HandleWriteError(
    int error_code,
    scoped_refptr<QuicChromiumPacketWriter::ReusableIOBuffer> packet) {
  current_migration_cause_ = ON_WRITE_ERROR;
  LogHandshakeStatusOnMigrationSignal();

  base::UmaHistogramSparse("Net.QuicSession.WriteError", -error_code);
  if (OneRttKeysAvailable()) {
    base::UmaHistogramSparse("Net.QuicSession.WriteError.HandshakeConfirmed",
                             -error_code);
  }

  // For now, skip reporting if there are multiple packet writers and
  // connection migration is enabled.
  if (packet_readers_.size() == 1u || !migrate_session_early_v2_) {
    handles::NetworkHandle current_network = GetCurrentNetwork();
    for (auto& observer : connectivity_observer_list_) {
      observer.OnSessionEncounteringWriteError(this, current_network,
                                               error_code);
    }
  }

  // Proxied sessions cannot presently encounter write errors, but in case that
  // changes, those sessions should not attempt migration when such an error
  // occurs. The underlying connection to the proxy server may still migrate.
  if (!session_key_.proxy_chain().is_direct()) {
    return error_code;
  }

  if (error_code == ERR_MSG_TOO_BIG || session_pool_ == nullptr ||
      !migrate_session_on_network_change_v2_ || !OneRttKeysAvailable()) {
    return error_code;
  }

  handles::NetworkHandle current_network = GetCurrentNetwork();

  net_log_.AddEventWithInt64Params(
      NetLogEventType::QUIC_CONNECTION_MIGRATION_ON_WRITE_ERROR, "network",
      current_network);

  DCHECK(packet != nullptr);
  DCHECK_NE(ERR_IO_PENDING, error_code);
  DCHECK_GT(0, error_code);
  DCHECK(packet_ == nullptr);

  // Post a task to migrate the session onto a new network.
  task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(
          &QuicChromiumClientSession::MigrateSessionOnWriteError,
          weak_factory_.GetWeakPtr(), error_code,
          // UnsafeDanglingUntriaged triggered by test:
          // QuicSessionPoolTest.MigrateSessionOnSyncWriteErrorPauseBeforeConnected
          // TODO(crbug.com/40061562): Remove `UnsafeDanglingUntriaged`
          base::UnsafeDanglingUntriaged(connection()->writer())));

  ignore_read_error_ = true;

  // Cause the packet writer to return ERR_IO_PENDING and block so
  // that the actual migration happens from the message loop instead
  // of under the call stack of quic::QuicConnection::WritePacket.
  return ERR_IO_PENDING;
}

void QuicChromiumClientSession::MigrateSessionOnWriteError(
    int error_code,
    quic::QuicPacketWriter* writer) {
  DCHECK(migrate_session_on_network_change_v2_);
  // If |writer| is no longer actively in use, or a session migration has
  // started from MigrateNetworkImmediately, abort this migration attempt.
  if (writer != connection()->writer() ||
      pending_migrate_network_immediately_) {
    return;
  }

  most_recent_write_error_timestamp_ = tick_clock_->NowTicks();
  most_recent_write_error_ = error_code;

  if (session_pool_ == nullptr) {
    // Close the connection if migration failed. Do not cause a
    // connection close packet to be sent since socket may be borked.
    connection()->CloseConnection(quic::QUIC_PACKET_WRITE_ERROR,
                                  "Write error with nulled stream factory",
                                  quic::ConnectionCloseBehavior::SILENT_CLOSE);
    return;
  }

  current_migration_cause_ = ON_WRITE_ERROR;

  if (migrate_idle_session_ && CheckIdleTimeExceedsIdleMigrationPeriod()) {
    return;
  }

  if (!migrate_idle_session_ && !HasActiveRequestStreams()) {
    // connection close packet to be sent since socket may be borked.
    connection()->CloseConnection(quic::QUIC_PACKET_WRITE_ERROR,
                                  "Write error for non-migratable session",
                                  quic::ConnectionCloseBehavior::SILENT_CLOSE);
    return;
  }

  // Do not migrate if connection migration is disabled.
  if (config()->DisableConnectionMigration()) {
    HistogramAndLogMigrationFailure(MIGRATION_STATUS_DISABLED_BY_CONFIG,
                                    connection_id(),
                                    "Migration disabled by config");
    // Close the connection since migration was disabled. Do not cause a
    // connection close packet to be sent since socket may be borked.
    connection()->CloseConnection(quic::QUIC_PACKET_WRITE_ERROR,
                                  "Write error for non-migratable session",
                                  quic::ConnectionCloseBehavior::SILENT_CLOSE);
    return;
  }

  handles::NetworkHandle new_network =
      session_pool_->FindAlternateNetwork(GetCurrentNetwork());
  if (new_network == handles::kInvalidNetworkHandle) {
    // No alternate network found.
    HistogramAndLogMigrationFailure(MIGRATION_STATUS_NO_ALTERNATE_NETWORK,
                                    connection_id(),
                                    "No alternate network found");
    OnNoNewNetwork();
    return;
  }

  if (GetCurrentNetwork() == default_network_ &&
      current_migrations_to_non_default_network_on_write_error_ >=
          max_migrations_to_non_default_network_on_write_error_) {
    HistogramAndLogMigrationFailure(
        MIGRATION_STATUS_ON_WRITE_ERROR_DISABLED, connection_id(),
        "Exceeds maximum number of migrations on write error");
    connection()->CloseConnection(
        quic::QUIC_PACKET_WRITE_ERROR,
        "Too many migrations for write error for the same network",
        quic::ConnectionCloseBehavior::SILENT_CLOSE);
    return;
  }
  current_migrations_to_non_default_network_on_write_error_++;

  net_log_.BeginEventWithStringParams(
      NetLogEventType::QUIC_CONNECTION_MIGRATION_TRIGGERED, "trigger",
      "WriteError");
  pending_migrate_session_on_write_error_ = true;
  Migrate(new_network, ToIPEndPoint(connection()->peer_address()),
          /*close_session_on_error=*/false,
          base::BindOnce(
              &QuicChromiumClientSession::FinishMigrateSessionOnWriteError,
              weak_factory_.GetWeakPtr(), new_network));
  net_log_.EndEvent(NetLogEventType::QUIC_CONNECTION_MIGRATION_TRIGGERED);
}

void QuicChromiumClientSession::FinishMigrateSessionOnWriteError(
    handles::NetworkHandle new_network,
    MigrationResult result) {
  pending_migrate_session_on_write_error_ = false;
  if (result == MigrationResult::FAILURE) {
    // Close the connection if migration failed. Do not cause a
    // connection close packet to be sent since socket may be borked.
    connection()->CloseConnection(quic::QUIC_PACKET_WRITE_ERROR,
                                  "Write and subsequent migration failed",
                                  quic::ConnectionCloseBehavior::SILENT_CLOSE);
    return;
  }
  if (new_network != default_network_) {
    StartMigrateBackToDefaultNetworkTimer(
        base::Seconds(kMinRetryTimeForDefaultNetworkSecs));
  } else {
    CancelMigrateBackToDefaultNetworkTimer();
  }
}

void QuicChromiumClientSession::OnNoNewNetwork() {
  DCHECK(OneRttKeysAvailable());
  wait_for_new_network_ = true;
  net_log_.AddEvent(
      NetLogEventType::QUIC_CONNECTION_MIGRATION_WAITING_FOR_NEW_NETWORK);

  DVLOG(1) << "Force blocking the packet writer";
  // Force blocking the packet writer to avoid any writes since there is no
  // alternate network available.
  static_cast<QuicChromiumPacketWriter*>(connection()->writer())
      ->set_force_write_blocked(true);

  if (base::FeatureList::IsEnabled(features::kDisableBlackholeOnNoNewNetwork)) {
    // Turn off the black hole detector since the writer is blocked.
    // Blackhole will be re-enabled once a packet is sent again.
    connection()->blackhole_detector().StopDetection(false);
  }

  // Post a task to maybe close the session if the alarm fires.
  task_runner_->PostDelayedTask(
      FROM_HERE,
      base::BindOnce(&QuicChromiumClientSession::OnMigrationTimeout,
                     weak_factory_.GetWeakPtr(), packet_readers_.size()),
      base::Seconds(kWaitTimeForNewNetworkSecs));
}

void QuicChromiumClientSession::WriteToNewSocket() {
  // Set |send_packet_after_migration_| to true so that a packet will be
  // sent when the writer becomes unblocked.
  send_packet_after_migration_ = true;

  DVLOG(1) << "Cancel force blocking the packet writer";
  // Notify writer that it is no longer forced blocked, which may call
  // OnWriteUnblocked() if the writer has no write in progress.
  static_cast<QuicChromiumPacketWriter*>(connection()->writer())
      ->set_force_write_blocked(false);
}

void QuicChromiumClientSession::OnMigrationTimeout(size_t num_sockets) {
  // If number of sockets has changed, this migration task is stale.
  if (num_sockets != packet_readers_.size()) {
    return;
  }

  net_log_.AddEvent(
      NetLogEventType::QUIC_CONNECTION_MIGRATION_FAILURE_WAITING_FOR_NETWORK);

  int net_error = current_migration_cause_ == ON_NETWORK_DISCONNECTED
                      ? ERR_INTERNET_DISCONNECTED
                      : ERR_NETWORK_CHANGED;

  // |current_migration_cause_| will be reset after logging.
  LogMigrationResultToHistogram(MIGRATION_STATUS_TIMEOUT);

  CloseSessionOnError(net_error, quic::QUIC_CONNECTION_MIGRATION_NO_NEW_NETWORK,
                      quic::ConnectionCloseBehavior::SILENT_CLOSE);
}

void QuicChromiumClientSession::OnPortMigrationProbeSucceeded(
    handles::NetworkHandle network,
    const quic::QuicSocketAddress& peer_address,
    const quic::QuicSocketAddress& self_address,
    std::unique_ptr<QuicChromiumPacketWriter> writer,
    std::unique_ptr<QuicChromiumPacketReader> reader) {
  DCHECK(writer);
  DCHECK(reader);

  // Writer must be destroyed before reader, since it points to the socket owned
  // by reader. C++ doesn't have any guarantees about destruction order of
  // arguments.
  std::unique_ptr<QuicChromiumPacketWriter> writer_moved = std::move(writer);

  net_log_.AddEvent(NetLogEventType::QUIC_SESSION_CONNECTIVITY_PROBING_FINISHED,
                    [&] {
                      return NetLogProbingResultParams(network, &peer_address,
                                                       /*is_success=*/true);
                    });

  LogProbeResultToHistogram(current_migration_cause_, true);

  // Remove |this| as the old packet writer's delegate. Write error on old
  // writers will be ignored.
  // Set |this| to listen on socket write events on the packet writer
  // that was used for probing.
  static_cast<QuicChromiumPacketWriter*>(connection()->writer())
      ->set_delegate(nullptr);
  writer_moved->set_delegate(this);

  if (!migrate_idle_session_ && !HasActiveRequestStreams()) {
    // If idle sessions won't be migrated, close the connection.
    CloseSessionOnErrorLater(
        ERR_NETWORK_CHANGED,
        quic::QUIC_CONNECTION_MIGRATION_NO_MIGRATABLE_STREAMS,
        quic::ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
    return;
  }

  if (migrate_idle_session_ && CheckIdleTimeExceedsIdleMigrationPeriod()) {
    return;
  }

  // Migrate to the probed socket immediately: socket, writer and reader will
  // be acquired by connection and used as default on success.
  if (!MigrateToSocket(self_address, peer_address, std::move(reader),
                       std::move(writer_moved))) {
    LogMigrateToSocketStatus(false);
    net_log_.AddEvent(
        NetLogEventType::QUIC_CONNECTION_MIGRATION_FAILURE_AFTER_PROBING);
    return;
  }

  LogMigrateToSocketStatus(true);

  num_migrations_++;
  HistogramAndLogMigrationSuccess(connection_id());
}

void QuicChromiumClientSession::OnConnectionMigrationProbeSucceeded(
    handles::NetworkHandle network,
    const quic::QuicSocketAddress& peer_address,
    const quic::QuicSocketAddress& self_address,
    std::unique_ptr<QuicChromiumPacketWriter> writer,
    std::unique_ptr<QuicChromiumPacketReader> reader) {
  DCHECK(writer);
  DCHECK(reader);

  // Writer must be destroyed before reader, since it points to the socket owned
  // by reader. C++ doesn't have any guarantees about destruction order of
  // arguments.
  std::unique_ptr<QuicChromiumPacketWriter> writer_moved = std::move(writer);

  net_log_.AddEvent(NetLogEventType::QUIC_SESSION_CONNECTIVITY_PROBING_FINISHED,
                    [&] {
                      return NetLogProbingResultParams(network, &peer_address,
                                                       /*is_success=*/true);
                    });
  if (network == handles::kInvalidNetworkHandle) {
    return;
  }

  LogProbeResultToHistogram(current_migration_cause_, true);

  // Remove |this| as the old packet writer's delegate. Write error on old
  // writers will be ignored.
  // Set |this| to listen on socket write events on the packet writer
  // that was used for probing.
  static_cast<QuicChromiumPacketWriter*>(connection()->writer())
      ->set_delegate(nullptr);
  writer_moved->set_delegate(this);

  // Close streams that are not migratable to the probed |network|.
  ResetNonMigratableStreams();

  if (!migrate_idle_session_ && !HasActiveRequestStreams()) {
    // If idle sessions won't be migrated, close the connection.
    CloseSessionOnErrorLater(
        ERR_NETWORK_CHANGED,
        quic::QUIC_CONNECTION_MIGRATION_NO_MIGRATABLE_STREAMS,
        quic::ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
    return;
  }

  if (migrate_idle_session_ && CheckIdleTimeExceedsIdleMigrationPeriod()) {
    return;
  }

  // Migrate to the probed socket immediately: socket, writer and reader will
  // be acquired by connection and used as default on success.
  if (!MigrateToSocket(self_address, peer_address, std::move(reader),
                       std::move(writer_moved))) {
    LogMigrateToSocketStatus(false);
    net_log_.AddEvent(
        NetLogEventType::QUIC_CONNECTION_MIGRATION_FAILURE_AFTER_PROBING);
    return;
  }

  LogMigrateToSocketStatus(true);

  net_log_.AddEventWithInt64Params(
      NetLogEventType::QUIC_CONNECTION_MIGRATION_SUCCESS_AFTER_PROBING,
      "migrate_to_network", network);
  num_migrations_++;
  HistogramAndLogMigrationSuccess(connection_id());
  if (network == default_network_) {
    DVLOG(1) << "Client successfully migrated to default network: "
             << default_network_;
    CancelMigrateBackToDefaultNetworkTimer();
    return;
  }

  DVLOG(1) << "Client successfully got off default network after "
           << "successful probing network: " << network << ".";
  current_migrations_to_non_default_network_on_path_degrading_++;
  if (!migrate_back_to_default_timer_.IsRunning()) {
    current_migration_cause_ = ON_MIGRATE_BACK_TO_DEFAULT_NETWORK;
    // Session gets off the |default_network|, stay on |network| for now but
    // try to migrate back to default network after 1 second.
    StartMigrateBackToDefaultNetworkTimer(
        base::Seconds(kMinRetryTimeForDefaultNetworkSecs));
  }
}

void QuicChromiumClientSession::OnServerPreferredAddressProbeSucceeded(
    handles::NetworkHandle network,
    const quic::QuicSocketAddress& peer_address,
    const quic::QuicSocketAddress& self_address,
    std::unique_ptr<QuicChromiumPacketWriter> writer,
    std::unique_ptr<QuicChromiumPacketReader> reader) {
  // Writer must be destroyed before reader, since it points to the socket owned
  // by reader. C++ doesn't have any guarantees about destruction order of
  // arguments.
  std::unique_ptr<QuicChromiumPacketWriter> writer_moved = std::move(writer);

  net_log_.AddEvent(NetLogEventType::QUIC_SESSION_CONNECTIVITY_PROBING_FINISHED,
                    [&] {
                      return NetLogProbingResultParams(network, &peer_address,
                                                       /*is_success=*/true);
                    });

  LogProbeResultToHistogram(current_migration_cause_, true);
  connection()->mutable_stats().server_preferred_address_validated = true;

  // Remove |this| as the old packet writer's delegate. Write error on old
  // writers will be ignored.
  // Set |this| to listen on socket write events on the packet writer
  // that was used for probing.
  static_cast<QuicChromiumPacketWriter*>(connection()->writer())
      ->set_delegate(nullptr);
  writer_moved->set_delegate(this);

  // Migrate to the probed socket immediately: socket, writer and reader will
  // be acquired by connection and used as default on success.
  if (!MigrateToSocket(self_address, peer_address, std::move(reader),
                       std::move(writer_moved))) {
    LogMigrateToSocketStatus(false);
    net_log_.AddEvent(
        NetLogEventType::QUIC_CONNECTION_MIGRATION_FAILURE_AFTER_PROBING);
    return;
  }

  LogMigrateToSocketStatus(true);

  num_migrations_++;
  HistogramAndLogMigrationSuccess(connection_id());
}

void QuicChromiumClientSession::OnProbeFailed(
    handles::NetworkHandle network,
    const quic::QuicSocketAddress& peer_address) {
  net_log_.AddEvent(NetLogEventType::QUIC_SESSION_CONNECTIVITY_PROBING_FINISHED,
                    [&] {
                      return NetLogProbingResultParams(network, &peer_address,
                                                       /*is_success=*/false);
                    });

  LogProbeResultToHistogram(current_migration_cause_, false);

  auto* context = static_cast<QuicChromiumPathValidationContext*>(
      connection()->GetPathValidationContext());

  if (!context) {
    return;
  }

  if (context->network() == network &&
      context->peer_address() == peer_address) {
    connection()->CancelPathValidation();
  }

  if (network != handles::kInvalidNetworkHandle) {
    // Probing failure can be ignored.
    DVLOG(1) << "Connectivity probing failed on <network: " << network
             << ", peer_address: " << peer_address.ToString() << ">.";
    DVLOG_IF(1, network == default_network_ &&
                    GetCurrentNetwork() != default_network_)
        << "Client probing failed on the default network, still using "
           "non-default network.";
  }
}

void QuicChromiumClientSession::OnNetworkConnected(
    handles::NetworkHandle network) {
  if (connection()->IsPathDegrading()) {
    base::TimeDelta duration =
        tick_clock_->NowTicks() - most_recent_path_degrading_timestamp_;
    UMA_HISTOGRAM_CUSTOM_TIMES("Net.QuicNetworkDegradingDurationTillConnected",
                               duration, base::Milliseconds(1),
                               base::Minutes(10), 50);
  }
  net_log_.AddEventWithInt64Params(
      NetLogEventType::QUIC_SESSION_NETWORK_CONNECTED, "connected_network",
      network);
  if (!migrate_session_on_network_change_v2_) {
    return;
  }

  // If there was no migration waiting for new network and the path is not
  // degrading, ignore this signal.
  if (!wait_for_new_network_ && !connection()->IsPathDegrading()) {
    return;
  }

  net_log_.AddEventWithInt64Params(
      NetLogEventType::QUIC_CONNECTION_MIGRATION_ON_NETWORK_CONNECTED,
      "connected_network", network);

  if (connection()->IsPathDegrading()) {
    current_migration_cause_ = NEW_NETWORK_CONNECTED_POST_PATH_DEGRADING;
  }

  if (wait_for_new_network_) {
    wait_for_new_network_ = false;
    net_log_.AddEventWithInt64Params(
        NetLogEventType::QUIC_CONNECTION_MIGRATION_SUCCESS_WAITING_FOR_NETWORK,
        "network", network);
    if (current_migration_cause_ == ON_WRITE_ERROR) {
      current_migrations_to_non_default_network_on_write_error_++;
    }
    // |wait_for_new_network_| is true, there was no working network previously.
    // |network| is now the only possible candidate, migrate immed
```