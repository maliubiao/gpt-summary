Response:
The user wants a summary of the functionality of the provided C++ code snippet from Chromium's network stack. The code is part of `transport_client_socket_pool.cc`. I need to extract the main responsibilities and operations performed by this code section. Specifically, I should focus on what the methods within this snippet do.

Here's a breakdown of the key functionalities present in this snippet:

1. **Socket Group Management:**  The code deals with managing groups of sockets (`Group` objects).
2. **Idle Socket Handling:** It includes logic for cleaning up and closing idle sockets within these groups.
3. **Connection Management:** It handles releasing sockets back to the pool and checking for stalled connection attempts.
4. **Request Processing:** It involves processing pending socket requests and binding them to connection jobs.
5. **Error Handling:** It has mechanisms for handling network changes and flushing socket pools with errors.
6. **Connect Job Management:** It manages the lifecycle of `ConnectJob` objects, including their completion and handling of proxy authentication requests.
7. **Callback Invocation:** It manages the invocation of user callbacks related to socket operations.
8. **Resource Limits:** It checks and enforces limits on the number of sockets.
9. **Backup Connection Jobs:** It includes logic for starting backup connection attempts.

I need to condense these functionalities into a concise summary, noting that this is the second part of a three-part file. This implies that the earlier parts likely handle socket creation and initial request handling, while the later part might deal with more complex connection management scenarios or integration with higher layers.
This代码片段是 `TransportClientSocketPool` 类的实现的一部分，主要负责以下功能：

**核心功能归纳:**

1. **维护和管理 Socket 连接组 (Groups):**
   - 检查和创建 Socket 连接组 (`GetOrCreateGroup`)。
   - 检查是否存在指定的连接组 (`HasGroup`)。
   - 删除不再需要的空连接组 (`RemoveGroup`)。
   - 迭代处理连接组 (`group_map_`)。

2. **清理和关闭空闲 (Idle) 的 Socket 连接:**
   - 提供强制或基于超时时间的清理策略 (`CleanupIdleSockets`, `CleanupIdleSocketsInGroup`)。
   - 维护空闲 Socket 计数 (`idle_socket_count_`)。
   - 可以选择关闭一个空闲 Socket (`CloseOneIdleSocket`).
   - 可以请求更上层的连接池关闭空闲连接 (`CloseOneIdleConnectionInHigherLayeredPool`).
   - 根据 Socket 的使用状态 (是否曾经被使用) 应用不同的空闲超时时间。
   - 记录 Socket 关闭的原因到 NetLog。

3. **处理 Socket 连接的释放 (Release):**
   - 将不再使用的 Socket 连接放回连接池 (`ReleaseSocket`)。
   - 决定 Socket 是否可以被复用，并根据不同的情况（连接已关闭、收到意外数据、连接代数过期）选择关闭 Socket 或将其加入空闲列表。
   - 更新连接组的活跃 Socket 计数 (`handed_out_socket_count_`, `active_socket_count_`)。

4. **检查和处理停滞 (Stalled) 的 Socket 连接组:**
   - 当有空闲 Socket 可用时，尝试分配给优先级最高的停滞连接组 (`CheckForStalledSocketGroups`)。
   - 查找优先级最高的停滞连接组 (`FindTopStalledGroup`)。
   - 当达到最大 Socket 连接数限制时，尝试关闭一个空闲 Socket 来释放资源。

5. **处理 IP 地址变更:**
   - 当 IP 地址变更时，刷新连接池，断开所有连接并取消所有请求 (`OnIPAddressChanged`, `FlushWithError`)。

6. **管理 ConnectJob (连接任务):**
   - 移除完成或取消的连接任务 (`RemoveConnectJob`)。
   - 当有可用的 Socket 连接槽位时，处理等待中的请求 (`OnAvailableSocketSlot`, `ProcessPendingRequest`)。
   - 绑定连接任务到请求 (`BindRequestToConnectJob`，在代码的最后一部分）。

7. **Socket 连接的交付 (Hand Out):**
   - 将建立好的 Socket 连接交付给请求处理程序 (`HandOutSocket`)。
   - 设置 Socket 连接的复用类型、空闲时间、连接时序信息等。

8. **添加空闲 Socket:**
   - 将可复用的 Socket 连接添加到连接组的空闲列表 (`AddIdleSocket`)。

9. **取消所有连接任务和请求:**
   - 取消所有正在进行的连接任务 (`CancelAllConnectJobs`)。
   - 取消所有等待中的请求，并通知用户回调 (`CancelAllRequestsWithError`)。

10. **限制 Socket 连接数量:**
    - 检查是否已达到最大 Socket 连接数限制 (`ReachedMaxSocketsLimit`)。
    - 可以选择关闭一个非指定组的空闲 Socket (`CloseOneIdleSocketExceptInGroup`)。

11. **处理 ConnectJob 的完成:**
    - 当连接任务完成时，根据结果将 Socket 连接交付给请求，或将 Socket 加入空闲列表 (`OnConnectJobComplete`)。
    - 处理连接被上层池持有的情况。

12. **处理代理认证请求:**
    - 当需要代理认证时，调用请求的回调函数 (`OnNeedsProxyAuth`) （在代码的最后一部分）。

13. **延迟调用用户回调:**
    - 使用 `InvokeUserCallbackLater` 和 `InvokeUserCallback` 来确保用户回调在适当的时机被调用，避免并发问题。

14. **尝试关闭上层连接池的 Socket:**
    - 当当前连接池停滞时，尝试请求上层连接池关闭空闲连接 (`TryToCloseSocketsInLayeredPools`)。

15. **刷新连接组:**
    - 强制清理连接组中的空闲连接，取消所有未绑定的连接任务，并增加连接组的代数以防止复用 (`RefreshGroup`)。

**与 JavaScript 的关系 (可能存在间接关系):**

虽然这段 C++ 代码直接运行在 Chromium 的网络层，不直接与 JavaScript 交互，但它所管理和维护的 Socket 连接是 JavaScript 发起的网络请求的基础。

**举例说明:**

假设一个网页中的 JavaScript 代码发起了一个 HTTP 请求：

```javascript
fetch('https://example.com/data')
  .then(response => response.json())
  .then(data => console.log(data));
```

当这个请求发送到 Chromium 的网络栈时，`TransportClientSocketPool` 负责管理和复用与 `example.com` 建立的 TCP 连接。

- 当请求首次发起时，如果连接池中没有可用的连接，`TransportClientSocketPool` 会创建一个新的 `ConnectJob` 来建立连接。
- 如果之后 JavaScript 又发起了对 `example.com` 的请求，并且之前的连接还处于空闲状态，`TransportClientSocketPool` 可能会复用之前的连接，从而提高性能。
- 如果连接长时间处于空闲状态，`CleanupIdleSockets` 可能会关闭这个连接。
- 如果网络环境发生变化（例如 IP 地址变更），`OnIPAddressChanged` 会清理相关的连接。

**逻辑推理的假设输入与输出:**

**假设输入:**

- `group_id`: 一个用于标识连接组的唯一标识符，例如目标服务器的地址和端口。
- `socket`: 一个表示已建立的 TCP 连接的 `StreamSocket` 对象。
- `group_generation`: 连接组的代数，用于判断 Socket 是否属于当前连接组。
- `force`: 一个布尔值，指示是否强制清理空闲 Socket。
- `now`: 当前时间。

**输出:**

- `HasGroup(group_id)`: 如果存在指定 `group_id` 的连接组，则返回 `true`，否则返回 `false`。
- `CleanupIdleSockets(force, ...)`: 根据 `force` 的值，清理并可能关闭连接池中的空闲 Socket。
- `ReleaseSocket(group_id, socket, group_generation)`: 如果 Socket 可以复用，则将其添加到对应连接组的空闲列表；否则，关闭 Socket 并可能删除空的连接组。

**用户或编程常见的使用错误:**

1. **连接泄漏:** 如果 Socket 连接在使用完毕后没有正确地 `ReleaseSocket` 回到连接池，可能会导致连接数不断增加，最终耗尽资源。
2. **不合理的空闲超时时间配置:** 如果空闲超时时间设置得过短，可能会导致频繁地建立和关闭连接，降低性能。如果设置得过长，可能会占用不必要的资源。
3. **在高并发场景下超出连接数限制:** 如果用户发起大量并发请求，可能会超出 `max_sockets_` 的限制，导致请求被阻塞。
4. **对 Socket 的错误操作:**  用户代码不应该直接操作从连接池获取的 `StreamSocket` 对象，而应该通过 `ClientSocketHandle` 进行操作，否则可能导致连接池状态不一致。

**用户操作到达这里的调试线索:**

用户通常不会直接触发 `TransportClientSocketPool` 的代码，而是通过浏览器或应用程序的网络请求间接地触发。以下是一些可能的调试线索：

1. **网络请求失败或延迟:** 当用户访问网页或应用程序，并且网络请求失败、超时或非常缓慢时，可能是连接池遇到了问题。
2. **大量的 TCP 连接:** 使用网络监控工具（如 Wireshark 或 Chrome 的 `chrome://net-internals/#sockets`）观察到大量的 TCP 连接被建立或处于 `IDLE` 状态，可能表明连接池的行为异常。
3. **连接被意外关闭:** 用户在浏览过程中遇到连接中断或页面加载失败，可能是连接池过早地关闭了连接。
4. **内存占用过高:**  如果连接池管理不当，可能会导致内存占用过高。
5. **开发者工具的网络面板:** 查看 Chrome 开发者工具的网络面板，可以了解请求的状态、耗时以及是否复用了连接，这可以帮助定位连接池相关的问题。
6. **`chrome://net-internals/#events`:**  这个页面记录了 Chromium 网络栈的详细事件，可以用来跟踪 Socket 连接的创建、复用、释放和关闭等过程，从而深入了解 `TransportClientSocketPool` 的行为。

**总结 (本部分功能):**

这段代码主要负责**管理和维护传输层的 Socket 连接池**。它实现了连接的创建、复用、空闲清理、释放以及处理连接错误和网络状态变化等关键功能。其目标是高效地管理底层的 TCP 连接，为上层的 HTTP 请求等提供可靠的连接基础，并尽可能地复用连接以提高性能和减少资源消耗。

### 提示词
```
这是目录为net/socket/transport_client_socket_pool.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
without an assigned ConnectJob.
    CheckForStalledSocketGroups();
  }
}

bool TransportClientSocketPool::HasGroup(const GroupId& group_id) const {
  return base::Contains(group_map_, group_id);
}

void TransportClientSocketPool::CleanupIdleSockets(
    bool force,
    const char* net_log_reason_utf8) {
  if (idle_socket_count_ == 0)
    return;

  // Current time value. Retrieving it once at the function start rather than
  // inside the inner loop, since it shouldn't change by any meaningful amount.
  base::TimeTicks now = base::TimeTicks::Now();

  for (auto i = group_map_.begin(); i != group_map_.end();) {
    Group* group = i->second;
    CHECK(group);
    CleanupIdleSocketsInGroup(force, group, now, net_log_reason_utf8);
    // Delete group if no longer needed.
    if (group->IsEmpty()) {
      i = RemoveGroup(i);
    } else {
      ++i;
    }
  }
}

bool TransportClientSocketPool::CloseOneIdleSocket() {
  if (idle_socket_count_ == 0)
    return false;
  return CloseOneIdleSocketExceptInGroup(nullptr);
}

bool TransportClientSocketPool::CloseOneIdleConnectionInHigherLayeredPool() {
  // This pool doesn't have any idle sockets. It's possible that a pool at a
  // higher layer is holding one of this sockets active, but it's actually idle.
  // Query the higher layers.
  for (HigherLayeredPool* higher_pool : higher_pools_) {
    if (higher_pool->CloseOneIdleConnection())
      return true;
  }
  return false;
}

void TransportClientSocketPool::CleanupIdleSocketsInGroup(
    bool force,
    Group* group,
    const base::TimeTicks& now,
    const char* net_log_reason_utf8) {
  // If |force| is true, a reason must be provided.
  DCHECK(!force || net_log_reason_utf8);

  auto idle_socket_it = group->mutable_idle_sockets()->begin();
  while (idle_socket_it != group->idle_sockets().end()) {
    bool should_clean_up = force;
    const char* reason_for_closing_socket = net_log_reason_utf8;
    base::TimeDelta timeout = idle_socket_it->socket->WasEverUsed()
                                  ? used_idle_socket_timeout_
                                  : unused_idle_socket_timeout_;

    // Timeout errors take precedence over the reason for flushing sockets in
    // the group, if applicable.
    if (now - idle_socket_it->start_time >= timeout) {
      should_clean_up = true;
      reason_for_closing_socket = kIdleTimeLimitExpired;
    }

    // Usability errors take precedence over over other errors.
    if (!idle_socket_it->IsUsable(&reason_for_closing_socket))
      should_clean_up = true;

    if (should_clean_up) {
      DCHECK(reason_for_closing_socket);
      idle_socket_it->socket->NetLog().AddEventWithStringParams(
          NetLogEventType::SOCKET_POOL_CLOSING_SOCKET, "reason",
          reason_for_closing_socket);
      idle_socket_it = group->mutable_idle_sockets()->erase(idle_socket_it);
      DecrementIdleCount();
    } else {
      DCHECK(!reason_for_closing_socket);
      ++idle_socket_it;
    }
  }
}

TransportClientSocketPool::Group* TransportClientSocketPool::GetOrCreateGroup(
    const GroupId& group_id) {
  auto it = group_map_.find(group_id);
  if (it != group_map_.end())
    return it->second;
  Group* group = new Group(group_id, this);
  group_map_[group_id] = group;
  return group;
}

void TransportClientSocketPool::RemoveGroup(const GroupId& group_id) {
  auto it = group_map_.find(group_id);
  CHECK(it != group_map_.end());

  RemoveGroup(it);
}

TransportClientSocketPool::GroupMap::iterator
TransportClientSocketPool::RemoveGroup(GroupMap::iterator it) {
  delete it->second;
  return group_map_.erase(it);
}

// static
bool TransportClientSocketPool::connect_backup_jobs_enabled() {
  return g_connect_backup_jobs_enabled;
}

// static
bool TransportClientSocketPool::set_connect_backup_jobs_enabled(bool enabled) {
  bool old_value = g_connect_backup_jobs_enabled;
  g_connect_backup_jobs_enabled = enabled;
  return old_value;
}

void TransportClientSocketPool::IncrementIdleCount() {
  ++idle_socket_count_;
}

void TransportClientSocketPool::DecrementIdleCount() {
  --idle_socket_count_;
}

void TransportClientSocketPool::ReleaseSocket(
    const GroupId& group_id,
    std::unique_ptr<StreamSocket> socket,
    int64_t group_generation) {
  auto i = group_map_.find(group_id);
  CHECK(i != group_map_.end());

  Group* group = i->second;
  CHECK(group);

  CHECK_GT(handed_out_socket_count_, 0);
  handed_out_socket_count_--;

  CHECK_GT(group->active_socket_count(), 0);
  group->DecrementActiveSocketCount();

  bool can_resuse_socket = false;
  std::string_view not_reusable_reason;
  if (!socket->IsConnectedAndIdle()) {
    if (!socket->IsConnected()) {
      not_reusable_reason = kClosedConnectionReturnedToPool;
    } else {
      not_reusable_reason = kDataReceivedUnexpectedly;
    }
  } else if (group_generation != group->generation()) {
    not_reusable_reason = kSocketGenerationOutOfDate;
  } else {
    can_resuse_socket = true;
  }

  if (can_resuse_socket) {
    DCHECK(not_reusable_reason.empty());

    // Add it to the idle list.
    AddIdleSocket(std::move(socket), group);
    OnAvailableSocketSlot(group_id, group);
  } else {
    DCHECK(!not_reusable_reason.empty());

    socket->NetLog().AddEventWithStringParams(
        NetLogEventType::SOCKET_POOL_CLOSING_SOCKET, "reason",
        not_reusable_reason);
    if (group->IsEmpty())
      RemoveGroup(i);
    socket.reset();
  }

  CheckForStalledSocketGroups();
}

void TransportClientSocketPool::CheckForStalledSocketGroups() {
  // Loop until there's nothing more to do.
  while (true) {
    // If we have idle sockets, see if we can give one to the top-stalled group.
    Group* top_group = nullptr;
    GroupId top_group_id;
    if (!FindTopStalledGroup(&top_group, &top_group_id))
      return;

    if (ReachedMaxSocketsLimit()) {
      if (idle_socket_count_ > 0) {
        CloseOneIdleSocket();
      } else {
        // We can't activate more sockets since we're already at our global
        // limit.
        return;
      }
    }

    // Note that this may delete top_group.
    OnAvailableSocketSlot(top_group_id, top_group);
  }
}

// Search for the highest priority pending request, amongst the groups that
// are not at the |max_sockets_per_group_| limit. Note: for requests with
// the same priority, the winner is based on group hash ordering (and not
// insertion order).
bool TransportClientSocketPool::FindTopStalledGroup(Group** group,
                                                    GroupId* group_id) const {
  CHECK(group);
  CHECK(group_id);
  Group* top_group = nullptr;
  const GroupId* top_group_id = nullptr;
  bool has_stalled_group = false;
  for (const auto& it : group_map_) {
    Group* curr_group = it.second;
    if (!curr_group->has_unbound_requests())
      continue;
    if (curr_group->CanUseAdditionalSocketSlot(max_sockets_per_group_)) {
      has_stalled_group = true;
      bool has_higher_priority =
          !top_group ||
          curr_group->TopPendingPriority() > top_group->TopPendingPriority();
      if (has_higher_priority) {
        top_group = curr_group;
        top_group_id = &it.first;
      }
    }
  }

  if (top_group) {
    *group = top_group;
    *group_id = *top_group_id;
  } else {
    CHECK(!has_stalled_group);
  }
  return has_stalled_group;
}

void TransportClientSocketPool::OnIPAddressChanged() {
  DCHECK(cleanup_on_ip_address_change_);
  FlushWithError(ERR_NETWORK_CHANGED, kNetworkChanged);
}

void TransportClientSocketPool::FlushWithError(
    int error,
    const char* net_log_reason_utf8) {
  CancelAllConnectJobs();
  CloseIdleSockets(net_log_reason_utf8);
  CancelAllRequestsWithError(error);
  for (const auto& group : group_map_) {
    group.second->IncrementGeneration();
  }
}

void TransportClientSocketPool::RemoveConnectJob(ConnectJob* job,
                                                 Group* group) {
  CHECK_GT(connecting_socket_count_, 0);
  connecting_socket_count_--;

  DCHECK(group);
  group->RemoveUnboundJob(job);
}

void TransportClientSocketPool::OnAvailableSocketSlot(const GroupId& group_id,
                                                      Group* group) {
  DCHECK(base::Contains(group_map_, group_id));
  if (group->IsEmpty()) {
    RemoveGroup(group_id);
  } else if (group->has_unbound_requests()) {
    ProcessPendingRequest(group_id, group);
  }
}

void TransportClientSocketPool::ProcessPendingRequest(const GroupId& group_id,
                                                      Group* group) {
  const Request* next_request = group->GetNextUnboundRequest();
  DCHECK(next_request);

  // If the group has no idle sockets, and can't make use of an additional slot,
  // either because it's at the limit or because it's at the socket per group
  // limit, then there's nothing to do.
  if (group->idle_sockets().empty() &&
      !group->CanUseAdditionalSocketSlot(max_sockets_per_group_)) {
    return;
  }

  int rv =
      RequestSocketInternal(group_id, *next_request,
                            /*preconnect_done_closure=*/base::OnceClosure());
  if (rv != ERR_IO_PENDING) {
    std::unique_ptr<Request> request = group->PopNextUnboundRequest();
    DCHECK(request);
    if (group->IsEmpty())
      RemoveGroup(group_id);

    request->net_log().EndEventWithNetErrorCode(NetLogEventType::SOCKET_POOL,
                                                rv);
    InvokeUserCallbackLater(request->handle(), request->release_callback(), rv,
                            request->socket_tag());
  }
}

void TransportClientSocketPool::HandOutSocket(
    std::unique_ptr<StreamSocket> socket,
    ClientSocketHandle::SocketReuseType reuse_type,
    const LoadTimingInfo::ConnectTiming& connect_timing,
    ClientSocketHandle* handle,
    base::TimeDelta idle_time,
    Group* group,
    const NetLogWithSource& net_log) {
  DCHECK(socket);
  handle->SetSocket(std::move(socket));
  handle->set_reuse_type(reuse_type);
  handle->set_idle_time(idle_time);
  handle->set_group_generation(group->generation());
  handle->set_connect_timing(connect_timing);

  if (reuse_type == StreamSocketHandle::SocketReuseType::kReusedIdle) {
    net_log.AddEventWithIntParams(
        NetLogEventType::SOCKET_POOL_REUSED_AN_EXISTING_SOCKET, "idle_ms",
        static_cast<int>(idle_time.InMilliseconds()));
  }

  net_log.AddEventReferencingSource(
      NetLogEventType::SOCKET_POOL_BOUND_TO_SOCKET,
      handle->socket()->NetLog().source());

  handed_out_socket_count_++;
  group->IncrementActiveSocketCount();
}

void TransportClientSocketPool::AddIdleSocket(
    std::unique_ptr<StreamSocket> socket,
    Group* group) {
  DCHECK(socket);
  IdleSocket idle_socket;
  idle_socket.socket = std::move(socket);
  idle_socket.start_time = base::TimeTicks::Now();

  group->mutable_idle_sockets()->push_back(std::move(idle_socket));
  IncrementIdleCount();
}

void TransportClientSocketPool::CancelAllConnectJobs() {
  for (auto i = group_map_.begin(); i != group_map_.end();) {
    Group* group = i->second;
    CHECK(group);
    connecting_socket_count_ -= group->jobs().size();
    group->RemoveAllUnboundJobs();

    // Delete group if no longer needed.
    if (group->IsEmpty()) {
      i = RemoveGroup(i);
    } else {
      ++i;
    }
  }
}

void TransportClientSocketPool::CancelAllRequestsWithError(int error) {
  for (auto i = group_map_.begin(); i != group_map_.end();) {
    Group* group = i->second;
    CHECK(group);

    while (true) {
      std::unique_ptr<Request> request = group->PopNextUnboundRequest();
      if (!request)
        break;
      InvokeUserCallbackLater(request->handle(), request->release_callback(),
                              error, request->socket_tag());
    }

    // Mark bound connect jobs as needing to fail. Can't fail them immediately
    // because they may have access to objects owned by the ConnectJob, and
    // could access them if a user callback invocation is queued. It would also
    // result in the consumer handling two messages at once, which in general
    // isn't safe for a lot of code.
    group->SetPendingErrorForAllBoundRequests(error);

    // Delete group if no longer needed.
    if (group->IsEmpty()) {
      i = RemoveGroup(i);
    } else {
      ++i;
    }
  }
}

bool TransportClientSocketPool::ReachedMaxSocketsLimit() const {
  // Each connecting socket will eventually connect and be handed out.
  int total =
      handed_out_socket_count_ + connecting_socket_count_ + idle_socket_count_;
  // There can be more sockets than the limit since some requests can ignore
  // the limit
  if (total < max_sockets_)
    return false;
  return true;
}

bool TransportClientSocketPool::CloseOneIdleSocketExceptInGroup(
    const Group* exception_group) {
  CHECK_GT(idle_socket_count_, 0);

  for (auto i = group_map_.begin(); i != group_map_.end(); ++i) {
    Group* group = i->second;
    CHECK(group);
    if (exception_group == group)
      continue;
    std::list<IdleSocket>* idle_sockets = group->mutable_idle_sockets();

    if (!idle_sockets->empty()) {
      idle_sockets->pop_front();
      DecrementIdleCount();
      if (group->IsEmpty())
        RemoveGroup(i);

      return true;
    }
  }

  return false;
}

void TransportClientSocketPool::OnConnectJobComplete(Group* group,
                                                     int result,
                                                     ConnectJob* job) {
  DCHECK_NE(ERR_IO_PENDING, result);
  DCHECK(group_map_.find(group->group_id()) != group_map_.end());
  DCHECK_EQ(group, group_map_[group->group_id()]);
  DCHECK(result != OK || job->socket() != nullptr);

  // Check if the ConnectJob is already bound to a Request. If so, result is
  // returned to that specific request.
  std::optional<Group::BoundRequest> bound_request =
      group->FindAndRemoveBoundRequestForConnectJob(job);
  Request* request = nullptr;
  std::unique_ptr<Request> owned_request;
  if (bound_request) {
    --connecting_socket_count_;

    // If the socket pools were previously flushed with an error, return that
    // error to the bound request and discard the socket.
    if (bound_request->pending_error != OK) {
      InvokeUserCallbackLater(bound_request->request->handle(),
                              bound_request->request->release_callback(),
                              bound_request->pending_error,
                              bound_request->request->socket_tag());
      bound_request->request->net_log().EndEventWithNetErrorCode(
          NetLogEventType::SOCKET_POOL, bound_request->pending_error);
      OnAvailableSocketSlot(group->group_id(), group);
      CheckForStalledSocketGroups();
      return;
    }

    // If the ConnectJob is from a previous generation, add the request back to
    // the group, and kick off another request. The socket will be discarded.
    if (bound_request->generation != group->generation()) {
      group->InsertUnboundRequest(std::move(bound_request->request));
      OnAvailableSocketSlot(group->group_id(), group);
      CheckForStalledSocketGroups();
      return;
    }

    request = bound_request->request.get();
  } else {
    // In this case, RemoveConnectJob(job, _) must be called before exiting this
    // method. Otherwise, |job| will be leaked.
    owned_request = group->PopNextUnboundRequest();
    request = owned_request.get();

    if (!request) {
      if (result == OK)
        AddIdleSocket(job->PassSocket(), group);
      RemoveConnectJob(job, group);
      OnAvailableSocketSlot(group->group_id(), group);
      CheckForStalledSocketGroups();
      return;
    }

    LogBoundConnectJobToRequest(job->net_log().source(), *request);
  }

  // The case where there's no request is handled above.
  DCHECK(request);

  if (result != OK)
    request->handle()->SetAdditionalErrorState(job);
  if (job->socket()) {
    HandOutSocket(job->PassSocket(),
                  StreamSocketHandle::SocketReuseType::kUnused,
                  job->connect_timing(), request->handle(), base::TimeDelta(),
                  group, request->net_log());
  }
  request->net_log().EndEventWithNetErrorCode(NetLogEventType::SOCKET_POOL,
                                              result);
  InvokeUserCallbackLater(request->handle(), request->release_callback(),
                          result, request->socket_tag());
  if (!bound_request)
    RemoveConnectJob(job, group);
  // If no socket was handed out, there's a new socket slot available.
  if (!request->handle()->socket()) {
    OnAvailableSocketSlot(group->group_id(), group);
    CheckForStalledSocketGroups();
  }
}

void TransportClientSocketPool::OnNeedsProxyAuth(
    Group* group,
    const HttpResponseInfo& response,
    HttpAuthController* auth_controller,
    base::OnceClosure restart_with_auth_callback,
    ConnectJob* job) {
  DCHECK(group_map_.find(group->group_id()) != group_map_.end());
  DCHECK_EQ(group, group_map_[group->group_id()]);

  const Request* request = group->BindRequestToConnectJob(job);
  // If can't bind the ConnectJob to a request, treat this as a ConnectJob
  // failure.
  if (!request) {
    OnConnectJobComplete(group, ERR_PROXY_AUTH_REQUESTED, job);
    return;
  }

  request->proxy_auth_callback().Run(response, auth_controller,
                                     std::move(restart_with_auth_callback));
}

void TransportClientSocketPool::InvokeUserCallbackLater(
    ClientSocketHandle* handle,
    CompletionOnceCallback callback,
    int rv,
    const SocketTag& socket_tag) {
  CHECK(!base::Contains(pending_callback_map_, handle));
  pending_callback_map_[handle] = CallbackResultPair(std::move(callback), rv);
  if (rv == OK) {
    handle->socket()->ApplySocketTag(socket_tag);
  }
  base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
      FROM_HERE, base::BindOnce(&TransportClientSocketPool::InvokeUserCallback,
                                weak_factory_.GetWeakPtr(),
                                // This is safe as `handle` is checked against a
                                // map to verify it's alive before dereference.
                                // This code path must only be reachable by
                                // `handle`s that have had Init called.
                                base::UnsafeDangling(handle)));
}

void TransportClientSocketPool::InvokeUserCallback(
    MayBeDangling<ClientSocketHandle> handle) {
  auto it = pending_callback_map_.find(handle);

  // Exit if the request has already been cancelled.
  if (it == pending_callback_map_.end())
    return;

  CHECK(!handle->is_initialized());
  CompletionOnceCallback callback = std::move(it->second.callback);
  int result = it->second.result;
  pending_callback_map_.erase(it);
  std::move(callback).Run(result);
}

void TransportClientSocketPool::TryToCloseSocketsInLayeredPools() {
  while (IsStalled()) {
    // Closing a socket will result in calling back into |this| to use the freed
    // socket slot, so nothing else is needed.
    if (!CloseOneIdleConnectionInHigherLayeredPool())
      return;
  }
}

TransportClientSocketPool::GroupMap::iterator
TransportClientSocketPool::RefreshGroup(GroupMap::iterator it,
                                        const base::TimeTicks& now,
                                        const char* net_log_reason_utf8) {
  Group* group = it->second;
  CHECK(group);
  CleanupIdleSocketsInGroup(true /* force */, group, now, net_log_reason_utf8);

  connecting_socket_count_ -= group->jobs().size();
  group->RemoveAllUnboundJobs();

  // Otherwise, prevent reuse of existing sockets.
  group->IncrementGeneration();

  // Delete group if no longer needed.
  if (group->IsEmpty()) {
    return RemoveGroup(it);
  }
  return ++it;
}

TransportClientSocketPool::Group::Group(
    const GroupId& group_id,
    TransportClientSocketPool* client_socket_pool)
    : group_id_(group_id),
      client_socket_pool_(client_socket_pool),
      unbound_requests_(NUM_PRIORITIES) {}

TransportClientSocketPool::Group::~Group() {
  DCHECK_EQ(0u, never_assigned_job_count());
  DCHECK_EQ(0u, unassigned_job_count());
  DCHECK(unbound_requests_.empty());
  DCHECK(jobs_.empty());
  DCHECK(bound_requests_.empty());
}

void TransportClientSocketPool::Group::OnConnectJobComplete(int result,
                                                            ConnectJob* job) {
  DCHECK_NE(ERR_IO_PENDING, result);
  client_socket_pool_->OnConnectJobComplete(this, result, job);
}

void TransportClientSocketPool::Group::OnNeedsProxyAuth(
    const HttpResponseInfo& response,
    HttpAuthController* auth_controller,
    base::OnceClosure restart_with_auth_callback,
    ConnectJob* job) {
  client_socket_pool_->OnNeedsProxyAuth(this, response, auth_controller,
                                        std::move(restart_with_auth_callback),
                                        job);
}

void TransportClientSocketPool::Group::StartBackupJobTimer(
    const GroupId& group_id) {
  // Only allow one timer to run at a time.
  if (BackupJobTimerIsRunning())
    return;

  // Unretained here is okay because |backup_job_timer_| is
  // automatically cancelled when it's destroyed.
  backup_job_timer_.Start(FROM_HERE,
                          client_socket_pool_->ConnectRetryInterval(),
                          base::BindOnce(&Group::OnBackupJobTimerFired,
                                         base::Unretained(this), group_id));
}

bool TransportClientSocketPool::Group::BackupJobTimerIsRunning() const {
  return backup_job_timer_.IsRunning();
}

bool TransportClientSocketPool::Group::TryToUseNeverAssignedConnectJob() {
  SanityCheck();

  if (never_assigned_job_count_ == 0)
    return false;
  --never_assigned_job_count_;
  return true;
}

void TransportClientSocketPool::Group::AddJob(std::unique_ptr<ConnectJob> job,
                                              bool is_preconnect) {
  SanityCheck();

  if (is_preconnect)
    ++never_assigned_job_count_;
  jobs_.push_back(std::move(job));
  TryToAssignUnassignedJob(jobs_.back().get());

  SanityCheck();
}

std::unique_ptr<ConnectJob> TransportClientSocketPool::Group::RemoveUnboundJob(
    ConnectJob* job) {
  SanityCheck();

  // Check that |job| is in the list.
  auto it = base::ranges::find(jobs_, job, &std::unique_ptr<ConnectJob>::get);
  CHECK(it != jobs_.end(), base::NotFatalUntil::M130);

  // Check if |job| is in the unassigned jobs list. If so, remove it.
  auto it2 = base::ranges::find(unassigned_jobs_, job);
  if (it2 != unassigned_jobs_.end()) {
    unassigned_jobs_.erase(it2);
  } else {
    // Otherwise, |job| must be assigned to some Request. Unassign it, then
    // try to replace it with another job if possible (either by taking an
    // unassigned job or stealing from another request, if any requests after it
    // have a job).
    RequestQueue::Pointer request_with_job = FindUnboundRequestWithJob(job);
    DCHECK(!request_with_job.is_null());
    request_with_job.value()->ReleaseJob();
    TryToAssignJobToRequest(request_with_job);
  }
  std::unique_ptr<ConnectJob> owned_job = std::move(*it);
  jobs_.erase(it);

  size_t job_count = jobs_.size();
  if (job_count < never_assigned_job_count_)
    never_assigned_job_count_ = job_count;

  // If we've got no more jobs for this group, then we no longer need a
  // backup job either.
  if (jobs_.empty()) {
    DCHECK(unassigned_jobs_.empty());
    backup_job_timer_.Stop();
  }

  SanityCheck();
  return owned_job;
}

void TransportClientSocketPool::Group::OnBackupJobTimerFired(
    const GroupId& group_id) {
  // If there are no more jobs pending, there is no work to do.
  // If we've done our cleanups correctly, this should not happen.
  if (jobs_.empty()) {
    NOTREACHED();
  }

  // If the old job has already established a connection, don't start a backup
  // job. Backup jobs are only for issues establishing the initial TCP
  // connection - the timeout they used is tuned for that, and tests expect that
  // behavior.
  //
  // TODO(crbug.com/41440018): Replace both this and the
  // LOAD_STATE_RESOLVING_HOST check with a callback. Use the
  // LOAD_STATE_RESOLVING_HOST callback to start the timer (And invoke the
  // OnHostResolved callback of any pending requests), and the
  // HasEstablishedConnection() callback to stop the timer. That should result
  // in a more robust, testable API.
  if ((*jobs_.begin())->HasEstablishedConnection())
    return;

  // If our old job is waiting on DNS, or if we can't create any sockets
  // right now due to limits, just reset the timer.
  if (client_socket_pool_->ReachedMaxSocketsLimit() ||
      !HasAvailableSocketSlot(client_socket_pool_->max_sockets_per_group_) ||
      (*jobs_.begin())->GetLoadState() == LOAD_STATE_RESOLVING_HOST) {
    StartBackupJobTimer(group_id);
    return;
  }

  if (unbound_requests_.empty())
    return;

  Request* request = unbound_requests_.FirstMax().value().get();
  std::unique_ptr<ConnectJob> owned_backup_job =
      client_socket_pool_->CreateConnectJob(
          group_id, request->socket_params(), client_socket_pool_->proxy_chain_,
          request->proxy_annotation_tag(), request->priority(),
          request->socket_tag(), this);
  owned_backup_job->net_log().AddEvent(
      NetLogEventType::SOCKET_POOL_CONNECT_JOB_CREATED, [&] {
        return NetLogCreateConnectJobParams(true /* backup_job */, &group_id_);
      });
  ConnectJob* backup_job = owned_backup_job.get();
  AddJob(std::move(owned_backup_job), false);
  client_socket_pool_->connecting_socket_count_++;
  int rv = backup_job->Connect();
  if (rv != ERR_IO_PENDING) {
    client_socket_pool_->OnConnectJobComplete(this, rv, backup_job);
  }
}

void TransportClientSocketPool::Group::SanityCheck() const {
#if DCHECK_IS_ON()
  DCHECK_LE(never_assigned_job_count(), jobs_.size());
  DCHECK_LE(unassigned_job_count(), jobs_.size());

  // Check that |unassigned_jobs_| is empty iff there are at least as many
  // requests as jobs.
  DCHECK_EQ(unassigned_jobs_.empty(), jobs_.size() <= unbound_requests_.size());

  size_t num_assigned_jobs = jobs_.size() - unassigned_jobs_.size();

  RequestQueue::Pointer pointer = unbound_requests_.FirstMax();
  for (size_t i = 0; i < unbound_requests_.size();
       ++i, pointer = unbound_requests_.GetNextTowardsLastMin(pointer)) {
    DCHECK(!pointer.is_null());
    DCHECK(pointer.value());
    // Check that the first |num_assigned_jobs| requests have valid job
    // assignments.
    if (i < num_assigned_jobs) {
      // The request has a job.
      ConnectJob* job = pointer.value()->job();
      DCHECK(job);
      // The request's job is not in |unassigned_jobs_|
      DCHECK(!base::Contains(unassigned_jobs_, job));
      // The request's job is in |jobs_|
      DCHECK(base::Contains(jobs_, job, &std::unique_ptr<ConnectJob>::get));
      // The same job is not assigned to any other request with a job.
      RequestQueue::Pointer pointer2 =
          unbound_requests_.GetNextTowardsLastMin(pointer);
      for (size_t j = i + 1; j < num_assigned_jobs;
           ++j, pointer2 = unbound_requests_.GetNextTowardsLastMin(pointer2)) {
        DCHECK(!pointer2.is_null());
        ConnectJob* job2 = pointer2.value()->job();
        DCHECK(job2);
        DCHECK_NE(job, job2);
      }
      DCHECK_EQ(pointer.value()->priority(), job->priority());
    } else {
      // Check that any subsequent requests do not have a job.
      DCHECK(!pointer.value()->job());
    }
  }

  for (auto it = unassigned_jobs_.begin(); it != unassigned_jobs_.end(); ++it) {
    // Check that all unassigned jobs are in |jobs_|
    ConnectJob* job = *it;
    DCHECK(base::Contains(jobs_, job, &std::unique_ptr<ConnectJob>::get));
    // Check that there are no duplicated entries in |unassigned_jobs_|
    for (auto it2 = std::next(it); it2 != unassigned_jobs_.end(); ++it2) {
      DCHECK_NE(job, *it2);
    }

    // Check that no |unassigned_jobs_| are in |bound_requests_|.
    DCHECK(!base::Contains(bound_requests_, job,
                           [](const BoundRequest& bound_request) {
                             return bound_request.connect_job.get();
                           }));
  }
#endif
}

void TransportClientSocketPool::Group::RemoveAllUnboundJobs() {
  SanityCheck();

  // Remove jobs from any requests that have them.
  if (!unbound_requests_.empty()) {
    for (RequestQueue::Pointer pointer = unbound_requests_.FirstMax();
         !pointer.is_null() && pointer.value()->job();
         pointer = unbound_requests_.GetNextTowardsLastMin(pointer)) {
      pointer.value()->ReleaseJob();
    }
  }
  unassigned_jobs_.clear();
  never_assigned_job_count_ = 0;

  // Diagnostics check for crbug.com/1231248. `Group`s are deleted only on
  // removal from `TransportClientSocketPool::group_map_`, so if this check
  // fails, `this` has been deleted, likely through some reentrancy issue.
  CHECK(client_socket_pool_->HasGroup(group_id_));

  // Delete active jobs.
  jobs_.clear();
  // Stop backup job timer.
  backup_job_timer_.Stop();

  SanityCheck();
}

size_t TransportClientSocketPool::Group::ConnectJobCount() const {
  return bound_requests_.size() + jobs_.size();
}

ConnectJob* TransportClientSocketPool::Group::GetConnectJobForHandle(
    const ClientSocketHandle* handle) const {
  // Search through bound requests for |handle|.
  for (const auto& bound_pair : bound_requests_) {
    if (handle == bound_pair.request->handle())
      return bound_pair.connect_job.get();
  }

  // Search through the unbound requests that have corresponding jobs for a
  // request with |handle|.
  for (RequestQueue::Pointer pointer = unbound_requests_.FirstMax();
       !pointer.is_null() && pointer.value()->job();
       pointer = unbound_requests_.GetNextTowardsLastMin(pointer)) {
    if (pointer.value()->handle() == handle)
      return pointer.value()->job();
  }

  return nullptr;
}

void TransportClientSocketPool::Group::InsertUnboundRequest(
    std::unique_ptr<Request> request) {
  SanityCheck();

  // Should not have a job because it is not already in |unbound_requests_|
  DCHECK(!request->job());
  // This value must be cached before we release |request|.
  RequestPriority priority = request->priority();

  RequestQueue::Pointer new_position;
  if (request->respect_limits() == RespectLimits::DISABLED) {
    // Put requests with RespectLimits::DISABLED (which should have
    // priority == MAXIMUM_PRIORITY) ahead of other requests with
    // MAXIMUM_PRIORITY.
    DCHECK_EQ(priority, MAXIMUM_PRIORITY);
    new_position =
        unbound_requests_.InsertAtFront(std::move(request), priority);
  } else {
    new_position = unbound_requests_.Insert(std::move(request), priority);
  }
  DCHECK(!unbound_requests_.empty());

  TryToAssignJobToRequest(new_position);

  SanityCheck();
}

const TransportClientSocketPool::Request*
TransportClientSocketPool::Group::GetNextUnboundRequest() const {
  return unbound_requests_.empty() ? nullptr
                                   : unbound_requests_.FirstMax().value().get();
}

std::unique_ptr<TransportClientSocketPool::Request>
TransportClientSocketPool::Group::PopNextUnboundRequest() {
  if (unbound_requests_.empty())
    return nullptr;
  return RemoveUnboundRequest(unbound_requests_.FirstMax());
}

std::unique_ptr<TransportClientSocketPool::Request>
TransportClientSocketPool::Group::FindAndRemoveUnboundRequest(
    ClientSocketHandle* handle) {
  for (RequestQueue::Pointer pointer = unbound_requests_.FirstMax();
       !pointer.is_null();
       pointer = unbound_requests_.GetNextTowardsLastMin(pointer)) {
    if (pointer.value()->handle() == handle) {
      DCHECK_EQ(static_cast<RequestPriority>(pointer.priority()),
                pointer.value()->priority());
      std::unique_ptr<Request> request = RemoveUnboundRequest(pointer);
      return request;
    }
  }
  return nullptr;
}

void TransportClientSocketPool::Group::SetPendingErrorForAllBoundRequests(
    int pending_error) {
  for (auto& bound_request : bound_requests_) {
    // Earlier errors take precedence.
    if (bound_request.pending_error == OK)
      bound_request.pending_error = pending_error;
  }
}

const TransportClientSocketPool::Request*
TransportClientSocketPool::Group::BindRequestToConnectJob(
    ConnectJob* connect_job) {
  // Check if |job| is already bound to a Request.
  for (const auto& bound_pair : bound_requests_) {
    if (bound_pair.connect_job.get() == connect_job)
      return bound_pair.request.get();
  }

  // If not, try to bind it to a Request.
  const Request* request = GetNextUnboundRequest();
  // If there are no pending requests, or the highest priority request has no
  // callback to handle auth challenges, return nullptr.
  if (!request || request->proxy_auth_callback().is_null())
    return nullptr;

  // Otherwise, bind the ConnectJob to the Request.
```