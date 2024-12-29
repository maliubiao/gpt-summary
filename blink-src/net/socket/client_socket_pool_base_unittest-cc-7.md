Response:
The user wants a breakdown of the provided C++ code for a unit test file related to Chromium's network stack, specifically `net/socket/client_socket_pool_base_unittest.cc`.

Here's a plan to address each of the user's requests:

1. **Functionality:** Analyze the test cases and the `TestAuthHelper` class to understand the code's purpose. It seems to be testing the behavior of `ClientSocketPoolBase` related to proxy authentication.

2. **Relationship to Javascript:**  Consider how the network stack interacts with Javascript in a browser context. Javascript uses APIs that eventually rely on the network stack to make requests.

3. **Logical Reasoning (Hypothetical Input/Output):** For specific test cases, imagine scenarios leading to those tests and the expected outcome based on the test's assertions.

4. **Common Usage Errors:** Think about common programming mistakes or user actions that might trigger the scenarios being tested.

5. **User Operation to Reach Here (Debugging):** Trace the steps a user might take in a browser that would lead to this code being involved.

6. **File Functionality Summary (Part 8 of 8):**  Summarize the overall purpose of this specific test file, considering it's part of a larger test suite.
```c++
start_with_auth_callback_ = std::move(restart_with_auth_callback);

    if (reset_handle_sync_) {
      handle_.Reset();
      return;
    }
  }

  std::unique_ptr<base::RunLoop> run_loop_;
  base::OnceClosure restart_with_auth_callback_;

  bool restart_sync_ = false;
  bool reset_handle_sync_ = false;

  ClientSocketHandle handle_;
  int auth_count_ = 0;
  TestCompletionCallback callback_;
};

TEST_F(ClientSocketPoolBaseTest, ProxyAuthOnce) {
  CreatePool(1, 1);
  connect_job_factory_->set_job_type(TestConnectJob::kMockAuthChallengeOnceJob);

  TestAuthHelper auth_helper;
  auth_helper.InitHandle(params_, pool_.get());
  EXPECT_EQ(1u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(LOAD_STATE_CONNECTING,
            pool_->GetLoadState(TestGroupId("a"), auth_helper.handle()));

  auth_helper.WaitForAuth();
  EXPECT_EQ(1u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(LOAD_STATE_ESTABLISHING_PROXY_TUNNEL,
            pool_->GetLoadState(TestGroupId("a"), auth_helper.handle()));

  auth_helper.RestartWithAuth();
  EXPECT_EQ(1u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(LOAD_STATE_ESTABLISHING_PROXY_TUNNEL,
            pool_->GetLoadState(TestGroupId("a"), auth_helper.handle()));

  EXPECT_THAT(auth_helper.WaitForResult(), IsOk());
  EXPECT_EQ(1, auth_helper.auth_count());
  EXPECT_EQ(0u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(1, pool_->NumActiveSocketsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(0u, pool_->IdleSocketCountInGroup(TestGroupId("a")));
  EXPECT_EQ(0, pool_->IdleSocketCount());
}

TEST_F(ClientSocketPoolBaseTest, ProxyAuthOnceSync) {
  CreatePool(1, 1);
  connect_job_factory_->set_job_type(TestConnectJob::kMockAuthChallengeOnceJob);

  TestAuthHelper auth_helper;
  auth_helper.InitHandle(params_, pool_.get());
  EXPECT_EQ(1u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(LOAD_STATE_CONNECTING,
            pool_->GetLoadState(TestGroupId("a"), auth_helper.handle()));

  auth_helper.WaitForAuthAndRestartSync();
  EXPECT_EQ(1u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(LOAD_STATE_ESTABLISHING_PROXY_TUNNEL,
            pool_->GetLoadState(TestGroupId("a"), auth_helper.handle()));

  EXPECT_THAT(auth_helper.WaitForResult(), IsOk());
  EXPECT_EQ(1, auth_helper.auth_count());
  EXPECT_EQ(0u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(1, pool_->NumActiveSocketsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(0u, pool_->IdleSocketCountInGroup(TestGroupId("a")));
  EXPECT_EQ(0, pool_->IdleSocketCount());
}

TEST_F(ClientSocketPoolBaseTest, ProxyAuthOnceFails) {
  CreatePool(1, 1);
  connect_job_factory_->set_job_type(
      TestConnectJob::kMockAuthChallengeOnceFailingJob);

  TestAuthHelper auth_helper;
  auth_helper.InitHandle(params_, pool_.get());
  EXPECT_EQ(1u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));

  auth_helper.WaitForAuth();
  auth_helper.RestartWithAuth();
  EXPECT_THAT(auth_helper.WaitForResult(), IsError(ERR_CONNECTION_FAILED));

  EXPECT_EQ(1, auth_helper.auth_count());
  EXPECT_FALSE(pool_->HasGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(0, pool_->IdleSocketCount());
}

TEST_F(ClientSocketPoolBaseTest, ProxyAuthOnceSyncFails) {
  CreatePool(1, 1);
  connect_job_factory_->set_job_type(
      TestConnectJob::kMockAuthChallengeOnceFailingJob);

  TestAuthHelper auth_helper;
  auth_helper.InitHandle(params_, pool_.get());
  EXPECT_EQ(1u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));

  auth_helper.WaitForAuthAndRestartSync();
  EXPECT_THAT(auth_helper.WaitForResult(), IsError(ERR_CONNECTION_FAILED));

  EXPECT_EQ(1, auth_helper.auth_count());
  EXPECT_FALSE(pool_->HasGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(0, pool_->IdleSocketCount());
}

TEST_F(ClientSocketPoolBaseTest, ProxyAuthOnceDeleteHandle) {
  CreatePool(1, 1);
  connect_job_factory_->set_job_type(TestConnectJob::kMockAuthChallengeOnceJob);

  TestAuthHelper auth_helper;
  auth_helper.InitHandle(params_, pool_.get());
  EXPECT_EQ(1u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));

  auth_helper.WaitForAuth();
  EXPECT_EQ(1u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));

  auth_helper.handle()->Reset();

  EXPECT_EQ(1, auth_helper.auth_count());
  EXPECT_FALSE(pool_->HasGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(0, pool_->IdleSocketCount());
  EXPECT_FALSE(auth_helper.handle()->is_initialized());
  EXPECT_FALSE(auth_helper.handle()->socket());
}

TEST_F(ClientSocketPoolBaseTest, ProxyAuthOnceDeleteHandleSync) {
  CreatePool(1, 1);
  connect_job_factory_->set_job_type(TestConnectJob::kMockAuthChallengeOnceJob);

  TestAuthHelper auth_helper;
  auth_helper.InitHandle(params_, pool_.get());
  EXPECT_EQ(1u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));

  auth_helper.WaitForAuthAndResetHandleSync();
  EXPECT_EQ(1, auth_helper.auth_count());
  EXPECT_FALSE(pool_->HasGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(0, pool_->IdleSocketCount());
  EXPECT_FALSE(auth_helper.handle()->is_initialized());
  EXPECT_FALSE(auth_helper.handle()->socket());
}

TEST_F(ClientSocketPoolBaseTest, ProxyAuthOnceFlushWithError) {
  CreatePool(1, 1);
  connect_job_factory_->set_job_type(TestConnectJob::kMockAuthChallengeOnceJob);

  TestAuthHelper auth_helper;
  auth_helper.InitHandle(params_, pool_.get());
  EXPECT_EQ(1u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));

  auth_helper.WaitForAuth();

  pool_->FlushWithError(ERR_FAILED, "Network changed");
  base::RunLoop().RunUntilIdle();

  // When flushing the socket pool, bound sockets should delay returning the
  // error until completion.
  EXPECT_FALSE(auth_helper.have_result());
  EXPECT_EQ(1u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(0, pool_->IdleSocketCount());

  auth_helper.RestartWithAuth();
  // The callback should be called asynchronously.
  EXPECT_FALSE(auth_helper.have_result());

  EXPECT_THAT(auth_helper.WaitForResult(), IsError(ERR_FAILED));
  EXPECT_FALSE(pool_->HasGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(0, pool_->IdleSocketCount());
}

TEST_F(ClientSocketPoolBaseTest, ProxyAuthTwice) {
  CreatePool(1, 1);
  connect_job_factory_->set_job_type(
      TestConnectJob::kMockAuthChallengeTwiceJob);

  TestAuthHelper auth_helper;
  auth_helper.InitHandle(params_, pool_.get());
  EXPECT_EQ(1u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(LOAD_STATE_CONNECTING,
            pool_->GetLoadState(TestGroupId("a"), auth_helper.handle()));

  auth_helper.WaitForAuth();
  auth_helper.RestartWithAuth();
  EXPECT_EQ(1u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(1, auth_helper.auth_count());
  EXPECT_EQ(LOAD_STATE_ESTABLISHING_PROXY_TUNNEL,
            pool_->GetLoadState(TestGroupId("a"), auth_helper.handle()));

  auth_helper.WaitForAuth();
  EXPECT_EQ(1u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(2, auth_helper.auth_count());
  EXPECT_EQ(LOAD_STATE_ESTABLISHING_PROXY_TUNNEL,
            pool_->GetLoadState(TestGroupId("a"), auth_helper.handle()));

  auth_helper.RestartWithAuth();
  EXPECT_EQ(1u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(2, auth_helper.auth_count());
  EXPECT_EQ(LOAD_STATE_ESTABLISHING_PROXY_TUNNEL,
            pool_->GetLoadState(TestGroupId("a"), auth_helper.handle()));

  EXPECT_THAT(auth_helper.WaitForResult(), IsOk());
  EXPECT_EQ(2, auth_helper.auth_count());
  EXPECT_EQ(0u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(1, pool_->NumActiveSocketsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(0u, pool_->IdleSocketCountInGroup(TestGroupId("a")));
  EXPECT_EQ(0, pool_->IdleSocketCount());
}

TEST_F(ClientSocketPoolBaseTest, ProxyAuthTwiceFails) {
  CreatePool(1, 1);
  connect_job_factory_->set_job_type(
      TestConnectJob::kMockAuthChallengeTwiceFailingJob);

  TestAuthHelper auth_helper;
  auth_helper.InitHandle(params_, pool_.get());
  EXPECT_EQ(1u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));

  auth_helper.WaitForAuth();
  auth_helper.RestartWithAuth();
  EXPECT_EQ(1u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(1, auth_helper.auth_count());

  auth_helper.WaitForAuth();
  auth_helper.RestartWithAuth();
  EXPECT_EQ(1u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(2, auth_helper.auth_count());

  EXPECT_THAT(auth_helper.WaitForResult(), IsError(ERR_CONNECTION_FAILED));
  EXPECT_EQ(2, auth_helper.auth_count());
  EXPECT_FALSE(pool_->HasGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(0, pool_->IdleSocketCount());
}

// Makes sure that when a bound request is destroyed, a new ConnectJob is
// created, if needed.
TEST_F(ClientSocketPoolBaseTest,
       ProxyAuthCreateNewConnectJobOnDestroyBoundRequest) {
  CreatePool(1 /* max_sockets */, 1 /* max_sockets_per_group */);
  connect_job_factory_->set_job_type(
      TestConnectJob::kMockAuthChallengeOnceFailingJob);

  // First request creates a ConnectJob.
  TestAuthHelper auth_helper1;
  auth_helper1.InitHandle(params_, pool_.get());
  EXPECT_EQ(1u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));

  // A second request come in, but no new ConnectJob is needed, since the limit
  // has been reached.
  TestAuthHelper auth_helper2;
  auth_helper2.InitHandle(params_, pool_.get());
  EXPECT_EQ(1u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));

  // Run until the auth callback for the first request is invoked.
  auth_helper1.WaitForAuth();
  EXPECT_EQ(0, auth_helper2.auth_count());
  EXPECT_EQ(1u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(0, pool_->NumActiveSocketsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(0u, pool_->IdleSocketCountInGroup(TestGroupId("a")));

  // Make connect jobs succeed, then cancel the first request, which should
  // destroy the bound ConnectJob, and cause a new ConnectJob to start.
  connect_job_factory_->set_job_type(TestConnectJob::kMockPendingJob);
  auth_helper1.handle()->Reset();
  EXPECT_EQ(0, auth_helper2.auth_count());
  EXPECT_EQ(1u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));

  // The second ConnectJob should succeed.
  EXPECT_THAT(auth_helper2.WaitForResult(), IsOk());
  EXPECT_EQ(0, auth_helper2.auth_count());
  EXPECT_EQ(0u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));
}

// Makes sure that when a bound request is destroyed, a new ConnectJob is
// created for another group, if needed.
TEST_F(ClientSocketPoolBaseTest,
       ProxyAuthCreateNewConnectJobOnDestroyBoundRequestDifferentGroups) {
  CreatePool(1 /* max_sockets */, 1 /* max_sockets_per_group */);
  connect_job_factory_->set_job_type(
      TestConnectJob::kMockAuthChallengeOnceFailingJob);

  // First request creates a ConnectJob.
  TestAuthHelper auth_helper1;
  auth_helper1.InitHandle(params_, pool_.get(), DEFAULT_PRIORITY);
  EXPECT_EQ(1u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));

  // A second request come in, but no new ConnectJob is needed, since the limit
  // has been reached.
  TestAuthHelper auth_helper2;
  auth_helper2.InitHandle(params_, pool_.get(), DEFAULT_PRIORITY,
                          ClientSocketPool::RespectLimits::ENABLED,
                          TestGroupId("b"));
  EXPECT_EQ(1u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(0u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("b")));

  // Run until the auth callback for the first request is invoked.
  auth_helper1.WaitForAuth();
  EXPECT_EQ(0, auth_helper2.auth_count());
  EXPECT_EQ(1u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(0, pool_->NumActiveSocketsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(0u, pool_->IdleSocketCountInGroup(TestGroupId("a")));
  EXPECT_EQ(0u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("b")));
  EXPECT_EQ(0, pool_->NumActiveSocketsInGroupForTesting(TestGroupId("b")));
  EXPECT_EQ(0u, pool_->IdleSocketCountInGroup(TestGroupId("b")));

  // Make connect jobs succeed, then cancel the first request, which should
  // destroy the bound ConnectJob, and cause a new ConnectJob to start for the
  // other group.
  connect_job_factory_->set_job_type(TestConnectJob::kMockPendingJob);
  auth_helper1.handle()->Reset();
  EXPECT_EQ(0, auth_helper2.auth_count());
  EXPECT_FALSE(pool_->HasGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(1u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("b")));

  // The second ConnectJob should succeed.
  EXPECT_THAT(auth_helper2.WaitForResult(), IsOk());
  EXPECT_EQ(0, auth_helper2.auth_count());
  EXPECT_FALSE(pool_->HasGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(0u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("b")));
}

// Test that once an auth challenge is bound, that's the request that gets all
// subsequent calls and the socket itself.
TEST_F(ClientSocketPoolBaseTest, ProxyAuthStaysBound) {
  CreatePool(1, 1);
  connect_job_factory_->set_job_type(
      TestConnectJob::kMockAuthChallengeTwiceJob);

  // First request creates a ConnectJob.
  TestAuthHelper auth_helper1;
  auth_helper1.InitHandle(params_, pool_.get(), LOWEST);
  EXPECT_EQ(1u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));

  // A second, higher priority request is made.
  TestAuthHelper auth_helper2;
  auth_helper2.InitHandle(params_, pool_.get(), LOW);
  EXPECT_EQ(1u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));

  // Run until the auth callback for the second request is invoked.
  auth_helper2.WaitForAuth();
  EXPECT_EQ(0, auth_helper1.auth_count());
  EXPECT_EQ(1u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(0, pool_->NumActiveSocketsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(0u, pool_->IdleSocketCountInGroup(TestGroupId("a")));

  // Start a higher priority job. It shouldn't be able to steal |auth_helper2|'s
  // ConnectJob.
  TestAuthHelper auth_helper3;
  auth_helper3.InitHandle(params_, pool_.get(), HIGHEST);
  EXPECT_EQ(1u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));

  // Start a higher job that ignores limits, creating a hanging socket. It
  // shouldn't be able to steal |auth_helper2|'s ConnectJob.
  connect_job_factory_->set_job_type(TestConnectJob::kMockWaitingJob);
  TestAuthHelper auth_helper4;
  auth_helper4.InitHandle(params_, pool_.get(), HIGHEST,
                          ClientSocketPool::RespectLimits::DISABLED);
  EXPECT_EQ(2u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));

  // Restart with auth, and |auth_helper2|'s auth method should be invoked
  // again.
  auth_helper2.RestartWithAuth();
  auth_helper2.WaitForAuth();
  EXPECT_EQ(0, auth_helper1.auth_count());
  EXPECT_FALSE(auth_helper1.have_result());
  EXPECT_EQ(2, auth_helper2.auth_count());
  EXPECT_FALSE(auth_helper2.have_result());
  EXPECT_EQ(0, auth_helper3.auth_count());
  EXPECT_FALSE(auth_helper3.have_result());
  EXPECT_EQ(0, auth_helper4.auth_count());
  EXPECT_FALSE(auth_helper4.have_result());

  // Advance auth again, and |auth_helper2| should get the socket.
  auth_helper2.RestartWithAuth();
  EXPECT_THAT(auth_helper2.WaitForResult(), IsOk());
  // The hung ConnectJob for the RespectLimits::DISABLED request is still in the
  // socket pool.
  EXPECT_EQ(1u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(1, pool_->NumActiveSocketsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(0, auth_helper1.auth_count());
  EXPECT_FALSE(auth_helper1.have_result());
  EXPECT_EQ(0, auth_helper3.auth_count());
  EXPECT_FALSE(auth_helper3.have_result());
  EXPECT_EQ(0, auth_helper4.auth_count());
  EXPECT_FALSE(auth_helper4.have_result());

  // If the socket is returned to the socket pool, the RespectLimits::DISABLED
  // socket request should be able to claim it.
  auth_helper2.handle()->Reset();
  EXPECT_THAT(auth_helper4.WaitForResult(), IsOk());
  EXPECT_EQ(0, auth_helper1.auth_count());
  EXPECT_FALSE(auth_helper1.have_result());
  EXPECT_EQ(0, auth_helper3.auth_count());
  EXPECT_FALSE(auth_helper3.have_result());
  EXPECT_EQ(0, auth_helper4.auth_count());
}

enum class RefreshType {
  kServer,
  kProxy,
};

// Common base class to test RefreshGroup() when called from either
// OnSSLConfigForServersChanged() matching a specific group or the pool's proxy.
//
// Tests which test behavior specific to one or the other case should use
// ClientSocketPoolBaseTest directly. In particular, there is no "other group"
// when the pool's proxy matches.
class ClientSocketPoolBaseRefreshTest
    : public ClientSocketPoolBaseTest,
      public testing::WithParamInterface<RefreshType> {
 public:
  void CreatePoolForRefresh(int max_sockets,
                            int max_sockets_per_group,
                            bool enable_backup_connect_jobs = false) {
    switch (GetParam()) {
      case RefreshType::kServer:
        CreatePool(max_sockets, max_sockets_per_group,
                   enable_backup_connect_jobs);
        break;
      case RefreshType::kProxy:
        CreatePoolWithIdleTimeouts(
            max_sockets, max_sockets_per_group, kUnusedIdleSocketTimeout,
            ClientSocketPool::used_idle_socket_timeout(),
            enable_backup_connect_jobs,
            PacResultElementToProxyChain("HTTPS myproxy:70"));
        break;
    }
  }

  static ClientSocketPool::GroupId GetGroupId() {
    return TestGroupId("a", 443, url::kHttpsScheme);
  }

  static ClientSocketPool::GroupId GetGroupIdInPartition() {
    // Note this GroupId will match GetGroupId() unless
    // kPartitionConnectionsByNetworkAnonymizationKey is enabled.
    const SchemefulSite kSite(GURL("https://b/"));
    const auto kNetworkAnonymizationKey =
        NetworkAnonymizationKey::CreateSameSite(kSite);
    return TestGroupId("a", 443, url::kHttpsScheme,
                       PrivacyMode::PRIVACY_MODE_DISABLED,
                       kNetworkAnonymizationKey);
  }

  void OnSSLConfigForServersChanged() {
    switch (GetParam()) {
      case RefreshType::kServer:
        pool_->OnSSLConfigForServersChanged({HostPortPair("a", 443)});
        break;
      case RefreshType::kProxy:
        pool_->OnSSLConfigForServersChanged({HostPortPair("myproxy", 70)});
        break;
    }
  }
};

INSTANTIATE_TEST_SUITE_P(RefreshType,
                         ClientSocketPoolBaseRefreshTest,
                         ::testing::Values(RefreshType::kServer,
                                           RefreshType::kProxy));

TEST_P(ClientSocketPoolBaseRefreshTest, RefreshGroupCreatesNewConnectJobs) {
  CreatePoolForRefresh(kDefaultMaxSockets, kDefaultMaxSocketsPerGroup);
  const ClientSocketPool::GroupId kGroupId = GetGroupId();

  // First job will be waiting until it gets aborted.
  connect_job_factory_->set_job_type(TestConnectJob::kMockWaitingJob);

  ClientSocketHandle handle;
  TestCompletionCallback callback;
  EXPECT_THAT(
      handle.Init(kGroupId, params_, std::nullopt, DEFAULT_PRIORITY,
                  SocketTag(), ClientSocketPool::RespectLimits::ENABLED,
                  callback.callback(), ClientSocketPool::ProxyAuthCallback(),
                  pool_.get(), NetLogWithSource()),
      IsError(ERR_IO_PENDING));

  // Switch connect job types, so creating a new ConnectJob will result in
  // success.
  connect_job_factory_->set_job_type(TestConnectJob::kMockJob);

  OnSSLConfigForServersChanged();
  EXPECT_EQ(OK, callback.WaitForResult());
  ASSERT_TRUE(handle.socket());
  EXPECT_EQ(0, pool_->IdleSocketCount());
  ASSERT_TRUE(pool_->HasGroupForTesting(kGroupId));
  EXPECT_EQ(0u, pool_->IdleSocketCountInGroup(kGroupId));
  EXPECT_EQ(0u, pool_->NumConnectJobsInGroupForTesting(kGroupId));
  EXPECT_EQ(1, pool_->NumActiveSocketsInGroupForTesting(kGroupId));
}

TEST_P(ClientSocketPoolBaseRefreshTest, RefreshGroupClosesIdleConnectJobs) {
  base::test::ScopedFeatureList feature_list;
  feature_list.InitAndEnableFeature(
      features::kPartitionConnectionsByNetworkIsolationKey);

  CreatePoolForRefresh(kDefaultMaxSockets, kDefaultMaxSocketsPerGroup);
  const ClientSocketPool::GroupId kGroupId = GetGroupId();
  const ClientSocketPool::GroupId kGroupIdInPartition = GetGroupIdInPartition();

  EXPECT_EQ(
      OK, pool_->RequestSockets(kGroupId, params_, std::nullopt, 2,
                                CompletionOnceCallback(), NetLogWithSource()));

  EXPECT_EQ(
      OK, pool_->RequestSockets(kGroupIdInPartition, params_, std::nullopt, 2,
                                CompletionOnceCallback(), NetLogWithSource()));
  ASSERT_TRUE(pool_->HasGroupForTesting(kGroupId));
  ASSERT_TRUE(pool_->HasGroupForTesting(kGroupIdInPartition));
  EXPECT_EQ(4, pool_->IdleSocketCount());
  EXPECT_EQ(2u, pool_->IdleSocketCountInGroup(kGroupId));
  EXPECT_EQ(2u, pool_->IdleSocketCountInGroup(kGroupIdInPartition));

  OnSSLConfigForServersChanged();
  EXPECT_EQ(0, pool_->IdleSocketCount());
  EXPECT_FALSE(pool_->HasGroupForTesting(kGroupId));
  EXPECT_FALSE(pool_->HasGroupForTesting(kGroupIdInPartition));
}

TEST_F(ClientSocketPoolBaseTest,
       RefreshGroupDoesNotCloseIdleConnectJobsInOtherGroup) {
  CreatePool(kDefaultMaxSockets, kDefaultMaxSocketsPerGroup);
  const ClientSocketPool::GroupId kGroupId =
      TestGroupId("a", 443, url::kHttpsScheme);
  const ClientSocketPool::GroupId kOtherGroupId =
      TestGroupId("b", 443, url::kHttpsScheme);

  EXPECT_EQ(
      OK, pool_->RequestSockets(kOtherGroupId, params_, std::nullopt, 2,
                                CompletionOnceCallback(), NetLogWithSource()));
  ASSERT_TRUE(pool_->HasGroupForTesting(kOtherGroupId));
  EXPECT_EQ(2, pool_->IdleSocketCount());
  EXPECT_EQ(2u, pool_->IdleSocketCountInGroup(kOtherGroupId));

  pool_->OnSSLConfigForServersChanged({HostPortPair("a", 443)});
  ASSERT_TRUE(pool_->HasGroupForTesting(kOtherGroupId));
  EXPECT_EQ(2, pool_->IdleSocketCount());
  EXPECT_EQ(2u, pool_->IdleSocketCountInGroup(kOtherGroupId));
}

TEST_P(ClientSocketPoolBaseRefreshTest, RefreshGroupPreventsSocketReuse) {
  CreatePoolForRefresh(kDefaultMaxSockets, kDefaultMaxSocketsPerGroup);
  const ClientSocketPool::GroupId kGroupId = GetGroupId();

  ClientSocketHandle handle;
  TestCompletionCallback callback;
  EXPECT_THAT(
      handle.Init(kGroupId, params_, std::nullopt, DEFAULT_PRIORITY,
                  SocketTag(), ClientSocketPool::RespectLimits::ENABLED,
                  callback.callback(), ClientSocketPool::ProxyAuthCallback(),
                  pool_.get(), NetLogWithSource()),
      IsOk());
  ASSERT_TRUE(pool_->HasGroupForTesting(kGroupId));
  EXPECT_EQ(1, pool_->NumActiveSocketsInGroupForTesting(kGroupId));

  OnSSLConfigForServersChanged();

  handle.Reset();
  EXPECT_EQ(0, pool_->IdleSocketCount());
  EXPECT_FALSE(pool_->HasGroupForTesting(kGroupId));
}

TEST_F(ClientSocketPoolBaseTest,
       RefreshGroupDoesNotPreventSocketReuseInOtherGroup) {
  CreatePool(kDefaultMaxSockets, kDefaultMaxSocketsPerGroup);
  const ClientSocketPool::GroupId kGroupId =
      TestGroupId("a", 443, url::kHttpsScheme);
  const ClientSocketPool::GroupId kOtherGroupId =
      TestGroupId("b", 443, url::kHttpsScheme);

  ClientSocketHandle handle;
  TestCompletionCallback callback;
  EXPECT_THAT(
      handle.Init(kOtherGroupId, params_, std::nullopt, DEFAULT_PRIORITY,
                  SocketTag(), ClientSocketPool::RespectLimits::ENABLED,
                  callback.callback(), ClientSocketPool::ProxyAuthCallback(),
                  pool_.get(), NetLogWithSource()),
      IsOk());
  ASSERT_TRUE(pool_->HasGroupForTesting(kOtherGroupId));
  EXPECT_EQ(1, pool_->NumActiveSocketsInGroupForTesting(kOtherGroupId));

  pool_->OnSSLConfigForServersChanged({HostPortPair("a", 443)});

  handle.Reset();
  EXPECT_EQ(1, pool_->IdleSocketCount());
  ASSERT_TRUE(pool_->HasGroupForTesting(kOtherGroupId));
  EXPECT_EQ(1u, pool_->IdleSocketCountInGroup(kOtherGroupId));
}

TEST_P(ClientSocketPoolBaseRefreshTest,
       RefreshGroupReplacesBoundConnectJobOnConnect) {
  CreatePoolForRefresh(1, 1);
  const ClientSocketPool::GroupId kGroupId = GetGroupId();
  connect_job_factory_->set_job_type(TestConnectJob::kMockAuthChallengeOnceJob);

  TestAuthHelper auth_helper;
  auth_helper.InitHandle(params_, pool_.get(), DEFAULT_PRIORITY,
                         ClientSocketPool::RespectLimits::ENABLED, kGroupId);
  EXPECT_EQ(1u, pool_->NumConnectJobsInGroupForTesting(kGroupId));

  auth_helper.WaitForAuth();

  // This should update the generation, but not cancel the old ConnectJob - it's
  // not safe to do anything while waiting on the original ConnectJob.
  OnSSLConfigForServersChanged();

  // Providing auth credentials and restarting the request with them will cause
  // the ConnectJob to complete successfully, but the result will be discarded
  // because of the generation mismatch.
  auth_helper.RestartWithAuth();

  // Despite using ConnectJobs that simulate a single challenge, a second
  // challenge will be seen, due to using a new ConnectJob.
  auth_helper.WaitForAuth();
  auth_helper.RestartWithAuth();

  EXPECT_THAT(auth_helper.WaitForResult(), IsOk());
  EXPECT_TRUE(auth_helper.handle()->socket());
  EXPECT_EQ(2, auth_helper.auth_count());

  // When released, the socket will be returned to the socket pool, and
  // available for reuse.
  auth_helper.handle()->Reset();
  EXPECT_EQ(1, pool_->IdleSocketCount());
  ASSERT_TRUE(pool_->HasGroupForTesting(kGroupId));
  EXPECT_EQ(1u, pool_->IdleSocketCountInGroup(kGroupId));
}

// TODO(crbug.com/365771838): Add tests for non-ip protection nested proxy
// chains if support is enabled for all builds.
TEST_F(ClientSocketPoolBaseTest, RefreshProxyRefreshesAllGroups) {
  // Create a proxy chain containing `myproxy` (which is refreshed) and
  // nonrefreshedproxy (which is not), verifying that if any proxy in a chain is
  // refreshed, all groups are refreshed.
  auto proxy_chain = ProxyChain::ForIpProtection({
      PacResultElementToProxyServer("HTTPS myproxy:70"),
      PacResultElementToProxyServer("HTTPS nonrefreshedproxy:70"),
  });
  CreatePoolWithIdleTimeouts(kDefaultMaxSockets, kDefaultMaxSocketsPerGroup,
                             kUnusedIdleSocketTimeout,
                             ClientSocketPool::used_idle_socket_timeout(),
                             false /* no backup connect jobs */, proxy_chain);

  const ClientSocketPool::GroupId kGroupId1 =
      TestGroupId("a", 443, url::kHttpsScheme);
  const ClientSocketPool::GroupId kGroupId2 =
      TestGroupId("b", 443, url::kHttpsScheme);
  const ClientSocketPool::GroupId kGroupId3 =
      TestGroupId("c", 443, url::kHttpsScheme);

  // Make three sockets in three different groups. The third socket is released
  //
Prompt: 
```
这是目录为net/socket/client_socket_pool_base_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第8部分，共8部分，请归纳一下它的功能

"""
start_with_auth_callback_ = std::move(restart_with_auth_callback);

    if (reset_handle_sync_) {
      handle_.Reset();
      return;
    }
  }

  std::unique_ptr<base::RunLoop> run_loop_;
  base::OnceClosure restart_with_auth_callback_;

  bool restart_sync_ = false;
  bool reset_handle_sync_ = false;

  ClientSocketHandle handle_;
  int auth_count_ = 0;
  TestCompletionCallback callback_;
};

TEST_F(ClientSocketPoolBaseTest, ProxyAuthOnce) {
  CreatePool(1, 1);
  connect_job_factory_->set_job_type(TestConnectJob::kMockAuthChallengeOnceJob);

  TestAuthHelper auth_helper;
  auth_helper.InitHandle(params_, pool_.get());
  EXPECT_EQ(1u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(LOAD_STATE_CONNECTING,
            pool_->GetLoadState(TestGroupId("a"), auth_helper.handle()));

  auth_helper.WaitForAuth();
  EXPECT_EQ(1u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(LOAD_STATE_ESTABLISHING_PROXY_TUNNEL,
            pool_->GetLoadState(TestGroupId("a"), auth_helper.handle()));

  auth_helper.RestartWithAuth();
  EXPECT_EQ(1u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(LOAD_STATE_ESTABLISHING_PROXY_TUNNEL,
            pool_->GetLoadState(TestGroupId("a"), auth_helper.handle()));

  EXPECT_THAT(auth_helper.WaitForResult(), IsOk());
  EXPECT_EQ(1, auth_helper.auth_count());
  EXPECT_EQ(0u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(1, pool_->NumActiveSocketsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(0u, pool_->IdleSocketCountInGroup(TestGroupId("a")));
  EXPECT_EQ(0, pool_->IdleSocketCount());
}

TEST_F(ClientSocketPoolBaseTest, ProxyAuthOnceSync) {
  CreatePool(1, 1);
  connect_job_factory_->set_job_type(TestConnectJob::kMockAuthChallengeOnceJob);

  TestAuthHelper auth_helper;
  auth_helper.InitHandle(params_, pool_.get());
  EXPECT_EQ(1u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(LOAD_STATE_CONNECTING,
            pool_->GetLoadState(TestGroupId("a"), auth_helper.handle()));

  auth_helper.WaitForAuthAndRestartSync();
  EXPECT_EQ(1u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(LOAD_STATE_ESTABLISHING_PROXY_TUNNEL,
            pool_->GetLoadState(TestGroupId("a"), auth_helper.handle()));

  EXPECT_THAT(auth_helper.WaitForResult(), IsOk());
  EXPECT_EQ(1, auth_helper.auth_count());
  EXPECT_EQ(0u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(1, pool_->NumActiveSocketsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(0u, pool_->IdleSocketCountInGroup(TestGroupId("a")));
  EXPECT_EQ(0, pool_->IdleSocketCount());
}

TEST_F(ClientSocketPoolBaseTest, ProxyAuthOnceFails) {
  CreatePool(1, 1);
  connect_job_factory_->set_job_type(
      TestConnectJob::kMockAuthChallengeOnceFailingJob);

  TestAuthHelper auth_helper;
  auth_helper.InitHandle(params_, pool_.get());
  EXPECT_EQ(1u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));

  auth_helper.WaitForAuth();
  auth_helper.RestartWithAuth();
  EXPECT_THAT(auth_helper.WaitForResult(), IsError(ERR_CONNECTION_FAILED));

  EXPECT_EQ(1, auth_helper.auth_count());
  EXPECT_FALSE(pool_->HasGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(0, pool_->IdleSocketCount());
}

TEST_F(ClientSocketPoolBaseTest, ProxyAuthOnceSyncFails) {
  CreatePool(1, 1);
  connect_job_factory_->set_job_type(
      TestConnectJob::kMockAuthChallengeOnceFailingJob);

  TestAuthHelper auth_helper;
  auth_helper.InitHandle(params_, pool_.get());
  EXPECT_EQ(1u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));

  auth_helper.WaitForAuthAndRestartSync();
  EXPECT_THAT(auth_helper.WaitForResult(), IsError(ERR_CONNECTION_FAILED));

  EXPECT_EQ(1, auth_helper.auth_count());
  EXPECT_FALSE(pool_->HasGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(0, pool_->IdleSocketCount());
}

TEST_F(ClientSocketPoolBaseTest, ProxyAuthOnceDeleteHandle) {
  CreatePool(1, 1);
  connect_job_factory_->set_job_type(TestConnectJob::kMockAuthChallengeOnceJob);

  TestAuthHelper auth_helper;
  auth_helper.InitHandle(params_, pool_.get());
  EXPECT_EQ(1u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));

  auth_helper.WaitForAuth();
  EXPECT_EQ(1u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));

  auth_helper.handle()->Reset();

  EXPECT_EQ(1, auth_helper.auth_count());
  EXPECT_FALSE(pool_->HasGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(0, pool_->IdleSocketCount());
  EXPECT_FALSE(auth_helper.handle()->is_initialized());
  EXPECT_FALSE(auth_helper.handle()->socket());
}

TEST_F(ClientSocketPoolBaseTest, ProxyAuthOnceDeleteHandleSync) {
  CreatePool(1, 1);
  connect_job_factory_->set_job_type(TestConnectJob::kMockAuthChallengeOnceJob);

  TestAuthHelper auth_helper;
  auth_helper.InitHandle(params_, pool_.get());
  EXPECT_EQ(1u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));

  auth_helper.WaitForAuthAndResetHandleSync();
  EXPECT_EQ(1, auth_helper.auth_count());
  EXPECT_FALSE(pool_->HasGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(0, pool_->IdleSocketCount());
  EXPECT_FALSE(auth_helper.handle()->is_initialized());
  EXPECT_FALSE(auth_helper.handle()->socket());
}

TEST_F(ClientSocketPoolBaseTest, ProxyAuthOnceFlushWithError) {
  CreatePool(1, 1);
  connect_job_factory_->set_job_type(TestConnectJob::kMockAuthChallengeOnceJob);

  TestAuthHelper auth_helper;
  auth_helper.InitHandle(params_, pool_.get());
  EXPECT_EQ(1u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));

  auth_helper.WaitForAuth();

  pool_->FlushWithError(ERR_FAILED, "Network changed");
  base::RunLoop().RunUntilIdle();

  // When flushing the socket pool, bound sockets should delay returning the
  // error until completion.
  EXPECT_FALSE(auth_helper.have_result());
  EXPECT_EQ(1u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(0, pool_->IdleSocketCount());

  auth_helper.RestartWithAuth();
  // The callback should be called asynchronously.
  EXPECT_FALSE(auth_helper.have_result());

  EXPECT_THAT(auth_helper.WaitForResult(), IsError(ERR_FAILED));
  EXPECT_FALSE(pool_->HasGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(0, pool_->IdleSocketCount());
}

TEST_F(ClientSocketPoolBaseTest, ProxyAuthTwice) {
  CreatePool(1, 1);
  connect_job_factory_->set_job_type(
      TestConnectJob::kMockAuthChallengeTwiceJob);

  TestAuthHelper auth_helper;
  auth_helper.InitHandle(params_, pool_.get());
  EXPECT_EQ(1u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(LOAD_STATE_CONNECTING,
            pool_->GetLoadState(TestGroupId("a"), auth_helper.handle()));

  auth_helper.WaitForAuth();
  auth_helper.RestartWithAuth();
  EXPECT_EQ(1u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(1, auth_helper.auth_count());
  EXPECT_EQ(LOAD_STATE_ESTABLISHING_PROXY_TUNNEL,
            pool_->GetLoadState(TestGroupId("a"), auth_helper.handle()));

  auth_helper.WaitForAuth();
  EXPECT_EQ(1u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(2, auth_helper.auth_count());
  EXPECT_EQ(LOAD_STATE_ESTABLISHING_PROXY_TUNNEL,
            pool_->GetLoadState(TestGroupId("a"), auth_helper.handle()));

  auth_helper.RestartWithAuth();
  EXPECT_EQ(1u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(2, auth_helper.auth_count());
  EXPECT_EQ(LOAD_STATE_ESTABLISHING_PROXY_TUNNEL,
            pool_->GetLoadState(TestGroupId("a"), auth_helper.handle()));

  EXPECT_THAT(auth_helper.WaitForResult(), IsOk());
  EXPECT_EQ(2, auth_helper.auth_count());
  EXPECT_EQ(0u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(1, pool_->NumActiveSocketsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(0u, pool_->IdleSocketCountInGroup(TestGroupId("a")));
  EXPECT_EQ(0, pool_->IdleSocketCount());
}

TEST_F(ClientSocketPoolBaseTest, ProxyAuthTwiceFails) {
  CreatePool(1, 1);
  connect_job_factory_->set_job_type(
      TestConnectJob::kMockAuthChallengeTwiceFailingJob);

  TestAuthHelper auth_helper;
  auth_helper.InitHandle(params_, pool_.get());
  EXPECT_EQ(1u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));

  auth_helper.WaitForAuth();
  auth_helper.RestartWithAuth();
  EXPECT_EQ(1u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(1, auth_helper.auth_count());

  auth_helper.WaitForAuth();
  auth_helper.RestartWithAuth();
  EXPECT_EQ(1u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(2, auth_helper.auth_count());

  EXPECT_THAT(auth_helper.WaitForResult(), IsError(ERR_CONNECTION_FAILED));
  EXPECT_EQ(2, auth_helper.auth_count());
  EXPECT_FALSE(pool_->HasGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(0, pool_->IdleSocketCount());
}

// Makes sure that when a bound request is destroyed, a new ConnectJob is
// created, if needed.
TEST_F(ClientSocketPoolBaseTest,
       ProxyAuthCreateNewConnectJobOnDestroyBoundRequest) {
  CreatePool(1 /* max_sockets */, 1 /* max_sockets_per_group */);
  connect_job_factory_->set_job_type(
      TestConnectJob::kMockAuthChallengeOnceFailingJob);

  // First request creates a ConnectJob.
  TestAuthHelper auth_helper1;
  auth_helper1.InitHandle(params_, pool_.get());
  EXPECT_EQ(1u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));

  // A second request come in, but no new ConnectJob is needed, since the limit
  // has been reached.
  TestAuthHelper auth_helper2;
  auth_helper2.InitHandle(params_, pool_.get());
  EXPECT_EQ(1u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));

  // Run until the auth callback for the first request is invoked.
  auth_helper1.WaitForAuth();
  EXPECT_EQ(0, auth_helper2.auth_count());
  EXPECT_EQ(1u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(0, pool_->NumActiveSocketsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(0u, pool_->IdleSocketCountInGroup(TestGroupId("a")));

  // Make connect jobs succeed, then cancel the first request, which should
  // destroy the bound ConnectJob, and cause a new ConnectJob to start.
  connect_job_factory_->set_job_type(TestConnectJob::kMockPendingJob);
  auth_helper1.handle()->Reset();
  EXPECT_EQ(0, auth_helper2.auth_count());
  EXPECT_EQ(1u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));

  // The second ConnectJob should succeed.
  EXPECT_THAT(auth_helper2.WaitForResult(), IsOk());
  EXPECT_EQ(0, auth_helper2.auth_count());
  EXPECT_EQ(0u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));
}

// Makes sure that when a bound request is destroyed, a new ConnectJob is
// created for another group, if needed.
TEST_F(ClientSocketPoolBaseTest,
       ProxyAuthCreateNewConnectJobOnDestroyBoundRequestDifferentGroups) {
  CreatePool(1 /* max_sockets */, 1 /* max_sockets_per_group */);
  connect_job_factory_->set_job_type(
      TestConnectJob::kMockAuthChallengeOnceFailingJob);

  // First request creates a ConnectJob.
  TestAuthHelper auth_helper1;
  auth_helper1.InitHandle(params_, pool_.get(), DEFAULT_PRIORITY);
  EXPECT_EQ(1u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));

  // A second request come in, but no new ConnectJob is needed, since the limit
  // has been reached.
  TestAuthHelper auth_helper2;
  auth_helper2.InitHandle(params_, pool_.get(), DEFAULT_PRIORITY,
                          ClientSocketPool::RespectLimits::ENABLED,
                          TestGroupId("b"));
  EXPECT_EQ(1u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(0u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("b")));

  // Run until the auth callback for the first request is invoked.
  auth_helper1.WaitForAuth();
  EXPECT_EQ(0, auth_helper2.auth_count());
  EXPECT_EQ(1u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(0, pool_->NumActiveSocketsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(0u, pool_->IdleSocketCountInGroup(TestGroupId("a")));
  EXPECT_EQ(0u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("b")));
  EXPECT_EQ(0, pool_->NumActiveSocketsInGroupForTesting(TestGroupId("b")));
  EXPECT_EQ(0u, pool_->IdleSocketCountInGroup(TestGroupId("b")));

  // Make connect jobs succeed, then cancel the first request, which should
  // destroy the bound ConnectJob, and cause a new ConnectJob to start for the
  // other group.
  connect_job_factory_->set_job_type(TestConnectJob::kMockPendingJob);
  auth_helper1.handle()->Reset();
  EXPECT_EQ(0, auth_helper2.auth_count());
  EXPECT_FALSE(pool_->HasGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(1u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("b")));

  // The second ConnectJob should succeed.
  EXPECT_THAT(auth_helper2.WaitForResult(), IsOk());
  EXPECT_EQ(0, auth_helper2.auth_count());
  EXPECT_FALSE(pool_->HasGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(0u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("b")));
}

// Test that once an auth challenge is bound, that's the request that gets all
// subsequent calls and the socket itself.
TEST_F(ClientSocketPoolBaseTest, ProxyAuthStaysBound) {
  CreatePool(1, 1);
  connect_job_factory_->set_job_type(
      TestConnectJob::kMockAuthChallengeTwiceJob);

  // First request creates a ConnectJob.
  TestAuthHelper auth_helper1;
  auth_helper1.InitHandle(params_, pool_.get(), LOWEST);
  EXPECT_EQ(1u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));

  // A second, higher priority request is made.
  TestAuthHelper auth_helper2;
  auth_helper2.InitHandle(params_, pool_.get(), LOW);
  EXPECT_EQ(1u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));

  // Run until the auth callback for the second request is invoked.
  auth_helper2.WaitForAuth();
  EXPECT_EQ(0, auth_helper1.auth_count());
  EXPECT_EQ(1u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(0, pool_->NumActiveSocketsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(0u, pool_->IdleSocketCountInGroup(TestGroupId("a")));

  // Start a higher priority job. It shouldn't be able to steal |auth_helper2|'s
  // ConnectJob.
  TestAuthHelper auth_helper3;
  auth_helper3.InitHandle(params_, pool_.get(), HIGHEST);
  EXPECT_EQ(1u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));

  // Start a higher job that ignores limits, creating a hanging socket. It
  // shouldn't be able to steal |auth_helper2|'s ConnectJob.
  connect_job_factory_->set_job_type(TestConnectJob::kMockWaitingJob);
  TestAuthHelper auth_helper4;
  auth_helper4.InitHandle(params_, pool_.get(), HIGHEST,
                          ClientSocketPool::RespectLimits::DISABLED);
  EXPECT_EQ(2u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));

  // Restart with auth, and |auth_helper2|'s auth method should be invoked
  // again.
  auth_helper2.RestartWithAuth();
  auth_helper2.WaitForAuth();
  EXPECT_EQ(0, auth_helper1.auth_count());
  EXPECT_FALSE(auth_helper1.have_result());
  EXPECT_EQ(2, auth_helper2.auth_count());
  EXPECT_FALSE(auth_helper2.have_result());
  EXPECT_EQ(0, auth_helper3.auth_count());
  EXPECT_FALSE(auth_helper3.have_result());
  EXPECT_EQ(0, auth_helper4.auth_count());
  EXPECT_FALSE(auth_helper4.have_result());

  // Advance auth again, and |auth_helper2| should get the socket.
  auth_helper2.RestartWithAuth();
  EXPECT_THAT(auth_helper2.WaitForResult(), IsOk());
  // The hung ConnectJob for the RespectLimits::DISABLED request is still in the
  // socket pool.
  EXPECT_EQ(1u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(1, pool_->NumActiveSocketsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(0, auth_helper1.auth_count());
  EXPECT_FALSE(auth_helper1.have_result());
  EXPECT_EQ(0, auth_helper3.auth_count());
  EXPECT_FALSE(auth_helper3.have_result());
  EXPECT_EQ(0, auth_helper4.auth_count());
  EXPECT_FALSE(auth_helper4.have_result());

  // If the socket is returned to the socket pool, the RespectLimits::DISABLED
  // socket request should be able to claim it.
  auth_helper2.handle()->Reset();
  EXPECT_THAT(auth_helper4.WaitForResult(), IsOk());
  EXPECT_EQ(0, auth_helper1.auth_count());
  EXPECT_FALSE(auth_helper1.have_result());
  EXPECT_EQ(0, auth_helper3.auth_count());
  EXPECT_FALSE(auth_helper3.have_result());
  EXPECT_EQ(0, auth_helper4.auth_count());
}

enum class RefreshType {
  kServer,
  kProxy,
};

// Common base class to test RefreshGroup() when called from either
// OnSSLConfigForServersChanged() matching a specific group or the pool's proxy.
//
// Tests which test behavior specific to one or the other case should use
// ClientSocketPoolBaseTest directly. In particular, there is no "other group"
// when the pool's proxy matches.
class ClientSocketPoolBaseRefreshTest
    : public ClientSocketPoolBaseTest,
      public testing::WithParamInterface<RefreshType> {
 public:
  void CreatePoolForRefresh(int max_sockets,
                            int max_sockets_per_group,
                            bool enable_backup_connect_jobs = false) {
    switch (GetParam()) {
      case RefreshType::kServer:
        CreatePool(max_sockets, max_sockets_per_group,
                   enable_backup_connect_jobs);
        break;
      case RefreshType::kProxy:
        CreatePoolWithIdleTimeouts(
            max_sockets, max_sockets_per_group, kUnusedIdleSocketTimeout,
            ClientSocketPool::used_idle_socket_timeout(),
            enable_backup_connect_jobs,
            PacResultElementToProxyChain("HTTPS myproxy:70"));
        break;
    }
  }

  static ClientSocketPool::GroupId GetGroupId() {
    return TestGroupId("a", 443, url::kHttpsScheme);
  }

  static ClientSocketPool::GroupId GetGroupIdInPartition() {
    // Note this GroupId will match GetGroupId() unless
    // kPartitionConnectionsByNetworkAnonymizationKey is enabled.
    const SchemefulSite kSite(GURL("https://b/"));
    const auto kNetworkAnonymizationKey =
        NetworkAnonymizationKey::CreateSameSite(kSite);
    return TestGroupId("a", 443, url::kHttpsScheme,
                       PrivacyMode::PRIVACY_MODE_DISABLED,
                       kNetworkAnonymizationKey);
  }

  void OnSSLConfigForServersChanged() {
    switch (GetParam()) {
      case RefreshType::kServer:
        pool_->OnSSLConfigForServersChanged({HostPortPair("a", 443)});
        break;
      case RefreshType::kProxy:
        pool_->OnSSLConfigForServersChanged({HostPortPair("myproxy", 70)});
        break;
    }
  }
};

INSTANTIATE_TEST_SUITE_P(RefreshType,
                         ClientSocketPoolBaseRefreshTest,
                         ::testing::Values(RefreshType::kServer,
                                           RefreshType::kProxy));

TEST_P(ClientSocketPoolBaseRefreshTest, RefreshGroupCreatesNewConnectJobs) {
  CreatePoolForRefresh(kDefaultMaxSockets, kDefaultMaxSocketsPerGroup);
  const ClientSocketPool::GroupId kGroupId = GetGroupId();

  // First job will be waiting until it gets aborted.
  connect_job_factory_->set_job_type(TestConnectJob::kMockWaitingJob);

  ClientSocketHandle handle;
  TestCompletionCallback callback;
  EXPECT_THAT(
      handle.Init(kGroupId, params_, std::nullopt, DEFAULT_PRIORITY,
                  SocketTag(), ClientSocketPool::RespectLimits::ENABLED,
                  callback.callback(), ClientSocketPool::ProxyAuthCallback(),
                  pool_.get(), NetLogWithSource()),
      IsError(ERR_IO_PENDING));

  // Switch connect job types, so creating a new ConnectJob will result in
  // success.
  connect_job_factory_->set_job_type(TestConnectJob::kMockJob);

  OnSSLConfigForServersChanged();
  EXPECT_EQ(OK, callback.WaitForResult());
  ASSERT_TRUE(handle.socket());
  EXPECT_EQ(0, pool_->IdleSocketCount());
  ASSERT_TRUE(pool_->HasGroupForTesting(kGroupId));
  EXPECT_EQ(0u, pool_->IdleSocketCountInGroup(kGroupId));
  EXPECT_EQ(0u, pool_->NumConnectJobsInGroupForTesting(kGroupId));
  EXPECT_EQ(1, pool_->NumActiveSocketsInGroupForTesting(kGroupId));
}

TEST_P(ClientSocketPoolBaseRefreshTest, RefreshGroupClosesIdleConnectJobs) {
  base::test::ScopedFeatureList feature_list;
  feature_list.InitAndEnableFeature(
      features::kPartitionConnectionsByNetworkIsolationKey);

  CreatePoolForRefresh(kDefaultMaxSockets, kDefaultMaxSocketsPerGroup);
  const ClientSocketPool::GroupId kGroupId = GetGroupId();
  const ClientSocketPool::GroupId kGroupIdInPartition = GetGroupIdInPartition();

  EXPECT_EQ(
      OK, pool_->RequestSockets(kGroupId, params_, std::nullopt, 2,
                                CompletionOnceCallback(), NetLogWithSource()));

  EXPECT_EQ(
      OK, pool_->RequestSockets(kGroupIdInPartition, params_, std::nullopt, 2,
                                CompletionOnceCallback(), NetLogWithSource()));
  ASSERT_TRUE(pool_->HasGroupForTesting(kGroupId));
  ASSERT_TRUE(pool_->HasGroupForTesting(kGroupIdInPartition));
  EXPECT_EQ(4, pool_->IdleSocketCount());
  EXPECT_EQ(2u, pool_->IdleSocketCountInGroup(kGroupId));
  EXPECT_EQ(2u, pool_->IdleSocketCountInGroup(kGroupIdInPartition));

  OnSSLConfigForServersChanged();
  EXPECT_EQ(0, pool_->IdleSocketCount());
  EXPECT_FALSE(pool_->HasGroupForTesting(kGroupId));
  EXPECT_FALSE(pool_->HasGroupForTesting(kGroupIdInPartition));
}

TEST_F(ClientSocketPoolBaseTest,
       RefreshGroupDoesNotCloseIdleConnectJobsInOtherGroup) {
  CreatePool(kDefaultMaxSockets, kDefaultMaxSocketsPerGroup);
  const ClientSocketPool::GroupId kGroupId =
      TestGroupId("a", 443, url::kHttpsScheme);
  const ClientSocketPool::GroupId kOtherGroupId =
      TestGroupId("b", 443, url::kHttpsScheme);

  EXPECT_EQ(
      OK, pool_->RequestSockets(kOtherGroupId, params_, std::nullopt, 2,
                                CompletionOnceCallback(), NetLogWithSource()));
  ASSERT_TRUE(pool_->HasGroupForTesting(kOtherGroupId));
  EXPECT_EQ(2, pool_->IdleSocketCount());
  EXPECT_EQ(2u, pool_->IdleSocketCountInGroup(kOtherGroupId));

  pool_->OnSSLConfigForServersChanged({HostPortPair("a", 443)});
  ASSERT_TRUE(pool_->HasGroupForTesting(kOtherGroupId));
  EXPECT_EQ(2, pool_->IdleSocketCount());
  EXPECT_EQ(2u, pool_->IdleSocketCountInGroup(kOtherGroupId));
}

TEST_P(ClientSocketPoolBaseRefreshTest, RefreshGroupPreventsSocketReuse) {
  CreatePoolForRefresh(kDefaultMaxSockets, kDefaultMaxSocketsPerGroup);
  const ClientSocketPool::GroupId kGroupId = GetGroupId();

  ClientSocketHandle handle;
  TestCompletionCallback callback;
  EXPECT_THAT(
      handle.Init(kGroupId, params_, std::nullopt, DEFAULT_PRIORITY,
                  SocketTag(), ClientSocketPool::RespectLimits::ENABLED,
                  callback.callback(), ClientSocketPool::ProxyAuthCallback(),
                  pool_.get(), NetLogWithSource()),
      IsOk());
  ASSERT_TRUE(pool_->HasGroupForTesting(kGroupId));
  EXPECT_EQ(1, pool_->NumActiveSocketsInGroupForTesting(kGroupId));

  OnSSLConfigForServersChanged();

  handle.Reset();
  EXPECT_EQ(0, pool_->IdleSocketCount());
  EXPECT_FALSE(pool_->HasGroupForTesting(kGroupId));
}

TEST_F(ClientSocketPoolBaseTest,
       RefreshGroupDoesNotPreventSocketReuseInOtherGroup) {
  CreatePool(kDefaultMaxSockets, kDefaultMaxSocketsPerGroup);
  const ClientSocketPool::GroupId kGroupId =
      TestGroupId("a", 443, url::kHttpsScheme);
  const ClientSocketPool::GroupId kOtherGroupId =
      TestGroupId("b", 443, url::kHttpsScheme);

  ClientSocketHandle handle;
  TestCompletionCallback callback;
  EXPECT_THAT(
      handle.Init(kOtherGroupId, params_, std::nullopt, DEFAULT_PRIORITY,
                  SocketTag(), ClientSocketPool::RespectLimits::ENABLED,
                  callback.callback(), ClientSocketPool::ProxyAuthCallback(),
                  pool_.get(), NetLogWithSource()),
      IsOk());
  ASSERT_TRUE(pool_->HasGroupForTesting(kOtherGroupId));
  EXPECT_EQ(1, pool_->NumActiveSocketsInGroupForTesting(kOtherGroupId));

  pool_->OnSSLConfigForServersChanged({HostPortPair("a", 443)});

  handle.Reset();
  EXPECT_EQ(1, pool_->IdleSocketCount());
  ASSERT_TRUE(pool_->HasGroupForTesting(kOtherGroupId));
  EXPECT_EQ(1u, pool_->IdleSocketCountInGroup(kOtherGroupId));
}

TEST_P(ClientSocketPoolBaseRefreshTest,
       RefreshGroupReplacesBoundConnectJobOnConnect) {
  CreatePoolForRefresh(1, 1);
  const ClientSocketPool::GroupId kGroupId = GetGroupId();
  connect_job_factory_->set_job_type(TestConnectJob::kMockAuthChallengeOnceJob);

  TestAuthHelper auth_helper;
  auth_helper.InitHandle(params_, pool_.get(), DEFAULT_PRIORITY,
                         ClientSocketPool::RespectLimits::ENABLED, kGroupId);
  EXPECT_EQ(1u, pool_->NumConnectJobsInGroupForTesting(kGroupId));

  auth_helper.WaitForAuth();

  // This should update the generation, but not cancel the old ConnectJob - it's
  // not safe to do anything while waiting on the original ConnectJob.
  OnSSLConfigForServersChanged();

  // Providing auth credentials and restarting the request with them will cause
  // the ConnectJob to complete successfully, but the result will be discarded
  // because of the generation mismatch.
  auth_helper.RestartWithAuth();

  // Despite using ConnectJobs that simulate a single challenge, a second
  // challenge will be seen, due to using a new ConnectJob.
  auth_helper.WaitForAuth();
  auth_helper.RestartWithAuth();

  EXPECT_THAT(auth_helper.WaitForResult(), IsOk());
  EXPECT_TRUE(auth_helper.handle()->socket());
  EXPECT_EQ(2, auth_helper.auth_count());

  // When released, the socket will be returned to the socket pool, and
  // available for reuse.
  auth_helper.handle()->Reset();
  EXPECT_EQ(1, pool_->IdleSocketCount());
  ASSERT_TRUE(pool_->HasGroupForTesting(kGroupId));
  EXPECT_EQ(1u, pool_->IdleSocketCountInGroup(kGroupId));
}

// TODO(crbug.com/365771838): Add tests for non-ip protection nested proxy
// chains if support is enabled for all builds.
TEST_F(ClientSocketPoolBaseTest, RefreshProxyRefreshesAllGroups) {
  // Create a proxy chain containing `myproxy` (which is refreshed) and
  // nonrefreshedproxy (which is not), verifying that if any proxy in a chain is
  // refreshed, all groups are refreshed.
  auto proxy_chain = ProxyChain::ForIpProtection({
      PacResultElementToProxyServer("HTTPS myproxy:70"),
      PacResultElementToProxyServer("HTTPS nonrefreshedproxy:70"),
  });
  CreatePoolWithIdleTimeouts(kDefaultMaxSockets, kDefaultMaxSocketsPerGroup,
                             kUnusedIdleSocketTimeout,
                             ClientSocketPool::used_idle_socket_timeout(),
                             false /* no backup connect jobs */, proxy_chain);

  const ClientSocketPool::GroupId kGroupId1 =
      TestGroupId("a", 443, url::kHttpsScheme);
  const ClientSocketPool::GroupId kGroupId2 =
      TestGroupId("b", 443, url::kHttpsScheme);
  const ClientSocketPool::GroupId kGroupId3 =
      TestGroupId("c", 443, url::kHttpsScheme);

  // Make three sockets in three different groups. The third socket is released
  // to the pool as idle.
  ClientSocketHandle handle1, handle2, handle3;
  TestCompletionCallback callback;
  EXPECT_THAT(
      handle1.Init(kGroupId1, params_, std::nullopt, DEFAULT_PRIORITY,
                   SocketTag(), ClientSocketPool::RespectLimits::ENABLED,
                   callback.callback(), ClientSocketPool::ProxyAuthCallback(),
                   pool_.get(), NetLogWithSource()),
      IsOk());
  EXPECT_THAT(
      handle2.Init(kGroupId2, params_, std::nullopt, DEFAULT_PRIORITY,
                   SocketTag(), ClientSocketPool::RespectLimits::ENABLED,
                   callback.callback(), ClientSocketPool::ProxyAuthCallback(),
                   pool_.get(), NetLogWithSource()),
      IsOk());
  EXPECT_THAT(
      handle3.Init(kGroupId3, params_, std::nullopt, DEFAULT_PRIORITY,
                   SocketTag(), ClientSocketPool::RespectLimits::ENABLED,
                   callback.callback(), ClientSocketPool::ProxyAuthCallback(),
                   pool_.get(), NetLogWithSource()),
      IsOk());
  handle3.Reset();
  ASSERT_TRUE(pool_->HasGroupForTesting(kGroupId1));
  EXPECT_EQ(1, pool_->NumActiveSocketsInGroupForTesting(kGroupId1));
  ASSERT_TRUE(pool_->HasGroupForTesting(kGroupId2));
  EXPECT_EQ(1, pool_->NumActiveSocketsInGroupForTesting(kGroupId2));
  ASSERT_TRUE(pool_->HasGroupForTesting(kGroupId3));
  EXPECT_EQ(1u, pool_->IdleSocketCountInGroup(kGroupId3));

  // Changes to some other proxy do not affect the pool. The idle socket remains
  // alive and closing |handle2| makes the socket available for the pool.
  pool_->OnSSLConfigForServersChanged({HostPortPair("someotherproxy", 70)});

  ASSERT_TRUE(pool_->HasGroupForTesting(kGroupId1));
  EXPECT_EQ(1, pool_->NumActiveSocketsInGroupForTesting(kGroupId1));
  ASSERT_TRUE(pool_->HasGroupForTesting(kGroupId2));
  EXPECT_EQ(1, pool_->NumActiveSocketsInGroupForTesting(kGroupId2));
  ASSERT_TRUE(pool_->HasGroupForTesting(kGroupId3));
  EXPECT_EQ(1u, pool_->IdleSocketCountInGroup(kGroupId3));

  handle2.Reset();
  ASSERT_TRUE(pool_->HasGroupForTesting(kGroupId2));
  EXPECT_EQ(1u, pool_->IdleSocketCountInGroup(kGroupId2));

  // Changes to the matching proxy refreshes all groups.
  pool_->OnSSLConfigForServersChanged({HostPortPair("myproxy", 70)});

  // Idle sockets are closed.
  EXPECT_EQ(0, pool_->IdleSocketCount());
  EXPECT_FALSE(pool_->HasGroupForTesting(kGroupId2));
  EXPECT_FALSE(pool_->HasGroupForTesting(kGroupId3));

  // The active socket, however, continues to be active.
  ASSERT_TRUE(pool_->HasGroupForTesting(kGroupId1));
  EXPECT_EQ(1, pool_->NumActiveSocketsInGroupForTesting(kGroupId1));

  // Closing it does not make it available for the pool.
  handle1.Reset();
  EXPECT_EQ(0, pool_->IdleSocketCount());
  EXPECT_FALSE(pool_->HasGroupForTesting(kGroupId1));
}

TEST_F(ClientSocketPoolBaseTest, RefreshBothPrivacyAndNormalSockets) {
  CreatePool(kDefaultMaxSockets, kDefaultMaxSocketsPerGroup);

  const ClientSocketPool::GroupId kGroupId = TestGroupId(
      "a", 443, url::kHttpsScheme, PrivacyMode::PRIVACY_MODE_DISABLED);
  const ClientSocketPool::GroupId kGroupIdPrivacy = TestGroupId(
      "a", 443, url::kHttpsScheme, PrivacyMode::PRIVACY_MODE_ENABLED);
  const ClientSocketPool::GroupId kOtherGroupId =
      TestGroupId("b", 443, url::kHttpsScheme);

  // Make a socket in each groups.
  ClientSocketHandle handle1, handle2, handle3;
  TestCompletionCallback callback;
  EXPECT_THAT(
      handle1.Init(kGroupId, params_, std::nullopt, DEFAULT_PRIORITY,
                   SocketTag(), ClientSocketPool::RespectLimits::ENABLED,
                   callback.callback(), ClientSocketPool::ProxyAuthCallback(),
                   pool_.get(), NetLogWithSource()),
      IsOk());
  EXPECT_THAT(
      handle2.Init(kGroupIdPrivacy, params_, std::nullopt, DEFAULT_PRIORITY,
                   SocketTag(), ClientSocketPool::RespectLimits::ENABLED,
                   callback.callback(), ClientSocketPool::ProxyAuthCallback(),
                   pool_.get(), NetLogWithSource()),
      IsOk());
  EXPECT_THAT(
      handle3.Init(kOtherGroupId, params_, std::nullopt, DEFAULT_PRIORITY,
                   SocketTag(), ClientSocketPool::RespectLimits::ENABLED,
                   callback.callback(), ClientSocketPool::ProxyAuthCallback(),
                   pool_.get(), NetLogWithSource()),
      IsOk());
  ASSERT_TRUE(pool_->HasGroupForTesting(kGroupId));
  EXPECT_EQ(1, pool_->NumActiveSocketsInGroupForTesting(kGroupId));
  ASSERT_TRUE(pool_->HasGroupForTesting(kGroupIdPrivacy));
  EXPECT_EQ(1, pool_->NumActiveSocketsInGroupForTesting(kGroupIdPrivacy));
  ASSERT_TRUE(pool_->HasGroupForTesting(kOtherGroupId));
  EXPECT_EQ(1, pool_->NumActiveSocketsInGroupForTesting(kOtherGroupId));

  pool_->OnSSLConfigForServersChanged({HostPortPair("a", 443)});

  // Active sockets continue to be active.
  ASSERT_TRUE(pool_->HasGroupForTesting(kGroupId));
  EXPECT_EQ(1, pool_->NumActiveSocketsInGroupForTesting(kGroupId));
  ASSERT_TRUE(pool_->HasGroupForTesting(kGroupIdPrivacy));
  EXPECT_EQ(1, pool_->NumActiveSocketsInGroupForTesting(kGroupIdPrivacy));
  ASSERT_TRUE(pool_->HasGroupForTesting(kOtherGroupId));
  EXPECT_EQ(1, pool_->NumActiveSocketsInGroupForTesting(kOtherGroupId));

  // Closing them leaves kOtherGroupId alone, but kGroupId and kGroupIdPrivacy
  // are unusable.
  handle1.Reset();
  handle2.Reset();
  handle3.Reset();
  EXPECT_EQ(1, pool_->IdleSocketCount());
  EXPECT_FALSE(pool_->HasGroupForTesting(kGroupId));
  EXPECT_FALSE(pool_->HasGroupForTesting(kGroupIdPrivacy));
  EXPECT_TRUE(pool_->HasGroupForTesting(kOtherGroupId));
  EXPECT_EQ(1u, pool_->IdleSocketCountInGroup(kOtherGroupId));
}

}  // namespace

}  // namespace net

"""


```