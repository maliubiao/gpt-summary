Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is part of a unit test file for `ThrottlingURLLoader` in the Chromium Blink engine. I need to identify the features being tested in this section of the file and summarize them.

Here's a breakdown of the tests:

1. **`CancelBeforeResponse`**: Tests canceling a request before the response is received.
2. **`DeleteBeforeResponse`**: Tests deleting the `ThrottlingURLLoader` before a response is received.
3. **`CancelBeforeWillProcessResponse`**: Tests canceling a request in the `BeforeWillProcessResponse` hook.
4. **`DeleteBeforeWillProcessResponse`**: Tests deleting the `ThrottlingURLLoader` in the `BeforeWillProcessResponse` hook.
5. **`DeferBeforeResponse`**: Tests deferring the response processing and then resuming.
6. **`PipeClosure`**: Tests the behavior when the underlying network pipe is closed.
7. **`ResumeNoOpIfNotDeferred`**: Tests that calling `Resume` when not deferred has no effect.
8. **`CancelNoOpIfAlreadyCanceled`**: Tests that calling `CancelWithError` when already canceled has no effect.
9. **`ResumeNoOpIfAlreadyCanceled`**: Tests that calling `Resume` when already canceled has no effect.
10. **`MultipleThrottlesBasicSupport`**: Tests the basic interaction with multiple URL loader throttles.
11. **`BlockWithOneOfMultipleThrottles`**: Tests blocking a request with one of multiple throttles and then resuming.
12. **`BlockWithMultipleThrottles`**: Tests blocking a request with multiple throttles and then resuming.
13. **`DestroyingThrottlingURLLoaderInDelegateCall_Response`**: Tests destroying the `ThrottlingURLLoader` during a response processing delegate call.
14. **`DestroyingThrottlingURLLoaderInDelegateCall_Redirect`**: Tests destroying the `ThrottlingURLLoader` during a redirect processing delegate call.
15. **`RestartWithURLReset`**: Tests restarting a request with the original URL from `BeforeWillProcessResponse`.
16. **`MultipleRestartWithURLReset`**: Tests multiple throttles trying to restart a request with the original URL from `BeforeWillProcessResponse`.
17. **`RestartWithURLResetBeforeWillRedirectRequest`**: Tests restarting a request with the original URL from `BeforeWillRedirectRequest`.

Essentially, this part of the test suite focuses on the lifecycle management of the `ThrottlingURLLoader`, especially around canceling, deferring, and restarting requests, as well as its interaction with multiple throttles and the impact of destroying the loader at specific points in the process.
这是对`blink/common/loader/throttling_url_loader_unittest.cc`文件的第二部分功能的归纳，延续了第一部分的内容，主要关注`ThrottlingURLLoader`在不同场景下的行为，特别是与取消、延迟、恢复以及与多个Throttle协同工作相关的测试。

**归纳 `ThrottlingURLLoader` 的功能测试 (第 2 部分):**

这部分测试主要验证了 `ThrottlingURLLoader` 在处理网络请求生命周期中的各种边缘情况和交互行为，特别是以下几个方面：

1. **请求取消 (Cancellation):**
   - **在接收响应前取消 (`CancelBeforeResponse`)**: 验证了在收到服务器响应之前，Throttle可以取消请求，并正确通知客户端错误。
   - **在 `BeforeWillProcessResponse` 阶段取消 (`CancelBeforeWillProcessResponse`)**: 验证了在 `BeforeWillProcessResponse` 回调中可以取消请求。
   - **已取消后再次取消无效 (`CancelNoOpIfAlreadyCanceled`)**: 验证了如果请求已经被取消，再次调用取消方法不会产生额外的副作用。

2. **提前删除 `ThrottlingURLLoader` (Early Deletion):**
   - **在接收响应前删除 (`DeleteBeforeResponse`)**: 模拟了在接收到响应前 `ThrottlingURLLoader` 被删除的情况，验证了不会发生崩溃，并且客户端不会收到响应。
   - **在 `BeforeWillProcessResponse` 阶段删除 (`DeleteBeforeWillProcessResponse`)**: 模拟了在 `BeforeWillProcessResponse` 回调中 `ThrottlingURLLoader` 被删除的情况。

3. **请求延迟和恢复 (Defer and Resume):**
   - **在接收响应前延迟 (`DeferBeforeResponse`)**: 验证了 Throttle 可以在接收到响应之前延迟请求的处理，并在稍后恢复，以及延迟期间的行为。
   - **未延迟时恢复无效 (`ResumeNoOpIfNotDeferred`)**: 验证了如果没有调用延迟，调用恢复方法不会有任何作用。
   - **已取消后恢复无效 (`ResumeNoOpIfAlreadyCanceled`)**: 验证了如果请求已经被取消，调用恢复方法不会使请求重新开始。

4. **管道关闭 (Pipe Closure):**
   - **模拟底层网络连接中断 (`PipeClosure`)**: 验证了当底层网络连接关闭时，`ThrottlingURLLoader` 会正确地通知客户端请求中止。

5. **与多个 Throttle 协同工作 (Multiple Throttles):**
   - **基本支持 (`MultipleThrottlesBasicSupport`)**: 验证了 `ThrottlingURLLoader` 可以与多个 Throttle 对象协同工作，每个 Throttle 都能接收到相应的回调。
   - **单个 Throttle 阻塞请求 (`BlockWithOneOfMultipleThrottles`)**: 验证了当多个 Throttle 中有一个 Throttle 决定延迟请求时，请求会被阻塞，直到该 Throttle 允许继续。
   - **多个 Throttle 阻塞请求 (`BlockWithMultipleThrottles`)**: 验证了当多个 Throttle 都决定延迟请求时，请求会被阻塞，直到所有阻塞的 Throttle 都允许继续。

6. **在 Delegate 回调中销毁 `ThrottlingURLLoader` (Destruction in Delegate Callbacks):**
   - **在响应处理 Delegate 中销毁 (`DestroyingThrottlingURLLoaderInDelegateCall_Response`)**: 验证了在处理响应的 Delegate 回调中销毁 `ThrottlingURLLoader` 的安全性，确保 Throttle 对象仍然存活。
   - **在重定向处理 Delegate 中销毁 (`DestroyingThrottlingURLLoaderInDelegateCall_Redirect`)**:  验证了在处理重定向的 Delegate 回调中销毁 `ThrottlingURLLoader` 的安全性。

7. **请求重启 (Request Restart with URL Reset):**
   - **从 `BeforeWillProcessResponse` 重启 (`RestartWithURLReset`)**: 验证了 Throttle 可以在 `BeforeWillProcessResponse` 阶段请求重启，并且会使用原始的 URL。
   - **多个 Throttle 从 `BeforeWillProcessResponse` 重启 (`MultipleRestartWithURLReset`)**: 验证了即使多个 Throttle 同时请求重启，请求也只会重启一次，并且使用原始的 URL。
   - **从 `BeforeWillRedirectRequest` 重启 (`RestartWithURLResetBeforeWillRedirectRequest`)**: 验证了 Throttle 可以在 `BeforeWillRedirectRequest` 阶段请求重启，并且会使用原始的 URL。

**与 JavaScript, HTML, CSS 的关系举例:**

这些测试主要关注网络请求的底层控制，与 JavaScript, HTML, CSS 的直接功能关系相对较弱，但其行为会影响到这些上层技术的功能表现。

* **JavaScript `fetch` API 或 `XMLHttpRequest`**:  如果 JavaScript 发起的网络请求被 Throttle 延迟 (`DeferBeforeResponse`) 或取消 (`CancelBeforeResponse`)，那么 JavaScript 的回调函数将会在延迟后执行或收到错误通知。重启请求 (`RestartWithURLReset`) 可能会导致 JavaScript 观察到多次请求的发生。
    * **假设输入**: JavaScript 调用 `fetch('https://example.com')`.
    * **输出**: 如果 Throttle 延迟了请求，`fetch` 的 Promise 将会在 Throttle 恢复后 resolve 或 reject。如果 Throttle 取消了请求，`fetch` 的 Promise 将会 reject。
* **HTML `<link>` 或 `<img>` 标签**:  浏览器加载 CSS 文件 (`<link>`) 或图片 (`<img>`) 时，`ThrottlingURLLoader` 的行为会影响资源的加载速度和结果。例如，如果 Throttle 决定延迟加载图片，用户可能会看到图片加载的延迟。如果请求被取消，图片可能无法显示。
* **CSS `@import` 规则**:  类似地，如果 CSS 文件中使用了 `@import` 引入其他 CSS 文件，`ThrottlingURLLoader` 的行为会影响这些依赖文件的加载。

**用户或编程常见的使用错误举例:**

虽然 `ThrottlingURLLoader` 是 Chromium 内部的机制，开发者一般不会直接使用，但理解其行为有助于理解网络请求的生命周期和可能出现的错误。

* **误以为请求已经发出**: 如果开发者在 `will_start_request` 回调中设置了延迟，但误以为请求已经发送到服务器，并开始依赖服务器的响应，这就会导致逻辑错误，因为请求实际上是被 Throttle 阻塞了。
* **在 Delegate 回调中进行不安全的操作**:  虽然测试用例验证了在 Delegate 回调中销毁 `ThrottlingURLLoader` 的安全性，但在这些回调中执行复杂或耗时的操作仍然可能引入风险，例如死锁或资源泄漏。

总的来说，这部分测试覆盖了 `ThrottlingURLLoader` 在各种复杂场景下的行为，确保了其稳定性和可靠性，为 Chromium 的网络请求处理提供了坚实的基础。

Prompt: 
```
这是目录为blink/common/loader/throttling_url_loader_unittest.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能

"""
e* delegate, bool* /* defer */,
         std::vector<std::string>* removed_headers,
         net::HttpRequestHeaders* modified_headers,
         net::HttpRequestHeaders* modified_cors_exempt_headers) {
        removed_headers->push_back("X-Test-Header-1");
        removed_headers->push_back("X-Test-Header-2");
        modified_headers->SetHeader("X-Test-Header-4", "Throttle2");
      }));

  client_.set_on_received_redirect_callback(base::BindLambdaForTesting(
      [&]() { loader_->FollowRedirect({}, {}, {}); }));

  CreateLoaderAndStart();
  factory_.NotifyClientOnReceiveRedirect();
  base::RunLoop().RunUntilIdle();

  ASSERT_FALSE(factory_.headers_removed_on_redirect().empty());
  EXPECT_THAT(factory_.headers_removed_on_redirect(),
              testing::ElementsAre("X-Test-Header-0", "X-Test-Header-1",
                                   "X-Test-Header-2"));
  ASSERT_FALSE(factory_.headers_modified_on_redirect().IsEmpty());
  EXPECT_EQ(
      "X-Test-Header-3: Foo\r\n"
      "X-Test-Header-4: Throttle2\r\n\r\n",
      factory_.headers_modified_on_redirect().ToString());
}

TEST_F(ThrottlingURLLoaderTest, CancelBeforeResponse) {
  throttle_->set_will_process_response_callback(base::BindLambdaForTesting(
      [](blink::URLLoaderThrottle::Delegate* delegate, bool* defer) {
        delegate->CancelWithError(net::ERR_ACCESS_DENIED);
      }));

  base::RunLoop run_loop;
  client_.set_on_complete_callback(
      base::BindLambdaForTesting([&run_loop](int error) {
        EXPECT_EQ(net::ERR_ACCESS_DENIED, error);
        run_loop.Quit();
      }));

  CreateLoaderAndStart();

  factory_.NotifyClientOnReceiveResponse();

  run_loop.Run();

  EXPECT_EQ(1u, throttle_->will_start_request_called());
  EXPECT_EQ(0u, throttle_->will_redirect_request_called());
  EXPECT_EQ(1u, throttle_->before_will_process_response_called());
  EXPECT_EQ(1u, throttle_->will_process_response_called());

  EXPECT_TRUE(
      throttle_->observed_response_url().EqualsIgnoringRef(request_url));

  EXPECT_EQ(0u, client_.on_received_response_called());
  EXPECT_EQ(0u, client_.on_received_redirect_called());
  EXPECT_EQ(1u, client_.on_complete_called());
}

TEST_F(ThrottlingURLLoaderTest, DeleteBeforeResponse) {
  base::RunLoop run_loop;
  throttle_->set_will_process_response_callback(base::BindLambdaForTesting(
      [this, &run_loop](blink::URLLoaderThrottle::Delegate* delegate,
                        bool* defer) {
        ResetLoader();
        run_loop.Quit();
      }));

  CreateLoaderAndStart();

  factory_.NotifyClientOnReceiveResponse();

  run_loop.Run();

  EXPECT_EQ(0u, client_.on_received_response_called());
  EXPECT_EQ(0u, client_.on_received_redirect_called());
  EXPECT_EQ(0u, client_.on_complete_called());
}

TEST_F(ThrottlingURLLoaderTest, CancelBeforeWillProcessResponse) {
  throttle_->set_before_will_process_response_callback(
      base::BindLambdaForTesting(
          [](blink::URLLoaderThrottle::Delegate* delegate,
             RestartWithURLReset* restart_with_url_reset) {
            delegate->CancelWithError(net::ERR_ACCESS_DENIED);
          }));

  base::RunLoop run_loop;
  client_.set_on_complete_callback(
      base::BindLambdaForTesting([&run_loop](int error) {
        EXPECT_EQ(net::ERR_ACCESS_DENIED, error);
        run_loop.Quit();
      }));

  CreateLoaderAndStart();

  factory_.NotifyClientOnReceiveResponse();

  run_loop.Run();

  EXPECT_EQ(1u, throttle_->will_start_request_called());
  EXPECT_EQ(0u, throttle_->will_redirect_request_called());
  EXPECT_EQ(1u, throttle_->before_will_process_response_called());
  EXPECT_EQ(0u, throttle_->will_process_response_called());
  EXPECT_EQ(0u, client_.on_received_response_called());
  EXPECT_EQ(0u, client_.on_received_redirect_called());
  EXPECT_EQ(1u, client_.on_complete_called());
}

TEST_F(ThrottlingURLLoaderTest, DeleteBeforeWillProcessResponse) {
  base::RunLoop run_loop;
  throttle_->set_before_will_process_response_callback(
      base::BindLambdaForTesting(
          [this, &run_loop](blink::URLLoaderThrottle::Delegate* delegate,
                            RestartWithURLReset* restart_with_url_reset) {
            ResetLoader();
            run_loop.Quit();
          }));

  CreateLoaderAndStart();

  factory_.NotifyClientOnReceiveResponse();

  run_loop.Run();

  EXPECT_EQ(0u, client_.on_received_response_called());
  EXPECT_EQ(0u, client_.on_received_redirect_called());
  EXPECT_EQ(0u, client_.on_complete_called());
}

TEST_F(ThrottlingURLLoaderTest, DeferBeforeResponse) {
  base::RunLoop run_loop1;
  throttle_->set_will_process_response_callback(base::BindRepeating(
      [](const base::RepeatingClosure& quit_closure,
         blink::URLLoaderThrottle::Delegate* delegate, bool* defer) {
        *defer = true;
        quit_closure.Run();
      },
      run_loop1.QuitClosure()));

  base::RunLoop run_loop2;
  client_.set_on_complete_callback(
      base::BindLambdaForTesting([&run_loop2](int error) {
        EXPECT_EQ(net::ERR_UNEXPECTED, error);
        run_loop2.Quit();
      }));

  CreateLoaderAndStart();

  factory_.NotifyClientOnReceiveResponse();

  run_loop1.Run();

  EXPECT_EQ(1u, throttle_->will_start_request_called());
  EXPECT_EQ(0u, throttle_->will_redirect_request_called());
  EXPECT_EQ(1u, throttle_->before_will_process_response_called());
  EXPECT_EQ(1u, throttle_->will_process_response_called());

  EXPECT_TRUE(
      throttle_->observed_response_url().EqualsIgnoringRef(request_url));

  factory_.NotifyClientOnComplete(net::ERR_UNEXPECTED);

  base::RunLoop run_loop3;
  run_loop3.RunUntilIdle();

  EXPECT_EQ(0u, client_.on_received_response_called());
  EXPECT_EQ(0u, client_.on_received_redirect_called());
  EXPECT_EQ(0u, client_.on_complete_called());

  throttle_->delegate()->Resume();
  run_loop2.Run();

  EXPECT_EQ(1u, throttle_->will_start_request_called());
  EXPECT_EQ(0u, throttle_->will_redirect_request_called());
  EXPECT_EQ(1u, throttle_->before_will_process_response_called());
  EXPECT_EQ(1u, throttle_->will_process_response_called());

  EXPECT_TRUE(
      throttle_->observed_response_url().EqualsIgnoringRef(request_url));

  EXPECT_EQ(1u, client_.on_received_response_called());
  EXPECT_EQ(0u, client_.on_received_redirect_called());
  EXPECT_EQ(1u, client_.on_complete_called());
}

TEST_F(ThrottlingURLLoaderTest, PipeClosure) {
  base::RunLoop run_loop;
  client_.set_on_complete_callback(
      base::BindLambdaForTesting([&run_loop](int error) {
        EXPECT_EQ(net::ERR_ABORTED, error);
        run_loop.Quit();
      }));

  CreateLoaderAndStart();

  factory_.CloseClientPipe();

  run_loop.Run();

  EXPECT_EQ(1u, throttle_->will_start_request_called());
  EXPECT_EQ(0u, throttle_->will_redirect_request_called());
  EXPECT_EQ(0u, throttle_->before_will_process_response_called());
  EXPECT_EQ(0u, throttle_->will_process_response_called());

  EXPECT_EQ(0u, client_.on_received_response_called());
  EXPECT_EQ(0u, client_.on_received_redirect_called());
  EXPECT_EQ(1u, client_.on_complete_called());
}

TEST_F(ThrottlingURLLoaderTest, ResumeNoOpIfNotDeferred) {
  auto resume_callback = base::BindRepeating(
      [](blink::URLLoaderThrottle::Delegate* delegate, bool* /* defer */) {
        delegate->Resume();
        delegate->Resume();
      });
  throttle_->set_will_start_request_callback(resume_callback);
  throttle_->set_will_process_response_callback(std::move(resume_callback));
  throttle_->set_will_redirect_request_callback(base::BindLambdaForTesting(
      [](blink::URLLoaderThrottle::Delegate* delegate, bool* /* defer */,
         std::vector<std::string>* /* removed_headers */,
         net::HttpRequestHeaders* /* modified_headers */,
         net::HttpRequestHeaders* /* modified_cors_exempt_headers */) {
        delegate->Resume();
        delegate->Resume();
      }));

  base::RunLoop run_loop;
  client_.set_on_complete_callback(
      base::BindLambdaForTesting([&run_loop](int error) {
        EXPECT_EQ(net::OK, error);
        run_loop.Quit();
      }));

  CreateLoaderAndStart();
  factory_.NotifyClientOnReceiveRedirect();
  factory_.NotifyClientOnReceiveResponse();
  factory_.NotifyClientOnComplete(net::OK);

  run_loop.Run();

  EXPECT_EQ(1u, throttle_->will_start_request_called());
  EXPECT_EQ(1u, throttle_->will_redirect_request_called());
  EXPECT_EQ(1u, throttle_->before_will_process_response_called());
  EXPECT_EQ(1u, throttle_->will_process_response_called());

  EXPECT_TRUE(
      throttle_->observed_response_url().EqualsIgnoringRef(redirect_url));

  EXPECT_EQ(1u, client_.on_received_response_called());
  EXPECT_EQ(1u, client_.on_received_redirect_called());
  EXPECT_EQ(1u, client_.on_complete_called());
}

TEST_F(ThrottlingURLLoaderTest, CancelNoOpIfAlreadyCanceled) {
  throttle_->set_will_start_request_callback(base::BindRepeating(
      [](blink::URLLoaderThrottle::Delegate* delegate, bool* defer) {
        delegate->CancelWithError(net::ERR_ACCESS_DENIED);
        delegate->CancelWithError(net::ERR_UNEXPECTED);
      }));

  base::RunLoop run_loop;
  client_.set_on_complete_callback(
      base::BindLambdaForTesting([&run_loop](int error) {
        EXPECT_EQ(net::ERR_ACCESS_DENIED, error);
        run_loop.Quit();
      }));

  CreateLoaderAndStart();
  throttle_->delegate()->CancelWithError(net::ERR_INVALID_ARGUMENT);
  run_loop.Run();

  EXPECT_EQ(1u, throttle_->will_start_request_called());
  EXPECT_EQ(0u, throttle_->will_redirect_request_called());
  EXPECT_EQ(0u, throttle_->before_will_process_response_called());
  EXPECT_EQ(0u, throttle_->will_process_response_called());

  EXPECT_EQ(0u, factory_.create_loader_and_start_called());

  EXPECT_EQ(0u, client_.on_received_response_called());
  EXPECT_EQ(0u, client_.on_received_redirect_called());
  EXPECT_EQ(1u, client_.on_complete_called());
}

TEST_F(ThrottlingURLLoaderTest, ResumeNoOpIfAlreadyCanceled) {
  throttle_->set_will_process_response_callback(base::BindLambdaForTesting(
      [](blink::URLLoaderThrottle::Delegate* delegate, bool* defer) {
        delegate->CancelWithError(net::ERR_ACCESS_DENIED);
        delegate->Resume();
      }));

  base::RunLoop run_loop1;
  client_.set_on_complete_callback(
      base::BindLambdaForTesting([&run_loop1](int error) {
        EXPECT_EQ(net::ERR_ACCESS_DENIED, error);
        run_loop1.Quit();
      }));

  CreateLoaderAndStart();

  factory_.NotifyClientOnReceiveResponse();

  run_loop1.Run();

  throttle_->delegate()->Resume();

  base::RunLoop run_loop2;
  run_loop2.RunUntilIdle();

  EXPECT_EQ(1u, throttle_->will_start_request_called());
  EXPECT_EQ(0u, throttle_->will_redirect_request_called());
  EXPECT_EQ(1u, throttle_->before_will_process_response_called());
  EXPECT_EQ(1u, throttle_->will_process_response_called());

  EXPECT_TRUE(
      throttle_->observed_response_url().EqualsIgnoringRef(request_url));

  EXPECT_EQ(0u, client_.on_received_response_called());
  EXPECT_EQ(0u, client_.on_received_redirect_called());
  EXPECT_EQ(1u, client_.on_complete_called());
}

TEST_F(ThrottlingURLLoaderTest, MultipleThrottlesBasicSupport) {
  throttles_.emplace_back(std::make_unique<TestURLLoaderThrottle>());
  auto* throttle2 =
      static_cast<TestURLLoaderThrottle*>(throttles_.back().get());
  CreateLoaderAndStart();
  factory_.NotifyClientOnReceiveResponse();

  EXPECT_EQ(1u, throttle_->will_start_request_called());
  EXPECT_EQ(1u, throttle2->will_start_request_called());
}

TEST_F(ThrottlingURLLoaderTest, BlockWithOneOfMultipleThrottles) {
  throttles_.emplace_back(std::make_unique<TestURLLoaderThrottle>());
  auto* throttle2 =
      static_cast<TestURLLoaderThrottle*>(throttles_.back().get());
  throttle2->set_will_start_request_callback(base::BindLambdaForTesting(
      [](blink::URLLoaderThrottle::Delegate* delegate, bool* defer) {
        *defer = true;
      }));

  base::RunLoop loop;
  client_.set_on_complete_callback(
      base::BindLambdaForTesting([&loop](int error) {
        EXPECT_EQ(net::OK, error);
        loop.Quit();
      }));

  CreateLoaderAndStart();

  EXPECT_EQ(1u, throttle_->will_start_request_called());
  EXPECT_EQ(1u, throttle2->will_start_request_called());
  EXPECT_EQ(0u, throttle_->will_redirect_request_called());
  EXPECT_EQ(0u, throttle2->will_redirect_request_called());
  EXPECT_EQ(0u, throttle_->before_will_process_response_called());
  EXPECT_EQ(0u, throttle2->before_will_process_response_called());
  EXPECT_EQ(0u, throttle_->will_process_response_called());
  EXPECT_EQ(0u, throttle2->will_process_response_called());

  EXPECT_EQ(0u, factory_.create_loader_and_start_called());

  EXPECT_EQ(0u, client_.on_received_response_called());
  EXPECT_EQ(0u, client_.on_received_redirect_called());
  EXPECT_EQ(0u, client_.on_complete_called());

  throttle2->delegate()->Resume();
  factory_.factory_remote().FlushForTesting();

  EXPECT_EQ(1u, factory_.create_loader_and_start_called());

  factory_.NotifyClientOnReceiveResponse();
  factory_.NotifyClientOnComplete(net::OK);

  loop.Run();

  EXPECT_EQ(1u, throttle_->will_start_request_called());
  EXPECT_EQ(1u, throttle2->will_start_request_called());
  EXPECT_EQ(0u, throttle_->will_redirect_request_called());
  EXPECT_EQ(0u, throttle2->will_redirect_request_called());
  EXPECT_EQ(1u, throttle_->before_will_process_response_called());
  EXPECT_EQ(1u, throttle2->before_will_process_response_called());
  EXPECT_EQ(1u, throttle_->will_process_response_called());
  EXPECT_EQ(1u, throttle2->will_process_response_called());

  EXPECT_TRUE(
      throttle_->observed_response_url().EqualsIgnoringRef(request_url));
  EXPECT_TRUE(
      throttle2->observed_response_url().EqualsIgnoringRef(request_url));

  EXPECT_EQ(1u, client_.on_received_response_called());
  EXPECT_EQ(0u, client_.on_received_redirect_called());
  EXPECT_EQ(1u, client_.on_complete_called());
}

TEST_F(ThrottlingURLLoaderTest, BlockWithMultipleThrottles) {
  throttles_.emplace_back(std::make_unique<TestURLLoaderThrottle>());
  auto* throttle2 =
      static_cast<TestURLLoaderThrottle*>(throttles_.back().get());

  // Defers a request on both throttles.
  throttle_->set_will_start_request_callback(base::BindLambdaForTesting(
      [](blink::URLLoaderThrottle::Delegate* delegate, bool* defer) {
        *defer = true;
      }));
  throttle2->set_will_start_request_callback(base::BindLambdaForTesting(
      [](blink::URLLoaderThrottle::Delegate* delegate, bool* defer) {
        *defer = true;
      }));

  base::RunLoop loop;
  client_.set_on_complete_callback(
      base::BindLambdaForTesting([&loop](int error) {
        EXPECT_EQ(net::OK, error);
        loop.Quit();
      }));

  CreateLoaderAndStart();

  EXPECT_EQ(1u, throttle_->will_start_request_called());
  EXPECT_EQ(1u, throttle2->will_start_request_called());
  EXPECT_EQ(0u, throttle_->will_redirect_request_called());
  EXPECT_EQ(0u, throttle2->will_redirect_request_called());
  EXPECT_EQ(0u, throttle_->before_will_process_response_called());
  EXPECT_EQ(0u, throttle2->before_will_process_response_called());
  EXPECT_EQ(0u, throttle_->will_process_response_called());
  EXPECT_EQ(0u, throttle2->will_process_response_called());

  EXPECT_EQ(0u, factory_.create_loader_and_start_called());

  EXPECT_EQ(0u, client_.on_received_response_called());
  EXPECT_EQ(0u, client_.on_received_redirect_called());
  EXPECT_EQ(0u, client_.on_complete_called());

  throttle_->delegate()->Resume();

  // Should still not have started because there's |throttle2| is still blocking
  // the request.
  factory_.factory_remote().FlushForTesting();
  EXPECT_EQ(0u, factory_.create_loader_and_start_called());

  throttle2->delegate()->Resume();

  // Now it should have started.
  factory_.factory_remote().FlushForTesting();
  EXPECT_EQ(1u, factory_.create_loader_and_start_called());

  factory_.NotifyClientOnReceiveResponse();
  factory_.NotifyClientOnComplete(net::OK);

  loop.Run();

  EXPECT_EQ(1u, throttle_->will_start_request_called());
  EXPECT_EQ(1u, throttle2->will_start_request_called());
  EXPECT_EQ(0u, throttle_->will_redirect_request_called());
  EXPECT_EQ(0u, throttle2->will_redirect_request_called());
  EXPECT_EQ(1u, throttle_->before_will_process_response_called());
  EXPECT_EQ(1u, throttle2->before_will_process_response_called());
  EXPECT_EQ(1u, throttle_->will_process_response_called());
  EXPECT_EQ(1u, throttle2->will_process_response_called());

  EXPECT_TRUE(
      throttle_->observed_response_url().EqualsIgnoringRef(request_url));
  EXPECT_TRUE(
      throttle2->observed_response_url().EqualsIgnoringRef(request_url));

  EXPECT_EQ(1u, client_.on_received_response_called());
  EXPECT_EQ(0u, client_.on_received_redirect_called());
  EXPECT_EQ(1u, client_.on_complete_called());
}

TEST_F(ThrottlingURLLoaderTest,
       DestroyingThrottlingURLLoaderInDelegateCall_Response) {
  base::RunLoop run_loop1;
  throttle_->set_will_process_response_callback(base::BindLambdaForTesting(
      [&run_loop1](blink::URLLoaderThrottle::Delegate* delegate, bool* defer) {
        *defer = true;
        run_loop1.Quit();
      }));

  base::RunLoop run_loop2;
  client_.set_on_received_response_callback(base::BindLambdaForTesting([&]() {
    // Destroy the ThrottlingURLLoader while inside a delegate call from a
    // throttle.
    loader().reset();

    // The throttle should stay alive.
    EXPECT_NE(nullptr, throttle());

    run_loop2.Quit();
  }));

  CreateLoaderAndStart();

  factory_.NotifyClientOnReceiveResponse();

  run_loop1.Run();

  EXPECT_EQ(1u, throttle_->will_start_request_called());
  EXPECT_EQ(0u, throttle_->will_redirect_request_called());
  EXPECT_EQ(1u, throttle_->before_will_process_response_called());
  EXPECT_EQ(1u, throttle_->will_process_response_called());

  EXPECT_TRUE(
      throttle_->observed_response_url().EqualsIgnoringRef(request_url));

  throttle_->delegate()->Resume();
  run_loop2.Run();

  // The ThrottlingURLLoader should be gone.
  EXPECT_EQ(nullptr, loader_);
  // The throttle should stay alive and destroyed later.
  EXPECT_NE(nullptr, throttle_);

  task_environment_.RunUntilIdle();
  EXPECT_EQ(nullptr, throttle_.get());
}

// Regression test for crbug.com/833292.
TEST_F(ThrottlingURLLoaderTest,
       DestroyingThrottlingURLLoaderInDelegateCall_Redirect) {
  base::RunLoop run_loop1;
  throttle_->set_will_redirect_request_callback(base::BindLambdaForTesting(
      [&run_loop1](
          blink::URLLoaderThrottle::Delegate* delegate, bool* defer,
          std::vector<std::string>* /* removed_headers */,
          net::HttpRequestHeaders* /* modified_headers */,
          net::HttpRequestHeaders* /* modified_cors_exempt_headers */) {
        *defer = true;
        run_loop1.Quit();
      }));

  base::RunLoop run_loop2;
  client_.set_on_received_redirect_callback(base::BindRepeating(
      [](ThrottlingURLLoaderTest* test,
         const base::RepeatingClosure& quit_closure) {
        // Destroy the ThrottlingURLLoader while inside a delegate call from a
        // throttle.
        test->loader().reset();

        // The throttle should stay alive.
        EXPECT_NE(nullptr, test->throttle());

        quit_closure.Run();
      },
      base::Unretained(this), run_loop2.QuitClosure()));

  CreateLoaderAndStart();

  factory_.NotifyClientOnReceiveRedirect();

  run_loop1.Run();

  EXPECT_EQ(1u, throttle_->will_start_request_called());
  EXPECT_EQ(1u, throttle_->will_redirect_request_called());
  EXPECT_EQ(0u, throttle_->before_will_process_response_called());
  EXPECT_EQ(0u, throttle_->will_process_response_called());

  throttle_->delegate()->Resume();
  run_loop2.Run();

  // The ThrottlingURLLoader should be gone.
  EXPECT_EQ(nullptr, loader_);
  // The throttle should stay alive and destroyed later.
  EXPECT_NE(nullptr, throttle_);

  task_environment_.RunUntilIdle();
  EXPECT_EQ(nullptr, throttle_.get());
}

// Call RestartWithURLReset() from a single throttle while processing
// BeforeWillProcessResponse(), and verify that it restarts with the original
// URL.
TEST_F(ThrottlingURLLoaderTest, RestartWithURLReset) {
  base::RunLoop run_loop1;
  base::RunLoop run_loop2;
  base::RunLoop run_loop3;

  // URL for internal redirect.
  const GURL modified_url = GURL("http://www.example.uk.com");
  throttle_->set_modify_url_in_will_start(modified_url);

  factory_.set_on_create_loader_and_start(base::BindLambdaForTesting(
      [&run_loop1](const network::ResourceRequest& url_request) {
        run_loop1.Quit();
      }));

  // Set the client to actually follow redirects to allow URL resetting to
  // occur.
  client_.set_on_received_redirect_callback(
      base::BindLambdaForTesting([this]() {
        net::HttpRequestHeaders modified_headers;
        loader_->FollowRedirect({} /* removed_headers */,
                                std::move(modified_headers),
                                {} /* modified_cors_exempt_headers */);
      }));

  CreateLoaderAndStart();
  run_loop1.Run();

  EXPECT_EQ(1u, factory_.create_loader_and_start_called());
  EXPECT_EQ(1u, throttle_->will_start_request_called());
  EXPECT_EQ(1u, throttle_->will_redirect_request_called());
  EXPECT_EQ(0u, throttle_->before_will_process_response_called());
  EXPECT_EQ(0u, throttle_->will_process_response_called());

  // Restart the request with URL reset when processing
  // BeforeWillProcessResponse().
  throttle_->set_before_will_process_response_callback(
      base::BindRepeating([](blink::URLLoaderThrottle::Delegate* delegate,
                             RestartWithURLReset* restart_with_url_reset) {
        *restart_with_url_reset = RestartWithURLReset(true);
      }));

  // The next time we intercept CreateLoaderAndStart() should be for the
  // restarted request.
  factory_.set_on_create_loader_and_start(base::BindLambdaForTesting(
      [&run_loop2](const network::ResourceRequest& url_request) {
        run_loop2.Quit();
      }));

  factory_.NotifyClientOnReceiveResponse();
  run_loop2.Run();

  EXPECT_EQ(2u, factory_.create_loader_and_start_called());
  EXPECT_EQ(1u, throttle_->before_will_process_response_called());
  EXPECT_EQ(0u, throttle_->will_process_response_called());

  // Now that the restarted request has been made, clear
  // BeforeWillProcessResponse() so it doesn't restart the request yet again.
  throttle_->set_before_will_process_response_callback(
      TestURLLoaderThrottle::BeforeThrottleCallback());

  client_.set_on_complete_callback(
      base::BindLambdaForTesting([&run_loop3](int error) {
        EXPECT_EQ(net::OK, error);
        run_loop3.Quit();
      }));

  // Complete the response.
  factory_.NotifyClientOnReceiveResponse();
  factory_.NotifyClientOnComplete(net::OK);

  run_loop3.Run();

  EXPECT_EQ(2u, factory_.create_loader_and_start_called());
  EXPECT_EQ(1u, throttle_->will_start_request_called());
  EXPECT_EQ(2u, throttle_->will_redirect_request_called());
  EXPECT_EQ(2u, throttle_->before_will_process_response_called());
  EXPECT_EQ(1u, throttle_->will_process_response_called());
  EXPECT_EQ(throttle_->observed_response_url(), request_url);
}

// Call RestartWithURLReset() from multiple throttles while processing
// BeforeWillProcessResponse(). Ensures that the request is restarted exactly
// once with the original URL.
TEST_F(ThrottlingURLLoaderTest, MultipleRestartWithURLReset) {
  // Create two additional TestURLLoaderThrottles for a total of 3, and keep
  // local unowned pointers to them in |throttles|.
  std::vector<TestURLLoaderThrottle*> throttles;
  ASSERT_EQ(1u, throttles_.size());
  throttles.push_back(throttle_);
  for (size_t i = 0; i < 2u; ++i) {
    auto throttle = std::make_unique<TestURLLoaderThrottle>();
    throttles.push_back(throttle.get());
    throttles_.push_back(std::move(throttle));
  }
  ASSERT_EQ(3u, throttles_.size());
  ASSERT_EQ(3u, throttles.size());

  base::RunLoop run_loop1;
  base::RunLoop run_loop2;
  base::RunLoop run_loop3;

  // URL for internal redirect.
  const GURL modified_url = GURL("http://www.example.uk.com");
  throttle_->set_modify_url_in_will_start(modified_url);

  factory_.set_on_create_loader_and_start(base::BindLambdaForTesting(
      [&run_loop1](const network::ResourceRequest& url_request) {
        run_loop1.Quit();
      }));

  // Set the client to actually follow redirects to allow URL resetting to
  // occur.
  client_.set_on_received_redirect_callback(
      base::BindLambdaForTesting([this]() {
        net::HttpRequestHeaders modified_headers;
        loader_->FollowRedirect({} /* removed_headers */,
                                std::move(modified_headers),
                                {} /* modified_cors_exempt_headers */);
      }));

  CreateLoaderAndStart();
  run_loop1.Run();

  EXPECT_EQ(1u, factory_.create_loader_and_start_called());
  for (const auto* throttle : throttles) {
    EXPECT_EQ(1u, throttle->will_start_request_called());
    EXPECT_EQ(1u, throttle->will_redirect_request_called());
    EXPECT_EQ(0u, throttle->before_will_process_response_called());
    EXPECT_EQ(0u, throttle->will_process_response_called());
  }

  // Have two of the three throttles restart with URL reset when processing
  // BeforeWillProcessResponse().
  for (auto* throttle : {throttles[0], throttles[2]}) {
    throttle->set_before_will_process_response_callback(
        base::BindRepeating([](blink::URLLoaderThrottle::Delegate* delegate,
                               RestartWithURLReset* restart_with_url_reset) {
          *restart_with_url_reset = RestartWithURLReset(true);
        }));
  }

  // The next time we intercept CreateLoaderAndStart() should be for the
  // restarted request.
  factory_.set_on_create_loader_and_start(base::BindLambdaForTesting(
      [&run_loop2](const network::ResourceRequest& url_request) {
        run_loop2.Quit();
      }));

  factory_.NotifyClientOnReceiveResponse();
  run_loop2.Run();

  EXPECT_EQ(2u, factory_.create_loader_and_start_called());
  for (const auto* throttle : {throttles[0], throttles[2]}) {
    EXPECT_EQ(1u, throttle->before_will_process_response_called());
    EXPECT_EQ(0u, throttle->will_process_response_called());
  }

  // Now that the restarted request has been made, clear
  // BeforeWillProcessResponse() so it doesn't restart the request yet again.
  for (auto* throttle : throttles) {
    throttle->set_before_will_process_response_callback(
        TestURLLoaderThrottle::BeforeThrottleCallback());
  }

  client_.set_on_complete_callback(
      base::BindLambdaForTesting([&run_loop3](int error) {
        EXPECT_EQ(net::OK, error);
        run_loop3.Quit();
      }));

  // Complete the response.
  factory_.NotifyClientOnReceiveResponse();
  factory_.NotifyClientOnComplete(net::OK);

  run_loop3.Run();

  EXPECT_EQ(2u, factory_.create_loader_and_start_called());
  for (auto* throttle : throttles) {
    EXPECT_EQ(1u, throttle->will_start_request_called());
    EXPECT_EQ(2u, throttle->will_redirect_request_called());
    EXPECT_EQ(2u, throttle->before_will_process_response_called());
    EXPECT_EQ(1u, throttle->will_process_response_called());
    EXPECT_EQ(throttle_->observed_response_url(), request_url);
  }
}

// Test restarts from "BeforeWillRedirectRequest".
TEST_F(ThrottlingURLLoaderTest, RestartWithURLResetBeforeWillRedirectRequest) {
  base::RunLoop run_loop1;
  base::RunLoop run_loop2;

  // URL for internal redirect.
  GURL modified_url = GURL("http://www.example.uk.com");
  throttle_->set_modify_url_in_will_start(modified_url);

  // When we intercept CreateLoaderAndStart() it is for the restarted request
  // already.
  factory_.set_on_create_loader_and_start(base::BindLambdaForTesting(
      [&run_loop1](const network::ResourceRequest& url_request) {
        run_loop1.Quit();
      }));

  // Set the client to actually follow redirects to allow URL resetting to
  // occur.
  client_.set_on_received_redirect_callback(
      base::BindLambdaForTesting([this]() {
        net::HttpRequestHeaders modified_headers;
        loader_->FollowRedirect({} /* removed_headers */,
                                std::move(modified_headers),
                                {} /* modified_cors_exempt_headers */);
      }));

  // Restart the request with URL reset when processing
  // BeforeWillRedirectRequest().
  throttle_->set_before_will_redirect_request_callback(base::BindRepeating(
      [](blink::URLLoaderThrottle::Delegate* delegate,
         RestartWithURLReset* restart_with_url_reset,
         std::vector<std::string>* /* removed_headers */,
         net::HttpRequestHeaders* /* modified_headers */,
         net::HttpRequestHeaders* /* modified_cors_exempt_headers */) {
        *restart_with_url_reset = RestartWithURLReset(true);
      }));

  CreateLoaderAndStart();
  run_loop1.Run();

  EXPECT_EQ(1u, factory_.create_loader_and_start_called());
  EXPECT_EQ(1u, throttle_->will_start_request_called());
  EXPECT_EQ(2u, throttle_->before_will_redirect_request_called());
  EXPECT_EQ(1u, throttle_->will_redirect_request_called());
  EXPECT_EQ(0u, throttle_->before_will_process_response_called());
  EXPECT_EQ(0u, throttle_->will_process_response_called());

  client_.set_on_complete_callback(
      base::BindLambdaForTesting([&run_loop2](int error) {
        EXPECT_EQ(net::OK, error);
        run_loop2.Quit();
      }));

  // Complete the response.
  factory_.NotifyClientOnReceiveResponse();
  factory_.NotifyClientOnComplete(net::OK);

  run_loop2.Run();

  EXPECT_EQ(1u, factory_.create_loader_and_start_called());
  EXPECT_EQ(1u, throttle_->will_start_request_called());
  EXPECT_EQ(2u, throttle_->before_will_redirect_request_called());
  EXPECT_EQ(1u, throttle_->will_redirect_request_called());
  EXPECT_EQ(1u, throttle_->before_will_process_response_called());
  EXPECT_EQ(1u, throttle_->will_process_response_called());
  EXPECT_EQ(throttle_->observed_response_url(), request_url);
}

}  // namespace
}  // namespace blink

"""


```