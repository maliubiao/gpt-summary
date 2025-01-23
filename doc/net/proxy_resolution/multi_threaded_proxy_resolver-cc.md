Response:
Let's break down the thought process for analyzing this C++ code.

1. **Understand the Goal:** The request asks for a functional breakdown of the `MultiThreadedProxyResolver.cc` file, its relationship to JavaScript, potential issues, and debugging information.

2. **Identify the Core Class:** The filename immediately points to `MultiThreadedProxyResolver`. This will be a central focus.

3. **High-Level Functionality (The "Why"):**  Skim the initial comments and class definition. The name suggests it's about resolving proxy settings using multiple threads. The constructor mentions `ProxyResolverFactory`, `max_num_threads`, and `PacFileData`. This signals that it's likely dealing with PAC scripts and aims to improve performance through concurrency.

4. **Identify Key Components and Their Roles (The "What"):**  Look for other important classes and structures:

    * **`Executor`:**  Seems to be the worker unit. It has a thread and a `ProxyResolver`. The `Coordinator` suggests a management role.
    * **`Job`:** Represents a single proxy resolution task. It can be queued and executed. The subclasses (`GetProxyForURLJob`, `CreateResolverJob`) indicate different types of tasks.
    * **`ProxyResolverFactory`:**  Used to create the underlying `ProxyResolver` instances within the worker threads.
    * **`PacFileData`:**  Holds the PAC script content.
    * **`PendingJobsQueue`:** A queue for tasks waiting for an available executor.

5. **Trace the Request Flow (The "How"):** Follow the path of a `GetProxyForURL` request:

    * **`MultiThreadedProxyResolver::GetProxyForURL`:** This is the entry point. It creates a `GetProxyForURLJob`.
    * **`FindIdleExecutor`:** Checks for available worker threads.
    * **Queueing:** If no idle executor, the job is added to `pending_jobs_`.
    * **`AddNewExecutor`:**  If the thread limit isn't reached, a new `Executor` is created. This involves a `CreateResolverJob`.
    * **`Executor::StartJob`:**  Submits a job to a worker thread.
    * **`Job::Run`:** Executes the actual proxy resolution (either `ProxyResolver::GetProxyForURL` or `ProxyResolverFactory::CreateProxyResolver`).
    * **Callbacks:**  Uses `CompletionOnceCallback` to notify the original thread of completion.
    * **`Executor::OnJobCompleted`:** Signals that an executor is free.
    * **`MultiThreadedProxyResolver::OnExecutorReady`:**  Dequeues and starts the next pending job.

6. **Identify JavaScript Relationship:**  PAC scripts *are* JavaScript. The core purpose of this code is to *execute* that JavaScript to determine proxy settings. Therefore, the connection is fundamental. Look for mentions of "PAC" or "script."

7. **Consider Logic and Edge Cases (The "What Could Go Wrong"):**

    * **No Available Threads:** What happens if `max_num_threads` is reached?  The job gets queued.
    * **Cancellation:** The `RequestImpl` and `Job::Cancel` methods handle request cancellation.
    * **PAC Script Errors:**  The `CreateResolverJob` and the `OnExecutorReady` method in `MultiThreadedProxyResolverFactory::Job` handle potential errors during PAC script initialization.
    * **Executor Shutdown:** The `Destroy` methods in `Executor` and `MultiThreadedProxyResolver` handle proper cleanup and thread joining.

8. **Think About Debugging:**  How would a developer end up in this code?

    * **Network Configuration Issues:** Problems with proxy settings are a primary driver.
    * **Performance Investigations:**  Understanding multi-threading behavior.
    * **PAC Script Errors:** Debugging why a PAC script isn't working.
    * **Breakpoints:** Where would you set breakpoints to understand the flow?  Key methods like `GetProxyForURL`, `StartJob`, `Run`, and the completion callbacks are good candidates.
    * **NetLog:** The code uses `net_log`, which is a crucial debugging tool in Chromium's networking stack.

9. **Structure the Output:** Organize the information logically, using headings and bullet points for clarity. Address each part of the prompt explicitly.

10. **Refine and Elaborate:**  Go back through and add details. For example, when discussing JavaScript, explain *why* it's relevant (PAC scripts). When giving examples of errors, provide concrete scenarios.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe the JavaScript interaction is more about the browser UI.
* **Correction:** Realized the core interaction is the *execution* of the PAC script itself within the C++ code.

* **Initial thought:** Just listing the classes is enough.
* **Refinement:**  Needed to explain *how* those classes interact and what their specific responsibilities are. Tracing the request flow is key.

* **Initial thought:**  Focus only on the positive path.
* **Refinement:**  Considered error handling, cancellation, and resource management as important aspects of the code.

By following these steps, combining high-level understanding with detailed code examination, and constantly refining the analysis, you can produce a comprehensive explanation like the example provided in the initial prompt.
好的，让我们来详细分析一下 `net/proxy_resolution/multi_threaded_proxy_resolver.cc` 这个 Chromium 网络栈的源代码文件。

**功能概述**

`MultiThreadedProxyResolver` 的主要功能是实现一个**异步的代理解析器**，它通过使用多线程来提高代理解析的性能。 传统上，代理解析（特别是当涉及到执行 PAC (Proxy Auto-Config) 脚本时）可能是耗时的操作。  `MultiThreadedProxyResolver` 通过将解析任务分发到多个工作线程上并行执行来加速这个过程。

以下是它的主要功能点：

1. **多线程处理：**  它创建并管理一个工作线程池，用于并行执行代理解析任务。线程的数量由 `max_num_threads_` 参数控制。
2. **PAC 脚本执行：** 它负责执行 PAC 脚本，以确定给定 URL 应该使用的代理服务器。每个工作线程都有自己的 `ProxyResolver` 实例（通常是执行 PAC 脚本的解析器）。
3. **异步接口：**  它实现了 `ProxyResolver` 接口，这意味着它的 `GetProxyForURL` 方法是异步的，通过回调函数返回结果，避免阻塞调用线程。
4. **任务队列：** 它维护一个待处理的代理解析任务队列 (`pending_jobs_`)。当没有空闲的工作线程时，新的解析请求会被加入到这个队列中。
5. **Executor 管理：**  它管理一组 `Executor` 对象，每个 `Executor` 封装了一个工作线程和一个 `ProxyResolver` 实例。
6. **生命周期管理：** 它负责创建、启动和销毁工作线程以及相关的 `ProxyResolver` 实例。
7. **请求取消：** 它支持取消正在进行的代理解析请求。
8. **NetLog 集成：** 它使用 Chromium 的 NetLog 系统记录事件，用于调试和性能分析。

**与 JavaScript 的关系**

`MultiThreadedProxyResolver` 与 JavaScript 的关系非常密切，因为它主要用于执行 **PAC (Proxy Auto-Config) 脚本**。PAC 脚本是用 JavaScript 编写的，用于动态地确定给定 URL 应使用的代理服务器。

**举例说明：**

假设一个 PAC 脚本如下：

```javascript
function FindProxyForURL(url, host) {
  if (shExpMatch(host, "*.example.com")) {
    return "PROXY proxy1.example.com:8080; PROXY proxy2.example.com:8080";
  }
  return "DIRECT";
}
```

当 Chromium 需要为一个 URL（例如 `http://www.example.com/index.html`）查找代理时，会调用 `MultiThreadedProxyResolver::GetProxyForURL`。  `MultiThreadedProxyResolver` 会将这个请求分配给一个空闲的工作线程。

在这个工作线程上，会使用一个 `ProxyResolver` 实例（通常是 `PacProxyResolver`），它会执行上述的 JavaScript 代码。JavaScript 引擎会评估 `FindProxyForURL` 函数，并根据 URL 和主机名返回一个代理服务器列表（在这个例子中是 `PROXY proxy1.example.com:8080; PROXY proxy2.example.com:8080`）。

`MultiThreadedProxyResolver` 接收到这个结果后，会通过回调函数将 `ProxyInfo` 对象（包含代理服务器信息）返回给调用方。

**逻辑推理 (假设输入与输出)**

**假设输入：**

* **URL:** `http://intranet.company.com/resource`
* **PAC 脚本内容:**
  ```javascript
  function FindProxyForURL(url, host) {
    if (isPlainHostName(host) ||
        shExpMatch(host, "*.local") ||
        isInNet(dnsResolve(host), "10.0.0.0", "255.0.0.0")) {
      return "DIRECT";
    }
    return "PROXY proxy.company.com:3128";
  }
  ```

**执行流程：**

1. `MultiThreadedProxyResolver::GetProxyForURL` 被调用，传入 URL 和 PAC 脚本。
2. 如果有空闲的 `Executor`，任务被分配给它。否则，任务被添加到 `pending_jobs_` 队列。
3. 在 `Executor` 的工作线程中，`PacProxyResolver` 执行 PAC 脚本的 `FindProxyForURL` 函数。
4. `isPlainHostName("intranet.company.com")` 返回 false。
5. `shExpMatch("intranet.company.com", "*.local")` 返回 false。
6. 假设 `dnsResolve("intranet.company.com")` 返回的 IP 地址不在 `10.0.0.0/8` 网段内。
7. `FindProxyForURL` 函数返回 `"PROXY proxy.company.com:3128"`。
8. `Executor` 通过回调通知主线程，`ProxyInfo` 对象被设置为使用 `proxy.company.com:3128`。

**预期输出 (ProxyInfo):**

```
proxy_list_.Get() = "PROXY proxy.company.com:3128"
```

**假设输入：**

* **URL:** `http://public.example.net/file.html`
* **PAC 脚本内容:** (同上)

**执行流程：**

1. `MultiThreadedProxyResolver::GetProxyForURL` 被调用。
2. PAC 脚本执行 `FindProxyForURL` 函数。
3. `isPlainHostName("public.example.net")` 返回 false。
4. `shExpMatch("public.example.net", "*.local")` 返回 false。
5. 假设 `dnsResolve("public.example.net")` 返回的 IP 地址不在 `10.0.0.0/8` 网段内。
6. `FindProxyForURL` 函数返回 `"PROXY proxy.company.com:3128"`。

**预期输出 (ProxyInfo):**

```
proxy_list_.Get() = "PROXY proxy.company.com:3128"
```

**用户或编程常见的使用错误**

1. **PAC 脚本错误：** PAC 脚本中存在语法错误或逻辑错误会导致解析失败。例如，拼写错误的 JavaScript 关键字、未定义的变量或无限循环。 这会导致 `CreateResolverJob` 或 `GetProxyForURLJob` 中的操作失败，最终调用回调时返回错误码（例如 `ERR_PAC_SCRIPT_FAILED`）。

   **用户操作如何到达这里：** 用户配置了一个包含错误的 PAC 脚本的代理设置。当浏览器尝试加载网页时，网络栈会尝试解析代理，从而调用到 `MultiThreadedProxyResolver` 并执行有错误的 PAC 脚本。

2. **线程数量配置不当：** 将 `max_num_threads_` 设置得过高可能会导致过多的线程上下文切换，反而降低性能。设置得过低则可能无法充分利用多核 CPU 的优势。

   **用户操作如何到达这里：** 这通常不是用户直接操作，而是编程配置错误。开发人员在创建 `MultiThreadedProxyResolverFactory` 时可能会传入错误的 `max_num_threads` 值。

3. **在非 IO 线程上执行同步操作：** 尽管 `MultiThreadedProxyResolver` 的目标是异步，但底层的 `ProxyResolver` 实例（例如 `PacProxyResolver`）仍然可能在工作线程上执行同步操作，例如 DNS 解析。在某些情况下，这可能会导致线程阻塞。代码中通过 `MultiThreadedProxyResolverScopedAllowJoinOnIO` 注释来允许在 IO 线程上进行 join 操作，这通常是为了测试或者某些特定的同步场景。滥用这种机制可能会导致性能问题。

   **用户操作如何到达这里：**  这通常是编程实现的问题。如果底层的 `ProxyResolverFactory` 创建了一个执行阻塞操作的 `ProxyResolver`，那么即使使用了多线程，也可能遇到性能瓶颈。

4. **忘记取消请求：** 如果调用方创建了一个请求 (`std::unique_ptr<Request>`) 但在不再需要结果时忘记销毁它，可能会导致资源泄漏，因为 `Job` 对象不会被释放。

   **编程错误示例：**

   ```c++
   void SomeFunction(MultiThreadedProxyResolver* resolver, const GURL& url) {
     ProxyInfo proxy_info;
     std::unique_ptr<ProxyResolver::Request> request;
     resolver->GetProxyForURL(url, NetworkAnonymizationKey(), &proxy_info,
                                  base::DoNothing(), &request, NetLogWithSource::Make(net::NetLogSourceType::NONE));
     // ... 忘记处理或销毁 request
   }
   ```

**用户操作是如何一步步的到达这里，作为调试线索**

假设用户报告网页加载缓慢或无法加载，并且怀疑是代理配置的问题。以下是调试的步骤，可能会让你深入到 `MultiThreadedProxyResolver.cc`：

1. **检查代理设置：** 用户首先会检查其操作系统或浏览器的代理设置，确认是否配置了代理服务器或 PAC 脚本。
2. **使用 Chromium 的网络工具 (chrome://net-internals/#proxy)：**  用户或开发人员可以使用 Chromium 提供的网络内部工具来查看当前的代理配置和解析状态。这个页面会显示正在使用的代理解析器类型（这里应该是 `MultiThreadedProxyResolver`）。
3. **启用 NetLog (chrome://net-internals/#events)：** 为了更详细地了解网络请求的流程，可以启用 NetLog。NetLog 会记录包括代理解析在内的各种网络事件。
4. **查看 NetLog 事件：** 在 NetLog 中，你会看到与代理解析相关的事件，例如：
   * `PROXY_RESOLVER_REQUEST`：表示开始进行代理解析请求。
   * `PROXY_RESOLVER_PAC_FILE_FETCH` (如果使用了 PAC 脚本)：表示正在获取 PAC 文件。
   * `PROXY_RESOLVER_PAC_SCRIPT_COMPILE` (如果使用了 PAC 脚本)：表示正在编译 PAC 脚本。
   * `PROXY_RESOLVER_PAC_SCRIPT_EXECUTE` (如果使用了 PAC 脚本)：表示正在执行 PAC 脚本。
   * `WAITING_FOR_PROXY_RESOLVER_THREAD`：表示请求正在等待可用的工作线程。
   * `SUBMITTED_TO_RESOLVER_THREAD`：表示请求已提交给某个工作线程。
   * `PROXY_RESOLVER_DONE`：表示代理解析完成。
5. **设置断点 (对于开发人员)：** 如果需要深入调试代码，开发人员可以在 `MultiThreadedProxyResolver.cc` 中的关键方法上设置断点，例如：
   * `MultiThreadedProxyResolver::GetProxyForURL`：查看请求的入口。
   * `MultiThreadedProxyResolver::FindIdleExecutor`：查看线程分配逻辑。
   * `Executor::StartJob`：查看任务如何提交到工作线程。
   * `Job::Run` (及其子类)：查看实际的代理解析执行过程。
   * `MultiThreadedProxyResolver::OnExecutorReady`：查看工作线程完成任务后的处理。
6. **分析堆栈信息：** 当程序在断点处停止时，可以查看调用堆栈，了解用户操作是如何一步步触发到 `MultiThreadedProxyResolver` 的。通常，你会看到网络请求处理流程中的函数调用，例如 `URLRequest::Start` -> `HttpTransactionFactory::CreateTransaction` -> `ProxyService::ResolveProxy` -> `MultiThreadedProxyResolver::GetProxyForURL`。

通过以上步骤，可以追踪代理解析的过程，识别潜在的瓶颈或错误，并最终定位到 `MultiThreadedProxyResolver.cc` 中的相关代码。 NetLog 是一个非常有用的工具，可以帮助理解异步操作的执行顺序和时间消耗。

### 提示词
```
这是目录为net/proxy_resolution/multi_threaded_proxy_resolver.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/proxy_resolution/multi_threaded_proxy_resolver.h"

#include <memory>
#include <utility>
#include <vector>

#include "base/containers/circular_deque.h"
#include "base/functional/bind.h"
#include "base/functional/callback_helpers.h"
#include "base/location.h"
#include "base/memory/raw_ptr.h"
#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "base/task/single_thread_task_runner.h"
#include "base/threading/thread.h"
#include "base/threading/thread_checker.h"
#include "base/threading/thread_restrictions.h"
#include "net/base/net_errors.h"
#include "net/base/network_anonymization_key.h"
#include "net/log/net_log.h"
#include "net/log/net_log_event_type.h"
#include "net/log/net_log_with_source.h"
#include "net/proxy_resolution/proxy_info.h"
#include "net/proxy_resolution/proxy_resolver.h"

namespace net {

class NetworkAnonymizationKey;

// http://crbug.com/69710
class MultiThreadedProxyResolverScopedAllowJoinOnIO
    : public base::ScopedAllowBaseSyncPrimitivesOutsideBlockingScope {};

namespace {
class Job;

// An "executor" is a job-runner for PAC requests. It encapsulates a worker
// thread and a synchronous ProxyResolver (which will be operated on said
// thread.)
class Executor : public base::RefCountedThreadSafe<Executor> {
 public:
  class Coordinator {
   public:
    virtual void OnExecutorReady(Executor* executor) = 0;

   protected:
    virtual ~Coordinator() = default;
  };

  // |coordinator| must remain valid throughout our lifetime. It is used to
  // signal when the executor is ready to receive work by calling
  // |coordinator->OnExecutorReady()|.
  // |thread_number| is an identifier used when naming the worker thread.
  Executor(Coordinator* coordinator, int thread_number);

  // Submit a job to this executor.
  void StartJob(scoped_refptr<Job> job);

  // Callback for when a job has completed running on the executor's thread.
  void OnJobCompleted(Job* job);

  // Cleanup the executor. Cancels all outstanding work, and frees the thread
  // and resolver.
  void Destroy();

  // Returns the outstanding job, or NULL.
  Job* outstanding_job() const { return outstanding_job_.get(); }

  ProxyResolver* resolver() { return resolver_.get(); }

  int thread_number() const { return thread_number_; }

  void set_resolver(std::unique_ptr<ProxyResolver> resolver) {
    resolver_ = std::move(resolver);
  }

  void set_coordinator(Coordinator* coordinator) {
    DCHECK(coordinator);
    DCHECK(coordinator_);
    coordinator_ = coordinator;
  }

 private:
  friend class base::RefCountedThreadSafe<Executor>;
  ~Executor();

  raw_ptr<Coordinator> coordinator_;
  const int thread_number_;

  // The currently active job for this executor (either a CreateProxyResolver or
  // GetProxyForURL task).
  scoped_refptr<Job> outstanding_job_;

  // The synchronous resolver implementation.
  std::unique_ptr<ProxyResolver> resolver_;

  // The thread where |resolver_| is run on.
  // Note that declaration ordering is important here. |thread_| needs to be
  // destroyed *before* |resolver_|, in case |resolver_| is currently
  // executing on |thread_|.
  std::unique_ptr<base::Thread> thread_;
};

class MultiThreadedProxyResolver : public ProxyResolver,
                                   public Executor::Coordinator {
 public:
  // Creates an asynchronous ProxyResolver that runs requests on up to
  // |max_num_threads|.
  //
  // For each thread that is created, an accompanying synchronous ProxyResolver
  // will be provisioned using |resolver_factory|. All methods on these
  // ProxyResolvers will be called on the one thread.
  MultiThreadedProxyResolver(
      std::unique_ptr<ProxyResolverFactory> resolver_factory,
      size_t max_num_threads,
      const scoped_refptr<PacFileData>& script_data,
      scoped_refptr<Executor> executor);

  ~MultiThreadedProxyResolver() override;

  // ProxyResolver implementation:
  int GetProxyForURL(const GURL& url,
                     const NetworkAnonymizationKey& network_anonymization_key,
                     ProxyInfo* results,
                     CompletionOnceCallback callback,
                     std::unique_ptr<Request>* request,
                     const NetLogWithSource& net_log) override;

 private:
  class GetProxyForURLJob;
  class RequestImpl;
  // FIFO queue of pending jobs waiting to be started.
  // TODO(eroman): Make this priority queue.
  using PendingJobsQueue = base::circular_deque<scoped_refptr<Job>>;
  using ExecutorList = std::vector<scoped_refptr<Executor>>;

  // Returns an idle worker thread which is ready to receive GetProxyForURL()
  // requests. If all threads are occupied, returns NULL.
  Executor* FindIdleExecutor();

  // Creates a new worker thread, and appends it to |executors_|.
  void AddNewExecutor();

  // Starts the next job from |pending_jobs_| if possible.
  void OnExecutorReady(Executor* executor) override;

  const std::unique_ptr<ProxyResolverFactory> resolver_factory_;
  const size_t max_num_threads_;
  PendingJobsQueue pending_jobs_;
  ExecutorList executors_;
  scoped_refptr<PacFileData> script_data_;

  THREAD_CHECKER(thread_checker_);
};

// Job ---------------------------------------------

class Job : public base::RefCountedThreadSafe<Job> {
 public:
  Job() = default;

  void set_executor(Executor* executor) {
    executor_ = executor;
  }

  // The "executor" is the job runner that is scheduling this job. If
  // this job has not been submitted to an executor yet, this will be
  // NULL (and we know it hasn't started yet).
  Executor* executor() {
    return executor_;
  }

  // Mark the job as having been cancelled.
  virtual void Cancel() { was_cancelled_ = true; }

  // Returns true if Cancel() has been called.
  bool was_cancelled() const { return was_cancelled_; }

  // This method is called when the job is inserted into a wait queue
  // because no executors were ready to accept it.
  virtual void WaitingForThread() {}

  // This method is called just before the job is posted to the work thread.
  virtual void FinishedWaitingForThread() {}

  // This method is called on the worker thread to do the job's work. On
  // completion, implementors are expected to call OnJobCompleted() on
  // |origin_runner|.
  virtual void Run(
      scoped_refptr<base::SingleThreadTaskRunner> origin_runner) = 0;

 protected:
  void OnJobCompleted() {
    // |executor_| will be NULL if the executor has already been deleted.
    if (executor_)
      executor_->OnJobCompleted(this);
  }

  friend class base::RefCountedThreadSafe<Job>;

  virtual ~Job() = default;

 private:
  raw_ptr<Executor> executor_ = nullptr;
  bool was_cancelled_ = false;
};

class MultiThreadedProxyResolver::RequestImpl : public ProxyResolver::Request {
 public:
  explicit RequestImpl(scoped_refptr<Job> job) : job_(std::move(job)) {}

  ~RequestImpl() override { job_->Cancel(); }

  LoadState GetLoadState() override {
    return LOAD_STATE_RESOLVING_PROXY_FOR_URL;
  }

 private:
  scoped_refptr<Job> job_;
};

// CreateResolverJob -----------------------------------------------------------

// Runs on the worker thread to call ProxyResolverFactory::CreateProxyResolver.
class CreateResolverJob : public Job {
 public:
  CreateResolverJob(const scoped_refptr<PacFileData>& script_data,
                    ProxyResolverFactory* factory)
      : script_data_(script_data), factory_(factory) {}

  // Runs on the worker thread.
  void Run(scoped_refptr<base::SingleThreadTaskRunner> origin_runner) override {
    std::unique_ptr<ProxyResolverFactory::Request> request;
    int rv = factory_->CreateProxyResolver(script_data_, &resolver_,
                                           CompletionOnceCallback(), &request);

    DCHECK_NE(rv, ERR_IO_PENDING);
    origin_runner->PostTask(
        FROM_HERE,
        base::BindOnce(&CreateResolverJob::RequestComplete, this, rv));
  }

 protected:
  ~CreateResolverJob() override = default;

  void Cancel() override {
    // Needed to prevent warnings danging warnings about `factory_`. The
    // executor ensures that the thread has joined, but there may still be a
    // pending RequestComplete() that still owns a reference to `this` after the
    // factory and executor have been destroyed.
    factory_ = nullptr;
    Job::Cancel();
  }

 private:
  // Runs the completion callback on the origin thread.
  void RequestComplete(int result_code) {
    // The task may have been cancelled after it was started.
    if (!was_cancelled()) {
      DCHECK(executor());
      executor()->set_resolver(std::move(resolver_));
    }
    OnJobCompleted();
  }

  const scoped_refptr<PacFileData> script_data_;
  raw_ptr<ProxyResolverFactory> factory_;
  std::unique_ptr<ProxyResolver> resolver_;
};

// MultiThreadedProxyResolver::GetProxyForURLJob ------------------------------

class MultiThreadedProxyResolver::GetProxyForURLJob : public Job {
 public:
  // |url|         -- the URL of the query.
  // |results|     -- the structure to fill with proxy resolve results.
  GetProxyForURLJob(const GURL& url,
                    const NetworkAnonymizationKey& network_anonymization_key,
                    ProxyInfo* results,
                    CompletionOnceCallback callback,
                    const NetLogWithSource& net_log)
      : callback_(std::move(callback)),
        results_(results),
        net_log_(net_log),
        url_(url),
        network_anonymization_key_(network_anonymization_key) {
    DCHECK(callback_);
  }

  NetLogWithSource* net_log() { return &net_log_; }

  void WaitingForThread() override {
    was_waiting_for_thread_ = true;
    net_log_.BeginEvent(NetLogEventType::WAITING_FOR_PROXY_RESOLVER_THREAD);
  }

  void FinishedWaitingForThread() override {
    DCHECK(executor());

    if (was_waiting_for_thread_) {
      net_log_.EndEvent(NetLogEventType::WAITING_FOR_PROXY_RESOLVER_THREAD);
    }

    net_log_.AddEventWithIntParams(
        NetLogEventType::SUBMITTED_TO_RESOLVER_THREAD, "thread_number",
        executor()->thread_number());
  }

  // Runs on the worker thread.
  void Run(scoped_refptr<base::SingleThreadTaskRunner> origin_runner) override {
    ProxyResolver* resolver = executor()->resolver();
    DCHECK(resolver);
    int rv = resolver->GetProxyForURL(url_, network_anonymization_key_,
                                      &results_buf_, CompletionOnceCallback(),
                                      nullptr, net_log_);
    DCHECK_NE(rv, ERR_IO_PENDING);

    origin_runner->PostTask(
        FROM_HERE, base::BindOnce(&GetProxyForURLJob::QueryComplete, this, rv));
  }

  void Cancel() override {
    // Needed to prevent warnings danging warnings about `results_`. The
    // executor ensures that the thread has joined, but there may still be a
    // pending QueryComplete() that still owns a reference to `this` after the
    // factory and executor have been destroyed.
    results_ = nullptr;
    Job::Cancel();
  }

 protected:
  ~GetProxyForURLJob() override = default;

 private:
  // Runs the completion callback on the origin thread.
  void QueryComplete(int result_code) {
    // The Job may have been cancelled after it was started.
    if (!was_cancelled()) {
      if (result_code >= OK) {  // Note: unit-tests use values > 0.
        results_->Use(results_buf_);
      }
      std::move(callback_).Run(result_code);
    }
    OnJobCompleted();
  }

  CompletionOnceCallback callback_;

  // Must only be used on the "origin" thread.
  raw_ptr<ProxyInfo> results_;

  // Can be used on either "origin" or worker thread.
  NetLogWithSource net_log_;

  const GURL url_;
  const NetworkAnonymizationKey network_anonymization_key_;

  // Usable from within DoQuery on the worker thread.
  ProxyInfo results_buf_;

  bool was_waiting_for_thread_ = false;
};

// Executor ----------------------------------------

Executor::Executor(Executor::Coordinator* coordinator, int thread_number)
    : coordinator_(coordinator), thread_number_(thread_number) {
  DCHECK(coordinator);
  // Start up the thread.
  thread_ = std::make_unique<base::Thread>(
      base::StringPrintf("PAC thread #%d", thread_number));
  CHECK(thread_->Start());
}

void Executor::StartJob(scoped_refptr<Job> job) {
  DCHECK(!outstanding_job_.get());
  outstanding_job_ = job;

  // Run the job. Once it has completed (regardless of whether it was
  // cancelled), it will invoke OnJobCompleted() on this thread.
  job->set_executor(this);
  job->FinishedWaitingForThread();
  thread_->task_runner()->PostTask(
      FROM_HERE,
      base::BindOnce(&Job::Run, job,
                     base::SingleThreadTaskRunner::GetCurrentDefault()));
}

void Executor::OnJobCompleted(Job* job) {
  DCHECK_EQ(job, outstanding_job_.get());
  outstanding_job_ = nullptr;
  coordinator_->OnExecutorReady(this);
}

void Executor::Destroy() {
  DCHECK(coordinator_);

  {
    // TODO(http://crbug.com/69710): Use ThreadPool instead of creating a
    // base::Thread.
    MultiThreadedProxyResolverScopedAllowJoinOnIO allow_thread_join;

    // Join the worker thread.
    thread_.reset();
  }

  // Cancel any outstanding job.
  if (outstanding_job_.get()) {
    outstanding_job_->Cancel();
    // Orphan the job (since this executor may be deleted soon).
    outstanding_job_->set_executor(nullptr);
  }

  // It is now safe to free the ProxyResolver, since all the tasks that
  // were using it on the resolver thread have completed.
  resolver_.reset();

  // Null some stuff as a precaution.
  coordinator_ = nullptr;
  outstanding_job_ = nullptr;
}

Executor::~Executor() {
  // The important cleanup happens as part of Destroy(), which should always be
  // called first.
  DCHECK(!coordinator_) << "Destroy() was not called";
  DCHECK(!thread_.get());
  DCHECK(!resolver_.get());
  DCHECK(!outstanding_job_.get());
}

// MultiThreadedProxyResolver --------------------------------------------------

MultiThreadedProxyResolver::MultiThreadedProxyResolver(
    std::unique_ptr<ProxyResolverFactory> resolver_factory,
    size_t max_num_threads,
    const scoped_refptr<PacFileData>& script_data,
    scoped_refptr<Executor> executor)
    : resolver_factory_(std::move(resolver_factory)),
      max_num_threads_(max_num_threads),
      script_data_(script_data) {
  DCHECK(script_data_);
  executor->set_coordinator(this);
  executors_.push_back(executor);
}

MultiThreadedProxyResolver::~MultiThreadedProxyResolver() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  // We will cancel all outstanding requests.
  pending_jobs_.clear();

  for (auto& executor : executors_) {
    executor->Destroy();
  }
}

int MultiThreadedProxyResolver::GetProxyForURL(
    const GURL& url,
    const NetworkAnonymizationKey& network_anonymization_key,
    ProxyInfo* results,
    CompletionOnceCallback callback,
    std::unique_ptr<Request>* request,
    const NetLogWithSource& net_log) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK(!callback.is_null());

  auto job = base::MakeRefCounted<GetProxyForURLJob>(
      url, network_anonymization_key, results, std::move(callback), net_log);

  // Completion will be notified through |callback|, unless the caller cancels
  // the request using |request|.
  if (request)
    *request = std::make_unique<RequestImpl>(job);

  // If there is an executor that is ready to run this request, submit it!
  Executor* executor = FindIdleExecutor();
  if (executor) {
    DCHECK_EQ(0u, pending_jobs_.size());
    executor->StartJob(job);
    return ERR_IO_PENDING;
  }

  // Otherwise queue this request. (We will schedule it to a thread once one
  // becomes available).
  job->WaitingForThread();
  pending_jobs_.push_back(job);

  // If we haven't already reached the thread limit, provision a new thread to
  // drain the requests more quickly.
  if (executors_.size() < max_num_threads_)
    AddNewExecutor();

  return ERR_IO_PENDING;
}

Executor* MultiThreadedProxyResolver::FindIdleExecutor() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  for (auto& executor : executors_) {
    if (!executor->outstanding_job())
      return executor.get();
  }
  return nullptr;
}

void MultiThreadedProxyResolver::AddNewExecutor() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK_LT(executors_.size(), max_num_threads_);
  // The "thread number" is used to give the thread a unique name.
  int thread_number = executors_.size();

  auto executor = base::MakeRefCounted<Executor>(this, thread_number);
  executor->StartJob(base::MakeRefCounted<CreateResolverJob>(
      script_data_, resolver_factory_.get()));
  executors_.push_back(std::move(executor));
}

void MultiThreadedProxyResolver::OnExecutorReady(Executor* executor) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  while (!pending_jobs_.empty()) {
    scoped_refptr<Job> job = pending_jobs_.front();
    pending_jobs_.pop_front();
    if (!job->was_cancelled()) {
      executor->StartJob(std::move(job));
      return;
    }
  }
}

}  // namespace

class MultiThreadedProxyResolverFactory::Job
    : public ProxyResolverFactory::Request,
      public Executor::Coordinator {
 public:
  Job(MultiThreadedProxyResolverFactory* factory,
      const scoped_refptr<PacFileData>& script_data,
      std::unique_ptr<ProxyResolver>* resolver,
      std::unique_ptr<ProxyResolverFactory> resolver_factory,
      size_t max_num_threads,
      CompletionOnceCallback callback)
      : factory_(factory),
        resolver_out_(resolver),
        resolver_factory_(std::move(resolver_factory)),
        max_num_threads_(max_num_threads),
        script_data_(script_data),
        executor_(base::MakeRefCounted<Executor>(this, 0)),
        callback_(std::move(callback)) {
    executor_->StartJob(base::MakeRefCounted<CreateResolverJob>(
        script_data_, resolver_factory_.get()));
  }

  ~Job() override {
    if (factory_) {
      executor_->Destroy();
      factory_->RemoveJob(this);
    }
  }

  void FactoryDestroyed() {
    executor_->Destroy();
    executor_ = nullptr;
    factory_ = nullptr;
    resolver_out_ = nullptr;
  }

 private:
  void OnExecutorReady(Executor* executor) override {
    int error = OK;
    if (executor->resolver()) {
      *resolver_out_ = std::make_unique<MultiThreadedProxyResolver>(
          std::move(resolver_factory_), max_num_threads_,
          std::move(script_data_), executor_);
    } else {
      error = ERR_PAC_SCRIPT_FAILED;
      executor_->Destroy();
    }
    factory_->RemoveJob(this);
    factory_ = nullptr;
    std::move(callback_).Run(error);
  }

  raw_ptr<MultiThreadedProxyResolverFactory> factory_;
  raw_ptr<std::unique_ptr<ProxyResolver>> resolver_out_;
  std::unique_ptr<ProxyResolverFactory> resolver_factory_;
  const size_t max_num_threads_;
  scoped_refptr<PacFileData> script_data_;
  scoped_refptr<Executor> executor_;
  CompletionOnceCallback callback_;
};

MultiThreadedProxyResolverFactory::MultiThreadedProxyResolverFactory(
    size_t max_num_threads,
    bool factory_expects_bytes)
    : ProxyResolverFactory(factory_expects_bytes),
      max_num_threads_(max_num_threads) {
  DCHECK_GE(max_num_threads, 1u);
}

MultiThreadedProxyResolverFactory::~MultiThreadedProxyResolverFactory() {
  for (Job* job : jobs_) {
    job->FactoryDestroyed();
  }
}

int MultiThreadedProxyResolverFactory::CreateProxyResolver(
    const scoped_refptr<PacFileData>& pac_script,
    std::unique_ptr<ProxyResolver>* resolver,
    CompletionOnceCallback callback,
    std::unique_ptr<Request>* request) {
  auto job = std::make_unique<Job>(this, pac_script, resolver,
                                   CreateProxyResolverFactory(),
                                   max_num_threads_, std::move(callback));
  jobs_.insert(job.get());
  *request = std::move(job);
  return ERR_IO_PENDING;
}

void MultiThreadedProxyResolverFactory::RemoveJob(
    MultiThreadedProxyResolverFactory::Job* job) {
  size_t erased = jobs_.erase(job);
  DCHECK_EQ(1u, erased);
}

}  // namespace net
```