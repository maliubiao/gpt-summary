Response: The user wants a summary of the C++ unittest file `multi_buffer_data_source_unittest.cc`. I need to identify the functionalities being tested in this file and explain their relevance to web technologies like JavaScript, HTML, and CSS if any. If the tests involve logical deductions with input and output, I should illustrate those. I should also highlight common user/programming errors that these tests might be preventing.

Here's a plan:
1. **Identify Core Functionality:**  The filename suggests tests for `MultiBufferDataSource`. I'll scan the test names and setup code to understand what aspects of this class are being validated.
2. **Relate to Web Technologies:**  Consider how `MultiBufferDataSource` fits into the broader context of web media loading. Does it directly interact with JavaScript APIs like `fetch` or media elements? Does it influence how HTML media elements behave or how CSS might style them?
3. **Analyze Logical Tests:** Look for tests that involve specific sequences of actions and expected outcomes. For example, tests involving retries, redirects, or specific HTTP response codes. Define a simplified input (e.g., server response) and the expected output (e.g., buffered data, error state).
4. **Identify Error Prevention:**  Consider what kinds of mistakes a developer or the browser could make when handling media loading, and how these tests help prevent them. This could involve incorrect handling of HTTP headers, network errors, or API usage.
5. **Summarize Part 1:**  Based on the analysis of the first part of the file, provide a concise summary of the tested functionalities.
这是对 `blink/renderer/platform/media/multi_buffer_data_source_unittest.cc` 文件第一部分的分析和功能归纳。

**功能列举:**

该单元测试文件主要用于测试 `MultiBufferDataSource` 类的各种功能和行为。`MultiBufferDataSource` 在 Chromium 的 Blink 渲染引擎中负责从网络或本地文件系统中高效地加载和管理多媒体数据。

以下是该文件第一部分涵盖的主要测试功能点：

1. **资源加载和初始化:**
   - 测试不同 URL 类型 (HTTP, File) 的资源加载和初始化过程。
   - 测试在初始化过程中处理各种 HTTP 响应状态码 (200, 206, 404, 416 等)。
   - 测试在初始化时处理缺失或错误的 HTTP 头部信息 (Content-Length, Content-Range)。
   - 测试在初始化时处理 CORS (跨域资源共享) 相关设置。

2. **Range 请求支持:**
   - 测试 `MultiBufferDataSource` 对 HTTP Range 请求的支持情况，包括成功请求和服务器不支持 Range 请求的情况。
   - 测试服务器返回 200 响应，但实际上支持 Range 请求的情况。
   - 测试服务器在初始响应中声明支持 Range 请求，但在后续请求中表现不一致的情况。

3. **数据读取 (Read):**
   - 测试从 `MultiBufferDataSource` 读取数据的基本功能。
   - 测试读取过程中发生错误、中断 (Abort) 的处理。
   - 测试读取过程中进行 Seek 操作的处理。

4. **重试 (Retry):**
   - 测试在数据加载过程中遇到网络错误或服务器错误时，`MultiBufferDataSource` 的重试机制。
   - 测试重试次数过多导致加载失败的情况。

5. **分段响应 (Partial Response):**
   - 测试 `MultiBufferDataSource` 处理 HTTP 分段响应 (206 Partial Content) 的能力。
   - 测试在加载过程中，服务器返回的响应在 URL 或 Origin 上发生变化的情况。

6. **数据共享 (Data Sharing):**
   - 测试多个 `MultiBufferDataSource` 实例共享底层数据资源的能力。

7. **停止 (Stop):**
   - 测试在数据加载或读取过程中停止 `MultiBufferDataSource` 的行为。

8. **预加载 (Preload):**
   - 测试不同的预加载策略 (`AUTO`, `METADATA`, `NONE`) 对数据加载行为的影响。
   - 测试在不同预加载策略下，数据加载是否会延迟 (defer)。

9. **码率 (Bitrate) 和播放速率 (Playback Rate):**
   - 测试设置和更新数据源的码率和播放速率，以及这些设置对后续加载的影响。

10. **文件大小 (File Size) 处理:**
    - 测试处理已知和未知文件大小的情况。
    - 测试文件大小小于块大小的情况。

11. **响应类型 (Response Type):**
    - 测试根据不同的 `FetchResponseType` (Basic, Cors, Default, Opaque, OpaqueRedirect) 来判断是否为跨域请求。

12. **Etag 支持:**
    - 测试对 HTTP Etag 头的处理。

13. **缓冲区大小 (Buffer Sizes):**
    - 测试根据码率动态调整缓冲区大小的机制。

**与 JavaScript, HTML, CSS 的关系 (举例说明):**

`MultiBufferDataSource` 是 Blink 渲染引擎的底层组件，不直接与 JavaScript, HTML, 或 CSS 交互。但是，它的功能直接支持了 HTML `<audio>` 和 `<video>` 元素的多媒体资源加载。

* **JavaScript:** 当 JavaScript 代码通过 HTMLMediaElement API (如 `video.play()`) 请求播放视频时，浏览器会使用 `MultiBufferDataSource` 来加载视频数据。JavaScript 可以通过 `HTMLMediaElement` 的属性和事件来监控加载进度和状态，但并不直接操作 `MultiBufferDataSource`。
* **HTML:**  HTML 的 `<video>` 和 `<audio>` 元素声明了需要加载的媒体资源的 URL。浏览器根据这些 URL 创建 `MultiBufferDataSource` 实例来负责实际的数据获取。
* **CSS:** CSS 可以用来样式化 `<video>` 和 `<audio>` 元素的外观，但与 `MultiBufferDataSource` 的数据加载过程没有直接关系。

**逻辑推理 (假设输入与输出):**

**假设输入:**
1. 初始化 `MultiBufferDataSource`，URL 为 "http://example.com/video.mp4"。
2. 服务器返回 HTTP 状态码 206 (Partial Content)，并带有 `Content-Range: bytes 0-1023/5000` 和 `Content-Length: 1024` 头部。
3. 接收到 1024 字节的数据。
4. 尝试读取偏移量为 2048，长度为 1024 的数据。

**预期输出:**
1. `MultiBufferDataSource` 记录已缓存的数据范围为 0-1023。
2. 由于请求读取的数据不在已缓存范围内，`MultiBufferDataSource` 会发起一个新的 Range 请求，请求范围为 "bytes=2048-3071"。

**用户或编程常见的使用错误 (举例说明):**

1. **错误地假设所有服务器都支持 Range 请求:**  如果开发者或浏览器错误地假设所有 HTTP 服务器都支持 Range 请求，并以此为基础进行优化，当服务器不支持时可能会导致加载失败或性能下降。`MultiBufferDataSource` 的测试确保了在服务器不支持 Range 请求时能够回退到完整资源加载。
2. **不正确地处理 HTTP 响应状态码:** 开发者或浏览器可能没有正确处理各种 HTTP 错误状态码 (如 404 Not Found, 416 Range Not Satisfiable)，导致用户体验不佳。`MultiBufferDataSource` 的测试覆盖了这些错误状态码的处理。
3. **在多线程环境中不安全地操作共享数据:** 如果多个组件不正确地访问或修改 `MultiBufferDataSource` 管理的共享数据，可能会导致数据不一致或崩溃。测试可以帮助发现这类并发问题。

**功能归纳:**

总而言之，该单元测试文件的第一部分主要集中测试了 `MultiBufferDataSource` 在资源加载、HTTP 协议处理（特别是 Range 请求和分段响应）、错误处理、数据读取和共享等核心功能方面的正确性和健壮性。这些测试确保了 Chromium 能够可靠和高效地加载多媒体资源，为用户提供流畅的媒体播放体验。 该部分还涵盖了预加载策略和码率/播放速率设置对数据加载行为的影响。

Prompt: 
```
这是目录为blink/renderer/platform/media/multi_buffer_data_source_unittest.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2013 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/media/multi_buffer_data_source.h"

#include <stddef.h>
#include <stdint.h>

#include <memory>
#include <utility>

#include "base/containers/heap_array.h"
#include "base/functional/bind.h"
#include "base/memory/scoped_refptr.h"
#include "base/run_loop.h"
#include "base/strings/string_number_conversions.h"
#include "base/task/single_thread_task_runner.h"
#include "base/test/task_environment.h"
#include "media/base/media_switches.h"
#include "media/base/media_util.h"
#include "media/base/mock_filters.h"
#include "media/base/mock_media_log.h"
#include "media/base/test_helpers.h"
#include "services/network/public/mojom/fetch_api.mojom.h"
#include "third_party/blink/public/platform/web_url.h"
#include "third_party/blink/public/platform/web_url_response.h"
#include "third_party/blink/renderer/platform/media/buffered_data_source_host_impl.h"
#include "third_party/blink/renderer/platform/media/multi_buffer_reader.h"
#include "third_party/blink/renderer/platform/media/resource_multi_buffer_data_provider.h"
#include "third_party/blink/renderer/platform/media/testing/mock_resource_fetch_context.h"
#include "third_party/blink/renderer/platform/media/testing/mock_web_associated_url_loader.h"
#include "third_party/blink/renderer/platform/media/testing/test_response_generator.h"

namespace blink {

using ::testing::_;
using ::testing::Assign;
using ::testing::Invoke;
using ::testing::InSequence;
using ::testing::NiceMock;
using ::testing::StrictMock;

class TestMultiBufferDataProvider;

std::set<TestMultiBufferDataProvider*> test_data_providers;

class TestMultiBufferDataProvider : public ResourceMultiBufferDataProvider {
 public:
  TestMultiBufferDataProvider(
      UrlData* url_data,
      MultiBuffer::BlockId pos,
      scoped_refptr<base::SingleThreadTaskRunner> task_runner)
      : ResourceMultiBufferDataProvider(url_data,
                                        pos,
                                        false /* is_client_audio_element */,
                                        std::move(task_runner)) {
    CHECK(test_data_providers.insert(this).second);
  }
  ~TestMultiBufferDataProvider() override {
    CHECK_EQ(static_cast<size_t>(1), test_data_providers.erase(this));
  }

  // ResourceMultiBufferDataProvider overrides.
  void Start() override {
    ResourceMultiBufferDataProvider::Start();
    if (on_start_)
      std::move(on_start_).Run();
  }
  void SetDeferred(bool defer) override {
    deferred_ = defer;
    ResourceMultiBufferDataProvider::SetDeferred(defer);
  }

  bool loading() const { return !!active_loader_; }
  bool deferred() const { return deferred_; }
  void RunOnStart(base::OnceClosure cb) { on_start_ = std::move(cb); }

 private:
  bool deferred_ = false;
  base::OnceClosure on_start_;
};

class TestUrlData;

class TestResourceMultiBuffer : public ResourceMultiBuffer {
 public:
  TestResourceMultiBuffer(
      UrlData* url_data,
      int shift,
      scoped_refptr<base::SingleThreadTaskRunner> task_runner)
      : ResourceMultiBuffer(url_data, shift, task_runner),
        task_runner_(std::move(task_runner)) {}

  std::unique_ptr<MultiBuffer::DataProvider> CreateWriter(const BlockId& pos,
                                                          bool) override {
    auto writer = std::make_unique<TestMultiBufferDataProvider>(url_data_, pos,
                                                                task_runner_);
    writer->Start();
    return writer;
  }

  // TODO: Make these global

  TestMultiBufferDataProvider* GetProvider() {
    EXPECT_EQ(test_data_providers.size(), 1U);
    if (test_data_providers.size() != 1)
      return nullptr;
    return *test_data_providers.begin();
  }
  TestMultiBufferDataProvider* GetProvider_allownull() {
    EXPECT_LE(test_data_providers.size(), 1U);
    if (test_data_providers.size() != 1U)
      return nullptr;
    return *test_data_providers.begin();
  }
  bool HasProvider() const { return test_data_providers.size() == 1U; }
  bool loading() {
    if (test_data_providers.empty())
      return false;
    return GetProvider()->loading();
  }

 private:
  const scoped_refptr<base::SingleThreadTaskRunner> task_runner_;
};

class TestUrlData : public UrlData {
 public:
  TestUrlData(const KURL& url,
              CorsMode cors_mode,
              UrlIndex* url_index,
              UrlData::CacheMode cache_mode,
              scoped_refptr<base::SingleThreadTaskRunner> task_runner)
      : UrlData(url, cors_mode, url_index, cache_mode, task_runner),
        block_shift_(url_index->block_shift()),
        task_runner_(std::move(task_runner)) {}

  ResourceMultiBuffer* multibuffer() override {
    if (!test_multibuffer_.get()) {
      test_multibuffer_ = std::make_unique<TestResourceMultiBuffer>(
          this, block_shift_, task_runner_);
    }
    return test_multibuffer_.get();
  }

  TestResourceMultiBuffer* test_multibuffer() {
    if (!test_multibuffer_.get()) {
      test_multibuffer_ = std::make_unique<TestResourceMultiBuffer>(
          this, block_shift_, task_runner_);
    }
    return test_multibuffer_.get();
  }

 private:
  ~TestUrlData() override = default;

  const int block_shift_;
  std::unique_ptr<TestResourceMultiBuffer> test_multibuffer_;
  const scoped_refptr<base::SingleThreadTaskRunner> task_runner_;
};

class TestUrlIndex : public UrlIndex {
 public:
  TestUrlIndex(ResourceFetchContext* fetch_context,
               scoped_refptr<base::SingleThreadTaskRunner> task_runner)
      : UrlIndex(fetch_context, task_runner),
        task_runner_(std::move(task_runner)) {}

  scoped_refptr<UrlData> NewUrlData(const KURL& url,
                                    UrlData::CorsMode cors_mode,
                                    UrlData::CacheMode cache_mode) override {
    NotifyNewUrlData(url, cors_mode, cache_mode);
    last_url_data_ = base::MakeRefCounted<TestUrlData>(
        url, cors_mode, this, cache_mode, task_runner_);
    return last_url_data_;
  }

  scoped_refptr<TestUrlData> last_url_data() {
    EXPECT_TRUE(last_url_data_);
    return last_url_data_;
  }

  MOCK_METHOD3(NotifyNewUrlData,
               void(KURL, UrlData::CorsMode, UrlData::CacheMode));

 private:
  scoped_refptr<TestUrlData> last_url_data_;
  const scoped_refptr<base::SingleThreadTaskRunner> task_runner_;
};

class MockBufferedDataSourceHost : public BufferedDataSourceHost {
 public:
  MockBufferedDataSourceHost() = default;
  MockBufferedDataSourceHost(const MockBufferedDataSourceHost&) = delete;
  MockBufferedDataSourceHost& operator=(const MockBufferedDataSourceHost&) =
      delete;
  ~MockBufferedDataSourceHost() override = default;

  MOCK_METHOD1(SetTotalBytes, void(int64_t total_bytes));
  MOCK_METHOD2(AddBufferedByteRange, void(int64_t start, int64_t end));
};

class MockMultiBufferDataSource : public MultiBufferDataSource {
 public:
  MockMultiBufferDataSource(
      const scoped_refptr<base::SingleThreadTaskRunner>& task_runner,
      scoped_refptr<UrlData> url_data,
      media::MediaLog* media_log,
      BufferedDataSourceHost* host)
      : MultiBufferDataSource(
            task_runner,
            std::move(url_data),
            media_log,
            host,
            base::BindRepeating(&MockMultiBufferDataSource::set_downloading,
                                base::Unretained(this))),
        downloading_(false) {}

  MockMultiBufferDataSource(const MockMultiBufferDataSource&) = delete;
  MockMultiBufferDataSource& operator=(const MockMultiBufferDataSource&) =
      delete;

  bool downloading() { return downloading_; }
  void set_downloading(bool downloading) { downloading_ = downloading; }
  bool range_supported() { return url_data_->range_supported(); }
  void CallSeekTask() { SeekTask(); }

 private:
  // Whether the resource is downloading or deferred.
  bool downloading_;
};

static const int64_t kFileSize = 5000000;
static const int64_t kFarReadPosition = 3997696;
static const int kDataSize = 32 << 10;

static const char kHttpUrl[] = "http://localhost/foo.webm";
static const char kFileUrl[] = "file:///tmp/bar.webm";
static const char kHttpDifferentPathUrl[] = "http://localhost/bar.webm";
static const char kHttpDifferentOriginUrl[] = "http://127.0.0.1/foo.webm";

class MultiBufferDataSourceTest : public testing::Test {
 public:
  MultiBufferDataSourceTest() : preload_(MultiBufferDataSource::AUTO) {
    ON_CALL(fetch_context_, CreateUrlLoader(_))
        .WillByDefault(Invoke([](const WebAssociatedURLLoaderOptions&) {
          return std::make_unique<NiceMock<MockWebAssociatedURLLoader>>();
        }));
  }

  MultiBufferDataSourceTest(const MultiBufferDataSourceTest&) = delete;
  MultiBufferDataSourceTest& operator=(const MultiBufferDataSourceTest&) =
      delete;

  MOCK_METHOD1(OnInitialize, void(bool));

  void InitializeWithCors(const char* url_string,
                          bool expected,
                          UrlData::CorsMode cors_mode,
                          size_t file_size = kFileSize) {
    KURL url(url_string);
    media_log_ = std::make_unique<NiceMock<media::MockMediaLog>>();
    data_source_ = std::make_unique<MockMultiBufferDataSource>(
        task_runner_, url_index_.GetByUrl(url, cors_mode, UrlData::kNormal),
        media_log_.get(), &host_);
    data_source_->SetPreload(preload_);

    response_generator_ =
        std::make_unique<TestResponseGenerator>(url, file_size);
    EXPECT_CALL(*this, OnInitialize(expected));
    data_source_->SetIsClientAudioElement(is_client_audio_element_);
    data_source_->Initialize(base::BindOnce(
        &MultiBufferDataSourceTest::OnInitialize, base::Unretained(this)));
    base::RunLoop().RunUntilIdle();

    // Not really loading until after OnInitialize is called.
    EXPECT_EQ(data_source_->downloading(), false);
  }

  void Initialize(const char* url,
                  bool expected,
                  size_t file_size = kFileSize) {
    InitializeWithCors(url, expected, UrlData::CORS_UNSPECIFIED, file_size);
  }

  // Helper to initialize tests with a valid 200 response.
  void InitializeWith200Response() {
    Initialize(kHttpUrl, true);

    EXPECT_CALL(host_, SetTotalBytes(response_generator_->content_length()));
    Respond(response_generator_->Generate200());

    EXPECT_CALL(host_, AddBufferedByteRange(0, kDataSize));
    ReceiveData(kDataSize);
  }

  // Helper to initialize tests with a valid 206 response.
  void InitializeWith206Response(size_t file_size = kFileSize) {
    Initialize(kHttpUrl, true, file_size);

    EXPECT_CALL(host_, SetTotalBytes(response_generator_->content_length()));
    Respond(response_generator_->Generate206(0));
    EXPECT_CALL(host_, AddBufferedByteRange(0, kDataSize));
    ReceiveData(kDataSize);
  }

  // Helper to initialize tests with a valid file:// response.
  void InitializeWithFileResponse() {
    Initialize(kFileUrl, true);

    EXPECT_CALL(host_, SetTotalBytes(kFileSize));
    EXPECT_CALL(host_, AddBufferedByteRange(0, kFileSize));
    Respond(response_generator_->GenerateFileResponse(0));

    ReceiveData(kDataSize);
  }

  // Starts data source.
  void Start() {
    EXPECT_TRUE(data_provider());
    EXPECT_FALSE(active_loader_allownull());
    data_provider()->Start();
  }

  // Stops any active loaders and shuts down the data source.
  //
  // This typically happens when the page is closed and for our purposes is
  // appropriate to do when tearing down a test.
  void Stop() {
    if (loading()) {
      data_provider()->DidFail(response_generator_->GenerateError());
      base::RunLoop().RunUntilIdle();
    }

    data_source_->Stop();
    base::RunLoop().RunUntilIdle();
  }

  void Respond(const WebURLResponse& response) {
    EXPECT_TRUE(active_loader());
    data_provider()->DidReceiveResponse(response);
    base::RunLoop().RunUntilIdle();
  }

  void ReceiveDataLow(int size) {
    EXPECT_TRUE(active_loader());
    auto data = base::HeapArray<char>::Uninit(size);
    memset(data.data(), 0xA5, size);  // Arbitrary non-zero value.

    data_provider()->DidReceiveData(data);
  }

  void ReceiveData(int size) {
    ReceiveDataLow(size);
    base::RunLoop().RunUntilIdle();
  }

  void FinishLoading() {
    EXPECT_TRUE(active_loader());
    data_provider()->DidFinishLoading();
    base::RunLoop().RunUntilIdle();
  }

  void FailLoading() {
    data_provider()->DidFail(response_generator_->GenerateError());
    base::RunLoop().RunUntilIdle();
  }

  MOCK_METHOD1(ReadCallback, void(int size));

  void ReadAt(int64_t position, int howmuch = kDataSize) {
    data_source_->Read(position, howmuch, buffer_,
                       base::BindOnce(&MultiBufferDataSourceTest::ReadCallback,
                                      base::Unretained(this)));
    base::RunLoop().RunUntilIdle();
  }

  void ExecuteMixedResponseSuccessTest(const WebURLResponse& response1,
                                       const WebURLResponse& response2) {
    EXPECT_CALL(host_, SetTotalBytes(kFileSize));
    EXPECT_CALL(host_, AddBufferedByteRange(0, kDataSize * 2));
    EXPECT_CALL(host_, AddBufferedByteRange(0, kDataSize));
    EXPECT_CALL(*this, ReadCallback(kDataSize)).Times(2);

    Respond(response1);
    ReceiveData(kDataSize);
    ReadAt(0);
    EXPECT_TRUE(loading());

    FinishLoading();
    Start();
    ReadAt(kDataSize);
    Respond(response2);
    ReceiveData(kDataSize);
    FinishLoading();
    Stop();
  }

  void ExecuteMixedResponseFailureTest(const WebURLResponse& response1,
                                       const WebURLResponse& response2) {
    EXPECT_CALL(host_, SetTotalBytes(kFileSize));
    EXPECT_CALL(host_, AddBufferedByteRange(0, kDataSize));
    EXPECT_CALL(*this, ReadCallback(kDataSize));
    // Stop() will also cause the readback to be called with kReadError, but
    // we want to make sure it was called before Stop().
    bool failed_ = false;
    EXPECT_CALL(*this, ReadCallback(media::DataSource::kReadError))
        .WillOnce(Assign(&failed_, true));

    Respond(response1);
    ReceiveData(kDataSize);
    ReadAt(0);
    EXPECT_TRUE(loading());

    FinishLoading();
    Start();
    ReadAt(kDataSize);
    Respond(response2);
    EXPECT_TRUE(failed_);
    Stop();
  }

  void CheckCapacityDefer() {
    EXPECT_EQ(2 << 20, preload_low());
    EXPECT_EQ(3 << 20, preload_high());
  }

  void CheckReadThenDefer() {
    EXPECT_EQ(2 << 14, preload_low());
    EXPECT_EQ(3 << 14, preload_high());
  }

  void CheckNeverDefer() {
    EXPECT_EQ(1LL << 40, preload_low());
    EXPECT_EQ(1LL << 40, preload_high());
  }

  // Accessors for private variables on |data_source_|.
  MultiBufferReader* loader() { return data_source_->reader_.get(); }

  TestResourceMultiBuffer* multibuffer() {
    return url_index_.last_url_data()->test_multibuffer();
  }

  TestMultiBufferDataProvider* data_provider() {
    return multibuffer()->GetProvider();
  }
  WebAssociatedURLLoader* active_loader() {
    EXPECT_TRUE(data_provider());
    if (!data_provider())
      return nullptr;
    return data_provider()->active_loader_.get();
  }
  WebAssociatedURLLoader* active_loader_allownull() {
    TestMultiBufferDataProvider* data_provider =
        multibuffer()->GetProvider_allownull();
    if (!data_provider)
      return nullptr;
    return data_provider->active_loader_.get();
  }
  bool loading() { return multibuffer()->loading(); }

  MultiBufferDataSource::Preload preload() { return data_source_->preload_; }
  void set_preload(MultiBufferDataSource::Preload preload) {
    preload_ = preload;
  }
  int64_t preload_high() {
    CHECK(loader());
    return loader()->preload_high();
  }
  int64_t preload_low() {
    CHECK(loader());
    return loader()->preload_low();
  }
  int data_source_bitrate() { return data_source_->bitrate_; }
  int64_t max_buffer_forward() { return loader()->max_buffer_forward_; }
  int64_t max_buffer_backward() { return loader()->max_buffer_backward_; }
  int64_t buffer_size() {
    return loader()->current_buffer_size_ * 32768 /* block size */;
  }
  double data_source_playback_rate() { return data_source_->playback_rate_; }
  bool is_local_source() { return data_source_->AssumeFullyBuffered(); }
  bool is_client_audio_element() { return loader()->is_client_audio_element_; }
  scoped_refptr<UrlData> url_data() { return data_source_->url_data_; }
  void set_might_be_reused_from_cache_in_future(bool value) {
    url_data()->set_cacheable(value);
  }
  void set_is_client_audio_element(bool value) {
    is_client_audio_element_ = value;
  }

 protected:
  base::test::SingleThreadTaskEnvironment task_environment_;
  MultiBufferDataSource::Preload preload_;
  NiceMock<MockResourceFetchContext> fetch_context_;
  const scoped_refptr<base::SingleThreadTaskRunner> task_runner_ =
      task_environment_.GetMainThreadTaskRunner();
  TestUrlIndex url_index_{&fetch_context_, task_runner_};

  std::unique_ptr<media::MediaLog> media_log_;
  std::unique_ptr<MockMultiBufferDataSource> data_source_;

  std::unique_ptr<TestResponseGenerator> response_generator_;

  StrictMock<MockBufferedDataSourceHost> host_;

  // Used for calling MultiBufferDataSource::Read().
  uint8_t buffer_[kDataSize * 2];

  bool is_client_audio_element_ = false;
};

TEST_F(MultiBufferDataSourceTest, Range_Supported) {
  InitializeWith206Response();

  EXPECT_TRUE(loading());
  EXPECT_FALSE(data_source_->IsStreaming());
  Stop();
}

TEST_F(MultiBufferDataSourceTest, Range_InstanceSizeUnknown) {
  Initialize(kHttpUrl, true);

  Respond(response_generator_->Generate206(
      0, TestResponseGenerator::kNoContentRangeInstanceSize));

  EXPECT_CALL(host_, AddBufferedByteRange(0, kDataSize));
  ReceiveData(kDataSize);

  EXPECT_TRUE(loading());
  EXPECT_TRUE(data_source_->IsStreaming());
  Stop();
}

TEST_F(MultiBufferDataSourceTest, Range_NotFound) {
  Initialize(kHttpUrl, false);
  Respond(response_generator_->Generate404());

  EXPECT_FALSE(loading());
  Stop();
}

TEST_F(MultiBufferDataSourceTest, Range_NotSupported) {
  InitializeWith200Response();

  EXPECT_TRUE(loading());
  EXPECT_TRUE(data_source_->IsStreaming());
  Stop();
}

TEST_F(MultiBufferDataSourceTest, Range_NotSatisfiable) {
  Initialize(kHttpUrl, true);
  EXPECT_CALL(host_, AddBufferedByteRange(0, kDataSize));
  Respond(response_generator_->GenerateResponse(416));
  EXPECT_FALSE(loading());
  Stop();
}

// Special carve-out for Apache versions that choose to return a 200 for
// Range:0- ("because it's more efficient" than a 206)
TEST_F(MultiBufferDataSourceTest, Range_SupportedButReturned200) {
  Initialize(kHttpUrl, true);
  EXPECT_CALL(host_, SetTotalBytes(response_generator_->content_length()));
  WebURLResponse response = response_generator_->Generate200();
  response.SetHttpHeaderField(WebString::FromUTF8("Accept-Ranges"),
                              WebString::FromUTF8("bytes"));
  Respond(response);

  EXPECT_CALL(host_, AddBufferedByteRange(0, kDataSize));
  ReceiveData(kDataSize);

  EXPECT_TRUE(loading());
  EXPECT_FALSE(data_source_->IsStreaming());
  Stop();
}

TEST_F(MultiBufferDataSourceTest, Range_MissingContentRange) {
  Initialize(kHttpUrl, false);
  Respond(response_generator_->Generate206(
      0, TestResponseGenerator::kNoContentRange));

  EXPECT_FALSE(loading());
  Stop();
}

TEST_F(MultiBufferDataSourceTest, Range_MissingContentLength) {
  Initialize(kHttpUrl, true);

  // It'll manage without a Content-Length response.
  EXPECT_CALL(host_, SetTotalBytes(response_generator_->content_length()));
  Respond(response_generator_->Generate206(
      0, TestResponseGenerator::kNoContentLength));

  EXPECT_CALL(host_, AddBufferedByteRange(0, kDataSize));
  ReceiveData(kDataSize);

  EXPECT_TRUE(loading());
  EXPECT_FALSE(data_source_->IsStreaming());
  Stop();
}

TEST_F(MultiBufferDataSourceTest, Range_WrongContentRange) {
  Initialize(kHttpUrl, false);

  // Now it's done and will fail.
  Respond(response_generator_->Generate206(1337));

  EXPECT_FALSE(loading());
  Stop();
}

// Test the case where the initial response from the server indicates that
// Range requests are supported, but a later request prove otherwise.
TEST_F(MultiBufferDataSourceTest, Range_ServerLied) {
  InitializeWith206Response();

  // Read causing a new request to be made, we will discard the data that
  // was already read in the first request.
  ReadAt(kFarReadPosition);

  // Return a 200 in response to a range request.
  EXPECT_CALL(*this, ReadCallback(media::DataSource::kReadError));
  Respond(response_generator_->Generate200());

  EXPECT_TRUE(loading());
  Stop();
}

TEST_F(MultiBufferDataSourceTest, Http_AbortWhileReading) {
  InitializeWith206Response();

  // Make sure there's a pending read -- we'll expect it to error.
  ReadAt(kFileSize);

  // Abort!!!
  EXPECT_CALL(*this, ReadCallback(media::DataSource::kAborted));
  data_source_->Abort();
  base::RunLoop().RunUntilIdle();

  EXPECT_TRUE(loading());
  Stop();
}

TEST_F(MultiBufferDataSourceTest, File_AbortWhileReading) {
  InitializeWithFileResponse();

  // Make sure there's a pending read -- we'll expect it to error.
  ReadAt(kFileSize);

  // Abort!!!
  EXPECT_CALL(*this, ReadCallback(media::DataSource::kAborted));
  data_source_->Abort();
  base::RunLoop().RunUntilIdle();

  EXPECT_TRUE(loading());
  Stop();
}

TEST_F(MultiBufferDataSourceTest, Http_Retry) {
  InitializeWith206Response();

  // Read to advance our position.
  EXPECT_CALL(*this, ReadCallback(kDataSize));
  ReadAt(0);

  // Issue a pending read but terminate the connection to force a retry.
  ReadAt(kDataSize);
  FinishLoading();
  Start();
  Respond(response_generator_->Generate206(kDataSize));

  // Complete the read.
  EXPECT_CALL(*this, ReadCallback(kDataSize));
  EXPECT_CALL(host_, AddBufferedByteRange(0, kDataSize * 2));
  ReceiveData(kDataSize);

  EXPECT_TRUE(loading());
  Stop();
}

TEST_F(MultiBufferDataSourceTest, Http_RetryOnError) {
  InitializeWith206Response();

  // Read to advance our position.
  EXPECT_CALL(*this, ReadCallback(kDataSize));
  ReadAt(0);

  // Issue a pending read but trigger an error to force a retry.
  EXPECT_CALL(*this, ReadCallback(kDataSize));
  EXPECT_CALL(host_, AddBufferedByteRange(0, kDataSize * 2));
  ReadAt(kDataSize);
  base::RunLoop run_loop;
  data_provider()->DidFail(response_generator_->GenerateError());
  data_provider()->RunOnStart(run_loop.QuitClosure());
  run_loop.Run();
  Respond(response_generator_->Generate206(kDataSize));
  ReceiveData(kDataSize);
  FinishLoading();
  EXPECT_FALSE(loading());
  Stop();
}

// Make sure that we prefetch across partial responses. (crbug.com/516589)
TEST_F(MultiBufferDataSourceTest, Http_PartialResponsePrefetch) {
  Initialize(kHttpUrl, true);
  WebURLResponse response1 =
      response_generator_->GeneratePartial206(0, kDataSize - 1);
  WebURLResponse response2 =
      response_generator_->GeneratePartial206(kDataSize, kDataSize * 3 - 1);

  EXPECT_CALL(host_, SetTotalBytes(kFileSize));
  EXPECT_CALL(host_, AddBufferedByteRange(0, kDataSize * 3));
  EXPECT_CALL(host_, AddBufferedByteRange(0, kDataSize * 2));
  EXPECT_CALL(host_, AddBufferedByteRange(0, kDataSize));
  EXPECT_CALL(*this, ReadCallback(kDataSize));

  Respond(response1);
  ReceiveData(kDataSize);
  ReadAt(0);
  EXPECT_TRUE(loading());

  FinishLoading();
  Start();
  Respond(response2);
  ReceiveData(kDataSize);
  ReceiveData(kDataSize);
  FinishLoading();
  Stop();
}

TEST_F(MultiBufferDataSourceTest, Http_PartialResponse) {
  Initialize(kHttpUrl, true);
  WebURLResponse response1 =
      response_generator_->GeneratePartial206(0, kDataSize - 1);
  WebURLResponse response2 =
      response_generator_->GeneratePartial206(kDataSize, kDataSize * 2 - 1);
  // The origin URL of response1 and response2 are same. So no error should
  // occur.
  ExecuteMixedResponseSuccessTest(response1, response2);
}

TEST_F(MultiBufferDataSourceTest,
       Http_MixedResponse_RedirectedToDifferentPathResponse) {
  Initialize(kHttpUrl, true);
  WebURLResponse response1 =
      response_generator_->GeneratePartial206(0, kDataSize - 1);
  WebURLResponse response2 =
      response_generator_->GeneratePartial206(kDataSize, kDataSize * 2 - 1);
  response2.SetCurrentRequestUrl(KURL(kHttpDifferentPathUrl));
  // The origin URL of response1 and response2 are same. So no error should
  // occur.
  ExecuteMixedResponseSuccessTest(response1, response2);
}

TEST_F(MultiBufferDataSourceTest,
       Http_MixedResponse_RedirectedToDifferentOriginResponse) {
  Initialize(kHttpUrl, true);
  WebURLResponse response1 =
      response_generator_->GeneratePartial206(0, kDataSize - 1);
  WebURLResponse response2 =
      response_generator_->GeneratePartial206(kDataSize, kDataSize * 2 - 1);
  response2.SetCurrentRequestUrl(KURL(kHttpDifferentOriginUrl));
  // The origin URL of response1 and response2 are different. So an error should
  // occur.
  ExecuteMixedResponseFailureTest(response1, response2);
}

TEST_F(MultiBufferDataSourceTest,
       Http_MixedResponse_ServiceWorkerGeneratedResponseAndNormalResponse) {
  Initialize(kHttpUrl, true);
  WebURLResponse response1 =
      response_generator_->GeneratePartial206(0, kDataSize - 1);
  response1.SetWasFetchedViaServiceWorker(true);
  WebURLResponse response2 =
      response_generator_->GeneratePartial206(kDataSize, kDataSize * 2 - 1);
  // response1 is generated in a Service Worker but response2 is from a native
  // server. So an error should occur.
  ExecuteMixedResponseFailureTest(response1, response2);
}

TEST_F(MultiBufferDataSourceTest,
       Http_MixedResponse_ServiceWorkerProxiedAndSameURLResponse) {
  Initialize(kHttpUrl, true);
  WebURLResponse response1 =
      response_generator_->GeneratePartial206(0, kDataSize - 1);
  response1.SetWasFetchedViaServiceWorker(true);
  std::vector<WebURL> url_list = {KURL(kHttpUrl)};
  response1.SetUrlListViaServiceWorker(url_list);
  WebURLResponse response2 =
      response_generator_->GeneratePartial206(kDataSize, kDataSize * 2 - 1);
  // The origin URL of response1 and response2 are same. So no error should
  // occur.
  ExecuteMixedResponseSuccessTest(response1, response2);
}

TEST_F(MultiBufferDataSourceTest,
       Http_MixedResponse_ServiceWorkerProxiedAndDifferentPathResponse) {
  Initialize(kHttpUrl, true);
  WebURLResponse response1 =
      response_generator_->GeneratePartial206(0, kDataSize - 1);
  response1.SetWasFetchedViaServiceWorker(true);
  std::vector<WebURL> url_list = {KURL(kHttpDifferentPathUrl)};
  response1.SetUrlListViaServiceWorker(url_list);
  WebURLResponse response2 =
      response_generator_->GeneratePartial206(kDataSize, kDataSize * 2 - 1);
  // The origin URL of response1 and response2 are same. So no error should
  // occur.
  ExecuteMixedResponseSuccessTest(response1, response2);
}

TEST_F(MultiBufferDataSourceTest,
       Http_MixedResponse_ServiceWorkerProxiedAndDifferentOriginResponse) {
  Initialize(kHttpUrl, true);
  WebURLResponse response1 =
      response_generator_->GeneratePartial206(0, kDataSize - 1);
  response1.SetWasFetchedViaServiceWorker(true);
  std::vector<WebURL> url_list = {KURL(kHttpDifferentOriginUrl)};
  response1.SetUrlListViaServiceWorker(url_list);
  WebURLResponse response2 =
      response_generator_->GeneratePartial206(kDataSize, kDataSize * 2 - 1);
  // The origin URL of response1 and response2 are different. So an error should
  // occur.
  ExecuteMixedResponseFailureTest(response1, response2);
}

TEST_F(MultiBufferDataSourceTest,
       Http_MixedResponse_ServiceWorkerProxiedAndDifferentOriginResponseCors) {
  InitializeWithCors(kHttpUrl, true, UrlData::CORS_ANONYMOUS);
  WebURLResponse response1 =
      response_generator_->GeneratePartial206(0, kDataSize - 1);
  response1.SetWasFetchedViaServiceWorker(true);
  std::vector<WebURL> url_list = {KURL(kHttpDifferentOriginUrl)};
  response1.SetUrlListViaServiceWorker(url_list);
  WebURLResponse response2 =
      response_generator_->GeneratePartial206(kDataSize, kDataSize * 2 - 1);
  // The origin URL of response1 and response2 are different, but a CORS check
  // has been passed for each request, so expect success.
  ExecuteMixedResponseSuccessTest(response1, response2);
}

TEST_F(MultiBufferDataSourceTest, File_Retry) {
  InitializeWithFileResponse();

  // Read to advance our position.
  EXPECT_CALL(*this, ReadCallback(kDataSize));
  ReadAt(0);

  // Issue a pending read but terminate the connection to force a retry.
  ReadAt(kDataSize);
  FinishLoading();
  Start();
  Respond(response_generator_->GenerateFileResponse(kDataSize));

  // Complete the read.
  EXPECT_CALL(*this, ReadCallback(kDataSize));
  ReceiveData(kDataSize);

  EXPECT_TRUE(loading());
  Stop();
}

TEST_F(MultiBufferDataSourceTest, Http_TooManyRetries) {
  InitializeWith206Response();

  // Make sure there's a pending read -- we'll expect it to error.
  ReadAt(kDataSize);

  for (int i = 0; i < ResourceMultiBufferDataProvider::kMaxRetries; i++) {
    FailLoading();
    Start();
    Respond(response_generator_->Generate206(kDataSize));
  }

  // Stop() will also cause the readback to be called with kReadError, but
  // we want to make sure it was called during FailLoading().
  bool failed_ = false;
  EXPECT_CALL(*this, ReadCallback(media::DataSource::kReadError))
      .WillOnce(Assign(&failed_, true));
  FailLoading();
  EXPECT_TRUE(failed_);
  EXPECT_FALSE(loading());
  Stop();
}

TEST_F(MultiBufferDataSourceTest, File_TooManyRetries) {
  InitializeWithFileResponse();

  // Make sure there's a pending read -- we'll expect it to error.
  ReadAt(kDataSize);

  for (int i = 0; i < ResourceMultiBufferDataProvider::kMaxRetries; i++) {
    FailLoading();
    Start();
    Respond(response_generator_->Generate206(kDataSize));
  }

  // Stop() will also cause the readback to be called with kReadError, but
  // we want to make sure it was called during FailLoading().
  bool failed_ = false;
  EXPECT_CALL(*this, ReadCallback(media::DataSource::kReadError))
      .WillOnce(Assign(&failed_, true));
  FailLoading();
  EXPECT_TRUE(failed_);
  EXPECT_FALSE(loading());
  Stop();
}

TEST_F(MultiBufferDataSourceTest, File_InstanceSizeUnknown) {
  Initialize(kFileUrl, false);

  Respond(
      response_generator_->GenerateFileResponse(media::DataSource::kReadError));
  ReceiveData(kDataSize);

  EXPECT_FALSE(data_source_->downloading());
  EXPECT_FALSE(loading());
  Stop();
}

TEST_F(MultiBufferDataSourceTest, File_Successful) {
  InitializeWithFileResponse();

  EXPECT_TRUE(loading());
  EXPECT_FALSE(data_source_->IsStreaming());
  Stop();
}

TEST_F(MultiBufferDataSourceTest, StopDuringRead) {
  InitializeWith206Response();

  uint8_t buffer[256];
  data_source_->Read(kDataSize, std::size(buffer), buffer,
                     base::BindOnce(&MultiBufferDataSourceTest::ReadCallback,
                                    base::Unretained(this)));

  // The outstanding read should fail before the stop callback runs.
  {
    InSequence s;
    EXPECT_CALL(*this, ReadCallback(media::DataSource::kReadError));
    data_source_->Stop();
  }
  base::RunLoop().RunUntilIdle();
}

TEST_F(MultiBufferDataSourceTest, DefaultValues) {
  InitializeWith206Response();

  // Ensure we have sane values for default loading scenario.
  EXPECT_EQ(MultiBufferDataSource::AUTO, preload());
  EXPECT_EQ(2 << 20, preload_low());
  EXPECT_EQ(3 << 20, preload_high());

  EXPECT_EQ(0, data_source_bitrate());
  EXPECT_EQ(0.0, data_source_playback_rate());

  EXPECT_TRUE(loading());
  Stop();
}

TEST_F(MultiBufferDataSourceTest, SetBitrate) {
  InitializeWith206Response();

  data_source_->SetBitrate(1234);
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(1234, data_source_bitrate());

  // Read so far ahead to cause the loader to get recreated.
  TestMultiBufferDataProvider* old_loader = data_provider();
  ReadAt(kFarReadPosition);
  Respond(response_generator_->Generate206(kFarReadPosition));

  // Verify loader changed but still has same bitrate.
  EXPECT_NE(old_loader, data_provider());

  EXPECT_TRUE(loading());
  EXPECT_CALL(*this, ReadCallback(media::DataSource::kReadError));
  Stop();
}

TEST_F(MultiBufferDataSourceTest, MediaPlaybackRateChanged) {
  InitializeWith206Response();

  data_source_->OnMediaPlaybackRateChanged(2.0);
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(2.0, data_source_playback_rate());

  // Read so far ahead to cause the loader to get recreated.
  TestMultiBufferDataProvider* old_loader = data_provider();
  ReadAt(kFarReadPosition);
  Respond(response_generator_->Generate206(kFarReadPosition));

  // Verify loader changed but still has same playback rate.
  EXPECT_NE(old_loader, data_provider());

  EXPECT_TRUE(loading());
  EXPECT_CALL(*this, ReadCallback(media::DataSource::kReadError));
  Stop();
}

TEST_F(MultiBufferDataSourceTest, Http_Read) {
  InitializeWith206Response();

  EXPECT_CALL(*this, ReadCallback(kDataSize));
  ReadAt(0, kDataSize * 2);

  ReadAt(kDataSize, kDataSize);
  EXPECT_CALL(*this, ReadCallback(kDataSize));
  EXPECT_CALL(host_,
              AddBufferedByteRange(kDataSize, kDataSize + kDataSize / 2));
  ReceiveData(kDataSize / 2);
  EXPECT_CALL(host_, AddBufferedByteRange(0, kDataSize * 2));
  ReceiveData(kDataSize / 2);

  EXPECT_TRUE(data_source_->downloading());
  Stop();
}

TEST_F(MultiBufferDataSourceTest, Http_ShareData) {
  InitializeWith206Response();

  EXPECT_CALL(*this, ReadCallback(kDataSize));
  ReadAt(0, kDataSize * 2);

  ReadAt(kDataSize, kDataSize);
  EXPECT_CALL(*this, ReadCallback(kDataSize));
  EXPECT_CALL(host_,
              AddBufferedByteRange(kDataSize, kDataSize + kDataSize / 2));
  ReceiveData(kDataSize / 2);
  EXPECT_CALL(host_, AddBufferedByteRange(0, kDataSize * 2));
  ReceiveData(kDataSize / 2);

  EXPECT_TRUE(data_source_->downloading());

  StrictMock<MockBufferedDataSourceHost> host2;
  media_log_ = std::make_unique<NiceMock<media::MockMediaLog>>();
  MockMultiBufferDataSource source2(
      task_runner_,
      url_index_.GetByUrl(KURL(kHttpUrl), UrlData::CORS_UNSPECIFIED,
                          UrlData::kNormal),
      media_log_.get(), &host2);
  source2.SetPreload(preload_);

  EXPECT_CALL(*this, OnInitialize(true));

  // This call would not be expected if we were not sharing data.
  EXPECT_CALL(host2, SetTotalBytes(response_generator_->content_length()));
  EXPECT_CALL(host2, AddBufferedByteRange(0, kDataSize * 2));
  source2.Initialize(base::BindOnce(&MultiBufferDataSourceTest::OnInitialize,
                                    base::Unretained(this)));
  base::RunLoop().RunUntilIdle();

  // Always loading after initialize.
  EXPECT_EQ(source2.downloading(), true);

  Stop();
}

TEST_F(MultiBufferDataSourceTest, Http_ShareData_AtLeastOneProgress) {
  // Initialize the first provider.
  Initialize(kHttpUrl, true, kFileSize);
  ASSERT_EQ(test_data_providers.size(), 1u);
  auto* provider1 = *test_data_providers.begin();

  // Initialize the second provider before the first receives any response.
  StrictMock<MockBufferedDataSourceHost> host2;
  media_log_ = std::make_unique<NiceMock<media::MockMediaLog>>();
  MockMultiBufferDataSource source2(
      task_runner_,
      url_index_.GetByUrl(KURL(kHttpUrl), UrlData::CORS_UNSPECIFIED,
                          UrlData::kNormal),
      media_log_.get(), &host2);
  source2.SetPreload(preload_);
  source2.Initialize(base::DoNothing());

  ASSERT_EQ(test_data_providers.size(), 2u);
  TestMultiBufferDataProvider* provider2 = nullptr;
  for (auto* provider : test_data_providers) {
    if (provider != provider1) {
      provider2 = provider;
      break;
    }
  }
  ASSERT_TRUE(provider2);

  // Respond to the first provider w/ a response and data.
  const auto total_bytes = response_generator_->content_length();
  EXPECT_CALL(host_, SetTotalBytes(total_bytes));
  provider1->DidReceiveResponse(response_generator_->Generate206(0));
  EXPECT_CALL(host_, AddBufferedByteRange(0, testing::Ge(total_bytes)))
      .Times(testing::AtLeast(1));

  auto data = base::HeapArray<char>::Uninit(total_bytes);
  base::ranges::fill(data, 0xA5);  // Arbitrary non-zero value.
  provider1->DidReceiveData(data);
  provider1->DidFinishLoading();
  task_environment_.RunUntilIdle();

  // Now respond to the second provider, it should merge with the first since
  // it can share the previous data. Note: MultiBuffer provides byte ranges in
  // terms of block units, so the buffered range may exceed total bytes.
  EXPECT_CALL(host2, AddBufferedByteRange(0, testing::Ge(total_bytes)));
  EXPECT_CALL(host2, SetTotalBytes(total_bytes));
  provider2->DidReceiveResponse(response_generator_->Generate206(0));
  provider1 = provider2 = nullptr;  // May have been released at this point.

  EXPECT_CALL(*this, ReadCallback(kDataSize));
  ReadAt(0, kDataSize);
  task_environment_.RunUntilIdle();

  // Expectations should be met before Stop() is called.
  testing::Mock::VerifyAndClear(&host_);
  testing::Mock::VerifyAndClear(&host2);

  data_source_->Stop();
  task_environment_.RunUntilIdle();
}

TEST_F(MultiBufferDataSourceTest, Http_Read_Seek) {
  InitializeWith206Response();

  // Read a bit from the beginning.
  EXPECT_CALL(*this, ReadCallback(kDataSize));
  ReadAt(0);

  // Simulate a seek by reading a bit beyond kDataSize.
  ReadAt(kDataSize * 2);

  // We receive data leading up to but not including our read.
  // No notification will happen, since it's progress outside
  // of our current range.
  ReceiveData(kDataSize);

  // We now receive the rest of the data for our read.
  EXPECT_CALL(*this, ReadCallback(kDataSize));
  EXPECT_CALL(host_, AddBufferedByteRange(0, kDataSize * 3));
  ReceiveData(kDataSize);

  EXPECT_TRUE(data_source_->downloading());
  Stop();
}

TEST_F(MultiBufferDataSourceTest, File_Read) {
  InitializeWithFileResponse();

  EXPECT_CALL(*this, ReadCallback(kDataSize));
  ReadAt(0, kDataSize * 2);

  ReadAt(kDataSize, kDataSize);
  EXPECT_CALL(*this, ReadCallback(kDataSize));
  ReceiveData(kDataSize);

  Stop();
}

TEST_F(MultiBufferDataSourceTest, Http_FinishLoading) {
  InitializeWith206Response();

  EXPECT_TRUE(data_source_->downloading());
  // premature didFinishLoading() will cause a retry.
  FinishLoading();
  EXPECT_TRUE(data_source_->downloading());

  Stop();
}

TEST_F(MultiBufferDataSourceTest, File_FinishLoading) {
  InitializeWithFileResponse();

  ReceiveData(kDataSize);

  EXPECT_FALSE(data_source_->downloading());
  // premature didFinishLoading() will cause a retry.
  FinishLoading();
  EXPECT_FALSE(data_source_->downloading());

  Stop();
}

TEST_F(MultiBufferDataSourceTest, LocalResource_DeferStrategy) {
  InitializeWithFileResponse();

  EXPECT_EQ(MultiBufferDataSource::AUTO, preload());
  EXPECT_TRUE(is_local_source());
  CheckCapacityDefer();

  data_source_->OnMediaIsPlaying();
  CheckCapacityDefer();

  Stop();
}

TEST_F(MultiBufferDataSourceTest, LocalResource_PreloadMetadata_DeferStrategy) {
  set_preload(MultiBufferDataSource::METADATA);
  InitializeWithFileResponse();

  EXPECT_EQ(MultiBufferDataSource::METADATA, preload());
  EXPECT_TRUE(is_local_source());
  CheckReadThenDefer();

  data_source_->OnMediaIsPlaying();
  CheckCapacityDefer();

  Stop();
}

TEST_F(MultiBufferDataSourceTest, ExternalResource_Reponse200_DeferStrategy) {
  InitializeWith200Response();

  EXPECT_EQ(MultiBufferDataSource::AUTO, preload());
  EXPECT_FALSE(is_local_source());
  EXPECT_FALSE(data_source_->range_supported());
  CheckCapacityDefer();

  data_source_->OnMediaIsPlaying();
  CheckCapacityDefer();

  Stop();
}

TEST_F(MultiBufferDataSourceTest,
       ExternalResource_Response200_PreloadMetadata_DeferStrategy) {
  set_preload(MultiBufferDataSource::METADATA);
  InitializeWith200Response();

  EXPECT_EQ(MultiBufferDataSource::METADATA, preload());
  EXPECT_FALSE(is_local_source());
  EXPECT_FALSE(data_source_->range_supported());
  CheckReadThenDefer();

  data_source_->OnMediaIsPlaying();
  CheckCapacityDefer();

  Stop();
}

TEST_F(MultiBufferDataSourceTest, ExternalResource_Reponse206_DeferStrategy) {
  InitializeWith206Response();

  EXPECT_EQ(MultiBufferDataSource::AUTO, preload());
  EXPECT_FALSE(is_local_source());
  EXPECT_TRUE(data_source_->range_supported());
  CheckCapacityDefer();

  data_source_->OnMediaIsPlaying();
  CheckCapacityDefer();

  set_might_be_reused_from_cache_in_future(true);
  data_source_->OnMediaIsPlaying();
  CheckCapacityDefer();

  Stop();
}

TEST_F(MultiBufferDataSourceTest,
       ExternalResource_Response206_PreloadMetadata_DeferStrategy) {
  set_preload(MultiBufferDataSource::METADATA);
  InitializeWith206Response();

  EXPECT_EQ(MultiBufferDataSource::METADATA, preload());
  EXPECT_FALSE(is_local_source());
  EXPECT_TRUE(data_source_->range_supported());
  CheckReadThenDefer();

  data_source_->OnMediaIsPlaying();
  CheckCapacityDefer();

  set_might_be_reused_from_cache_in_future(true);
  data_source_->OnMediaIsPlaying();
  CheckCapacityDefer();

  set_might_be_reused_from_cache_in_future(false);
  CheckCapacityDefer();

  Stop();
}

TEST_F(MultiBufferDataSourceTest, ExternalResource_Response206_VerifyDefer) {
  set_preload(MultiBufferDataSource::METADATA);
  InitializeWith206Response();

  EXPECT_EQ(MultiBufferDataSource::METADATA, preload());
  EXPECT_FALSE(is_local_source());
  EXPECT_TRUE(data_source_->range_supported());
  CheckReadThenDefer();

  // Read a bit from the beginning.
  EXPECT_CALL(*this, ReadCallback(kDataSize));
  ReadAt(0);

  EXPECT_CALL(host_, AddBufferedByteRange(0, kDataSize * 2));
  ReceiveData(kDataSize);

  ASSERT_TRUE(active_loader());
  EXPECT_TRUE(data_provider()->deferred());
}

TEST_F(MultiBufferDataSourceTest,
       ExternalResource_Response206_CancelAfterDefer) {
  set_preload(MultiBufferDataSource::METADATA);
  InitializeWith206Response();

  EXPECT_EQ(MultiBufferDataSource::METADATA, preload());
  EXPECT_FALSE(is_local_source());

  EXPECT_TRUE(data_source_->range_supported());
  CheckReadThenDefer();

  ReadAt(kDataSize);

  data_source_->OnBufferingHaveEnough(false);
  ASSERT_TRUE(active_loader());

  EXPECT_CALL(*this, ReadCallback(kDataSize));
  EXPECT_CALL(host_, AddBufferedByteRange(0, kDataSize * 2));
  ReceiveData(kDataSize);

  EXPECT_CALL(host_, AddBufferedByteRange(0, kDataSize * 3));
  ReceiveData(kDataSize);

  EXPECT_CALL(host_, AddBufferedByteRange(0, kDataSize * 4));
  ReceiveData(kDataSize);

  EXPECT_FALSE(active_loader_allownull());
}

// This test tries to trigger an edge case where the read callback
// never happens because the reader is deleted before that happens.
TEST_F(MultiBufferDataSourceTest,
       ExternalResource_Response206_CancelAfterDefer2) {
  set_preload(MultiBufferDataSource::METADATA);
  InitializeWith206Response();

  EXPECT_EQ(MultiBufferDataSource::METADATA, preload());
  EXPECT_FALSE(is_local_source());

  EXPECT_TRUE(data_source_->range_supported());
  CheckReadThenDefer();

  ReadAt(kDataSize);

  data_source_->OnBufferingHaveEnough(false);
  ASSERT_TRUE(active_loader());

  EXPECT_CALL(*this, ReadCallback(kDataSize));
  EXPECT_CALL(host_, AddBufferedByteRange(kDataSize, kDataSize + 2000));

  ReceiveDataLow(2000);
  EXPECT_CALL(host_, AddBufferedByteRange(0, kDataSize * 2 + 2000));
  EXPECT_CALL(host_, AddBufferedByteRange(kDataSize * 2, kDataSize * 2 + 2000));
  ReceiveDataLow(kDataSize);

  base::RunLoop().RunUntilIdle();

  EXPECT_CALL(host_, AddBufferedByteRange(0, kDataSize * 3 + 2000));
  ReceiveData(kDataSize);

  EXPECT_CALL(host_, AddBufferedByteRange(0, kDataSize * 4 + 2000));
  ReceiveData(kDataSize);

  EXPECT_FALSE(active_loader_allownull());
}

// This test tries to trigger an edge case where the read callback
// never happens because the reader is deleted before that happens.
TEST_F(MultiBufferDataSourceTest,
       ExternalResource_Response206_CancelAfterDefer3) {
  set_preload(MultiBufferDataSource::METADATA);
  InitializeWith206Response();

  EXPECT_EQ(MultiBufferDataSource::METADATA, preload());
  EXPECT_FALSE(is_local_source());

  EXPECT_TRUE(data_source_->range_supported());
  CheckReadThenDefer();

  ReadAt(kDataSize);
  ASSERT_TRUE(active_loader());

  EXPECT_CALL(*this, ReadCallback(kDataSize));
  EXPECT_CALL(host_, AddBufferedByteRange(0, kDataSize * 2));
  ReceiveData(kDataSize);

  EXPECT_CALL(host_, AddBufferedByteRange(0, kDataSize * 3));
  ReceiveData(kDataSize);

  EXPECT_CALL(host_, AddBufferedByteRange(0, kDataSize * 4));
  ReceiveData(kDataSize);
  EXPECT_EQ(data_source_->downloading(), false);
  data_source_->Read(kDataSize * 10, kDataSize, buffer_,
                     base::BindOnce(&MultiBufferDataSourceTest::ReadCallback,
                                    base::Unretained(this)));
  data_source_->OnBufferingHaveEnough(false);
  EXPECT_TRUE(active_loader_allownull());
  EXPECT_CALL(*this, ReadCallback(-1));
  Stop();
}

TEST_F(MultiBufferDataSourceTest,
       ExternalResource_Response206_CancelAfterPlay) {
  set_preload(MultiBufferDataSource::METADATA);
  InitializeWith206Response();

  EXPECT_EQ(MultiBufferDataSource::METADATA, preload());
  EXPECT_FALSE(is_local_source());

  EXPECT_TRUE(data_source_->range_supported());
  CheckReadThenDefer();

  ReadAt(kDataSize);

  // Marking the media as playing should prevent deferral. It also tells the
  // data source to start buffering beyond the initial load.
  EXPECT_FALSE(data_source_->cancel_on_defer_for_testing());
  data_source_->OnMediaIsPlaying();
  data_source_->OnBufferingHaveEnough(false);
  CheckCapacityDefer();
  ASSERT_TRUE(active_loader());

  // Read a bit from the beginning and ensure deferral hasn't happened yet.
  EXPECT_CALL(*this, ReadCallback(kDataSize));
  EXPECT_CALL(host_, AddBufferedByteRange(0, kDataSize * 2));
  ReceiveData(kDataSize);
  ASSERT_TRUE(active_loader());
  data_source_->OnBufferingHaveEnough(true);
  EXPECT_TRUE(data_source_->cancel_on_defer_for_testing());
  ASSERT_TRUE(active_loader());
  ASSERT_FALSE(data_provider()->deferred());

  // Deliver data until capacity is reached and verify deferral.
  int bytes_received = 0;
  EXPECT_CALL(host_, AddBufferedByteRange(_, _)).Times(testing::AtLeast(1));
  while (active_loader_allownull() && !data_provider()->deferred()) {
    ReceiveData(kDataSize);
    bytes_received += kDataSize;
  }
  EXPECT_GT(bytes_received, 0);
  EXPECT_LT(bytes_received + kDataSize, kFileSize);
  EXPECT_FALSE(active_loader_allownull());

  // Verify playback resumes correctly too.
  data_source_->OnMediaIsPlaying();
  EXPECT_FALSE(data_source_->cancel_on_defer_for_testing());

  // A read from a previously buffered range won't create a new loader yet.
  EXPECT_CALL(*this, ReadCallback(kDataSize));
  ReadAt(kDataSize);
  EXPECT_FALSE(active_loader_allownull());

  // Reads from an unbuffered range will though...
  EXPECT_CALL(*this, ReadCallback(kDataSize));
  ReadAt(kFarReadPosition);

  // Receive enough data to exhaust current capacity which would destroy the
  // loader upon deferral if the flag hasn't been cleared properly.
  for (int i = 0; i <= (preload_high() / kDataSize) + 1; ++i) {
    ReceiveData(kDataSize);
    ASSERT_TRUE(active_loader());
  }
}

// This test triggers an edge case where request destination is not
// properly set to "audio" (crbug.com/12345). The edge case is triggered when
// preload omitted or is set to metadata, and a read from an unbuffered range
// takes place.
TEST_F(MultiBufferDataSourceTest,
       ExternalResource_Response206_CheckIsClientAudioElement) {
  set_preload(MultiBufferDataSource::METADATA);
  set_is_client_audio_element(true);
  InitializeWith206Response();
  EXPECT_EQ(MultiBufferDataSource::METADATA, preload());
  EXPECT_FALSE(is_local_source());
  EXPECT_TRUE(is_client_audio_element());
  EXPECT_TRUE(data_source_->range_supported());
  CheckReadThenDefer();

  // Reset the reader on defer. As a result, during the next unbuffered range
  // read, a locked resource loader will be created.
  data_source_->OnBufferingHaveEnough(true);

  // Deliver data until capacity is reached and verify deferral.
  int bytes_received = 0;
  EXPECT_CALL(host_, AddBufferedByteRange(_, _)).Times(testing::AtLeast(1));
  while (active_loader_allownull() && !data_provider()->deferred()) {
    ReceiveData(kDataSize);
    bytes_received += kDataSize;
  }
  EXPECT_GT(bytes_received, 0);
  EXPECT_LT(bytes_received + kDataSize, kFileSize);
  EXPECT_FALSE(active_loader_allownull());

  // Read from an unbuffered range will create a new resource loader.
  ReadAt(kFarReadPosition);
  EXPECT_CALL(*this, ReadCallback(kDataSize));
  EXPECT_CALL(host_, AddBufferedByteRange(kFarReadPosition,
                                          kFarReadPosition + kDataSize));
  EXPECT_TRUE(is_client_audio_element());
  Respond(response_generator_->Generate206(kFarReadPosition));
  ReceiveData(kDataSize);

  Stop();
}

TEST_F(MultiBufferDataSourceTest, SeekPastEOF) {
  KURL url(kHttpUrl);
  media_log_ = std::make_unique<NiceMock<media::MockMediaLog>>();
  data_source_ = std::make_unique<MockMultiBufferDataSource>(
      task_runner_,
      url_index_.GetByUrl(url, UrlData::CORS_UNSPECIFIED, UrlData::kNormal),
      media_log_.get(), &host_);
  data_source_->SetPreload(preload_);

  response_generator_ =
      std::make_unique<TestResponseGenerator>(url, kDataSize + 1);
  EXPECT_CALL(*this, OnInitialize(true));
  data_source_->Initialize(base::BindOnce(
      &MultiBufferDataSourceTest::OnInitialize, base::Unretained(this)));
  base::RunLoop().RunUntilIdle();

  // Not really loading until after OnInitialize is called.
  EXPECT_EQ(data_source_->downloading(), false);

  EXPECT_CALL(host_, SetTotalBytes(response_generator_->content_length()));
  Respond(response_generator_->Generate206(0));
  EXPECT_CALL(host_, AddBufferedByteRange(0, kDataSize));
  ReceiveData(kDataSize);

  // Read a bit from the beginning.
  EXPECT_CALL(*this, ReadCallback(kDataSize));
  ReadAt(0);

  EXPECT_CALL(host_, AddBufferedByteRange(kDataSize, kDataSize + 1));
  ReceiveData(1);
  EXPECT_CALL(host_, AddBufferedByteRange(0, kDataSize * 3));
  FinishLoading();
  EXPECT_CALL(*this, ReadCallback(0));

  ReadAt(kDataSize + 5, kDataSize * 2);
  Stop();
}

TEST_F(MultiBufferDataSourceTest, Http_RetryThenRedirect) {
  InitializeWith206Response();

  // Read to advance our position.
  EXPECT_CALL(*this, ReadCallback(kDataSize));
  ReadAt(0);

  // Issue a pending read but trigger an error to force a retry.
  EXPECT_CALL(*this, ReadCallback(kDataSize - 10));
  ReadAt(kDataSize + 10, kDataSize - 10);
  base::RunLoop run_loop;
  data_provider()->DidFail(response_generator_->GenerateError());
  data_provider()->RunOnStart(run_loop.QuitClosure());
  run_loop.Run();

  // Server responds with a redirect.
  WebURL url{KURL(kHttpDifferentPathUrl)};
  WebURLResponse response((KURL(kHttpUrl)));
  response.SetHttpStatusCode(307);
  data_provider()->WillFollowRedirect(url, response);

  EXPECT_CALL(host_, AddBufferedByteRange(0, kDataSize * 2));
  Respond(response_generator_->Generate206(kDataSize));
  ReceiveData(kDataSize);

  FinishLoading();
  EXPECT_FALSE(loading());
  Stop();
}

TEST_F(MultiBufferDataSourceTest, Http_NotStreamingAfterRedirect) {
  Initialize(kHttpUrl, true);

  // Server responds with a redirect.
  WebURL url{KURL(kHttpDifferentPathUrl)};
  WebURLResponse response((KURL(kHttpUrl)));
  response.SetHttpStatusCode(307);
  data_provider()->WillFollowRedirect(url, response);

  EXPECT_CALL(host_, SetTotalBytes(response_generator_->content_length()));
  Respond(response_generator_->Generate206(0));

  EXPECT_CALL(host_, AddBufferedByteRange(0, kDataSize));
  ReceiveData(kDataSize);

  EXPECT_FALSE(data_source_->IsStreaming());

  FinishLoading();
  EXPECT_FALSE(loading());
  Stop();
}

TEST_F(MultiBufferDataSourceTest, Http_RangeNotSatisfiableAfterRedirect) {
  Initialize(kHttpUrl, true);

  // Server responds with a redirect.
  WebURL url{KURL(kHttpDifferentPathUrl)};
  WebURLResponse response((KURL(kHttpUrl)));
  response.SetHttpStatusCode(307);
  data_provider()->WillFollowRedirect(url, response);

  EXPECT_CALL(host_, AddBufferedByteRange(0, kDataSize));
  Respond(response_generator_->GenerateResponse(416));
  Stop();
}

TEST_F(MultiBufferDataSourceTest, Http_404AfterRedirect) {
  Initialize(kHttpUrl, false);

  // Server responds with a redirect.
  WebURL url{KURL(kHttpDifferentPathUrl)};
  WebURLResponse response((KURL(kHttpUrl)));
  response.SetHttpStatusCode(307);
  data_provider()->WillFollowRedirect(url, response);

  Respond(response_generator_->Generate404());
  Stop();
}

TEST_F(MultiBufferDataSourceTest, PreserveCachingModeAfterRedirect) {
  KURL start("https://start.com");
  KURL redir("https://redir.com");
  media_log_ = std::make_unique<NiceMock<media::MockMediaLog>>();
  WebURL url{redir};
  WebURLResponse redirect_response(start);
  redirect_response.SetHttpStatusCode(307);
  WebURLResponse data_response(redir);
  data_response.SetHttpStatusCode(200);
  data_response.SetExpectedContentLength(kDataSize);
  data_response.SetHttpHeaderField(WebString::FromUTF8("Accept-Ranges"),
                                   WebString::FromUTF8("bytes"));

  // Create a data source for a url which redirects. This will create a new
  // UrlData that bypasses any cache lookups (but can still be added to the
  // cache). This will create a new UrlData object with the bypass flag set.
  // The redirection will create another UrlData object with the new url, which
  // will also be in bypass mode.
  {
    EXPECT_CALL(url_index_,
                NotifyNewUrlData(start, _, UrlData::kCacheDisabled));
    auto data_source = std::make_unique<MockMultiBufferDataSource>(
        task_runner_,
        url_index_.GetByUrl(start, UrlData::CORS_UNSPECIFIED,
                            UrlData::kCacheDisabled),
        media_log_.get(), &host_);
    data_source->SetPreload(preload_);
    auto response_generator =
        std::make_unique<TestResponseGenerator>(start, kFileSize);
    data_source->SetIsClientAudioElement(false);
    EXPECT_CALL(*this, OnInitialize(true));
    data_source->Initialize(base::BindOnce(
        &MultiBufferDataSourceTest::OnInitialize, base::Unretained(this)));
    base::RunLoop().RunUntilIdle();
    EXPECT_EQ(data_source->downloading(), false);
    EXPECT_CALL(url_index_,
                NotifyNewUrlData(redir, _, UrlData::kCacheDisabled));
    data_provider()->WillFollowRedirect(url, redirect_response);
    EXPECT_CALL(host_, AddBufferedByteRange(0, _));
    EXPECT_CALL(host_, SetTotalBytes(kDataSize));
    Respond(data_response);
    ReceiveData(kDataSize);
    base::RunLoop().RunUntilIdle();
  }

  // Make another data source for the same URL, but this time, make it in normal
  // cache mode. This will still create a new UrlData for the initial URL
  // because the redirect was temporary (307). The redirect will NOT create a
  // new UrlData however, because that one is cached, as the previous response
  // was a 200.
  {
    EXPECT_CALL(url_index_, NotifyNewUrlData(start, _, UrlData::kNormal));
    auto data_source = std::make_unique<MockMultiBufferDataSource>(
        task_runner_,
        url_index_.GetByUrl(start, UrlData::CORS_UNSPECIFIED, UrlData::kNormal),
        media_log_.get(), &host_);
    data_source->SetPreload(preload_);
    auto response_generator =
        std::make_unique<TestResponseGenerator>(start, kFileSize);
    data_source->SetIsClientAudioElement(false);
    EXPECT_CALL(*this, OnInitialize(true));
    data_source->Initialize(base::BindOnce(
        &MultiBufferDataSourceTest::OnInitialize, base::Unretained(this)));
    base::RunLoop().RunUntilIdle();
    EXPECT_EQ(data_source->downloading(), false);
    EXPECT_CALL(url_index_, NotifyNewUrlData(redir, _, _)).Times(0);
    data_provider()->WillFollowRedirect(url, redirect_response);
    EXPECT_CALL(host_, AddBufferedByteRange(0, _)).Times(testing::AtLeast(1));
    EXPECT_CALL(host_, SetTotalBytes(kDataSize));
    Respond(data_response);
    ReceiveData(kDataSize);
    base::RunLoop().RunUntilIdle();
  }

  // Make another data source for the same URL, but again in bypass cache lookup
  // mode. This will create another UrlData object for the first URL, but then
  // will bypass the cached data and create another new UrlData object for the
  // redirection url.
  {
    EXPECT_CALL(url_index_,
                NotifyNewUrlData(start, _, UrlData::kCacheDisabled));
    auto data_source = std::make_unique<MockMultiBufferDataSource>(
        task_runner_,
        url_index_.GetByUrl(start, UrlData::CORS_UNSPECIFIED,
                            UrlData::kCacheDisabled),
        media_log_.get(), &host_);
    data_source->SetPreload(preload_);
    auto response_generator =
        std::make_unique<TestResponseGenerator>(start, kFileSize);
    data_source->SetIsClientAudioElement(false);
    EXPECT_CALL(*this, OnInitialize(true));
    data_source->Initialize(base::BindOnce(
        &MultiBufferDataSourceTest::OnInitialize, base::Unretained(this)));
    base::RunLoop().RunUntilIdle();
    EXPECT_EQ(data_source->downloading(), false);
    EXPECT_CALL(url_index_,
                NotifyNewUrlData(redir, _, UrlData::kCacheDisabled));
    data_provider()->WillFollowRedirect(url, redirect_response);
    EXPECT_CALL(host_, AddBufferedByteRange(0, _));
    EXPECT_CALL(host_, SetTotalBytes(kDataSize));
    Respond(data_response);
    ReceiveData(kDataSize);
    base::RunLoop().RunUntilIdle();
  }
}

TEST_F(MultiBufferDataSourceTest, LengthKnownAtEOF) {
  Initialize(kHttpUrl, true);
  // Server responds without content-length.
  WebURLResponse response = response_generator_->Generate200();
  response.ClearHttpHeaderField(WebString::FromUTF8("Content-Length"));
  response.SetExpectedContentLength(kPositionNotSpecified);
  Respond(response);
  EXPECT_CALL(host_, AddBufferedByteRange(0, kDataSize));
  ReceiveData(kDataSize);
  int64_t len;
  EXPECT_FALSE(data_source_->GetSize(&len));
  EXPECT_TRUE(data_source_->IsStreaming());
  EXPECT_CALL(*this, ReadCallback(kDataSize));
  ReadAt(0);

  ReadAt(kDataSize);
  EXPECT_CALL(host_, SetTotalBytes(kDataSize));
  EXPECT_CALL(*this, ReadCallback(0));
  EXPECT_CALL(host_, AddBufferedByteRange(0, kDataSize * 2));
  FinishLoading();

  // Done loading, now we should know the length.
  EXPECT_TRUE(data_source_->GetSize(&len));
  EXPECT_EQ(kDataSize, len);
  Stop();
}

TEST_F(MultiBufferDataSourceTest, FileSizeLessThanBlockSize) {
  Initialize(kHttpUrl, true);
  KURL url(kHttpUrl);
  WebURLResponse response(url);
  response.SetHttpStatusCode(200);
  response.SetHttpHeaderField(
      WebString::FromUTF8("Content-Length"),
      WebString::FromUTF8(base::NumberToString(kDataSize / 2)));
  response.SetExpectedContentLength(kDataSize / 2);
  Respond(response);
  EXPECT_CALL(host_, AddBufferedByteRange(0, kDataSize / 2));
  EXPECT_CALL(host_, SetTotalBytes(kDataSize / 2));
  EXPECT_CALL(host_, AddBufferedByteRange(0, kDataSize * 2));
  ReceiveData(kDataSize / 2);
  FinishLoading();

  int64_t len = 0;
  EXPECT_TRUE(data_source_->GetSize(&len));
  EXPECT_EQ(kDataSize / 2, len);
  Stop();
}

TEST_F(MultiBufferDataSourceTest, ResponseTypeBasic) {
  InitializeWithCors(kHttpUrl, true, UrlData::CORS_ANONYMOUS);
  set_preload(MultiBufferDataSource::NONE);
  WebURLResponse response1 =
      response_generator_->GeneratePartial206(0, kDataSize - 1);
  response1.SetType(network::mojom::FetchResponseType::kBasic);

  EXPECT_CALL(host_, SetTotalBytes(kFileSize));
  EXPECT_CALL(host_, AddBufferedByteRange(0, kDataSize));
  EXPECT_CALL(*this, ReadCallback(kDataSize));

  Respond(response1);
  ReceiveData(kDataSize);
  ReadAt(0);
  EXPECT_TRUE(loading());
  EXPECT_FALSE(data_source_->IsCorsCrossOrigin());

  FinishLoading();
}

TEST_F(MultiBufferDataSourceTest, ResponseTypeCors) {
  InitializeWithCors(kHttpUrl, true, UrlData::CORS_ANONYMOUS);
  set_preload(MultiBufferDataSource::NONE);
  WebURLResponse response1 =
      response_generator_->GeneratePartial206(0, kDataSize - 1);
  response1.SetType(network::mojom::FetchResponseType::kCors);

  EXPECT_CALL(host_, SetTotalBytes(kFileSize));
  EXPECT_CALL(host_, AddBufferedByteRange(0, kDataSize));
  EXPECT_CALL(*this, ReadCallback(kDataSize));

  Respond(response1);
  ReceiveData(kDataSize);
  ReadAt(0);
  EXPECT_TRUE(loading());
  EXPECT_FALSE(data_source_->IsCorsCrossOrigin());

  FinishLoading();
}

TEST_F(MultiBufferDataSourceTest, ResponseTypeDefault) {
  InitializeWithCors(kHttpUrl, true, UrlData::CORS_ANONYMOUS);
  set_preload(MultiBufferDataSource::NONE);
  WebURLResponse response1 =
      response_generator_->GeneratePartial206(0, kDataSize - 1);
  response1.SetType(network::mojom::FetchResponseType::kDefault);

  EXPECT_CALL(host_, SetTotalBytes(kFileSize));
  EXPECT_CALL(host_, AddBufferedByteRange(0, kDataSize));
  EXPECT_CALL(*this, ReadCallback(kDataSize));

  Respond(response1);
  ReceiveData(kDataSize);
  ReadAt(0);
  EXPECT_TRUE(loading());
  EXPECT_FALSE(data_source_->IsCorsCrossOrigin());

  FinishLoading();
}

TEST_F(MultiBufferDataSourceTest, ResponseTypeOpaque) {
  InitializeWithCors(kHttpUrl, true, UrlData::CORS_ANONYMOUS);
  set_preload(MultiBufferDataSource::NONE);
  WebURLResponse response1 =
      response_generator_->GeneratePartial206(0, kDataSize - 1);
  response1.SetType(network::mojom::FetchResponseType::kOpaque);

  EXPECT_CALL(host_, SetTotalBytes(kFileSize));
  EXPECT_CALL(host_, AddBufferedByteRange(0, kDataSize));
  EXPECT_CALL(*this, ReadCallback(kDataSize));

  Respond(response1);
  ReceiveData(kDataSize);
  ReadAt(0);
  EXPECT_TRUE(loading());
  EXPECT_TRUE(data_source_->IsCorsCrossOrigin());

  FinishLoading();
}

TEST_F(MultiBufferDataSourceTest, ResponseTypeOpaqueRedirect) {
  InitializeWithCors(kHttpUrl, true, UrlData::CORS_ANONYMOUS);
  set_preload(MultiBufferDataSource::NONE);
  WebURLResponse response1 =
      response_generator_->GeneratePartial206(0, kDataSize - 1);
  response1.SetType(network::mojom::FetchResponseType::kOpaqueRedirect);

  EXPECT_CALL(host_, SetTotalBytes(kFileSize));
  EXPECT_CALL(host_, AddBufferedByteRange(0, kDataSize));
  EXPECT_CALL(*this, ReadCallback(kDataSize));

  Respond(response1);
  ReceiveData(kDataSize);
  ReadAt(0);
  EXPECT_TRUE(loading());
  EXPECT_TRUE(data_source_->IsCorsCrossOrigin());

  FinishLoading();
}

TEST_F(MultiBufferDataSourceTest, EtagTest) {
  Initialize(kHttpUrl, true);

  EXPECT_CALL(host_, SetTotalBytes(response_generator_->content_length()));
  WebURLResponse response = response_generator_->Generate206(0);
  const std::string etag("\"arglebargle glop-glyf?\"");
  response.SetHttpHeaderField(WebString::FromUTF8("Etag"),
                              WebString::FromUTF8(etag));
  Respond(response);
  EXPECT_CALL(host_, AddBufferedByteRange(0, kDataSize));
  ReceiveData(kDataSize);

  EXPECT_EQ(url_data()->etag(), etag);
}

TEST_F(MultiBufferDataSourceTest, CheckBufferSizes) {
  InitializeWith206Response(1 << 30);  // 1 gb

  data_source_->SetBitrate(1 << 20);  // 1 mbit / s
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(1 << 20, data_source_bitrate());
  EXPECT_EQ(2 << 20, preload_low());
  EXPECT_EQ(3 << 20, preload_high());
  EXPECT_EQ(25 << 20, max_buffer_forward());
  EXPECT_EQ(2 << 20, max_buffer_backward());
  EXPECT_EQ(1572864 /* 1.5Mb */, buffer_size());

  data_source_->SetBitrate(8 << 20);  // 8 mbit / s
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(8 << 20, data_source_bitrate());
  EXPECT_EQ(10 << 20, preload_low());
  EXPECT_EQ(11 << 20, preload_high());
  EXPECT_EQ(25 << 20, max_buffer_forward());
  EXPECT_EQ(2 << 20, max_buffer_backward());
  EXPECT_EQ(12 << 20, buffer_size());

  data_source_->SetBitrate(16 << 20);  // 16 mbit / s
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(16 << 20, data_source_bitrate());
  EXPECT_EQ(20 << 20, preload_low());
  EXPECT_EQ(21 << 20, preload_high());
  EXPECT_EQ(25 << 20, max_buffer_forward());
  EXPECT_EQ(4 << 20, max_buffer_backward());
  EXPECT_EQ(24 << 20, buffer_size());

  data_source_->SetBitrate(32 << 20);  // 32 mbit / s
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(32 << 20, data_source_bitrate());
  EXPECT_EQ(40 << 20, preload_low());
  EXPECT_EQ(41 << 20, preload_high());
  EXPECT_EQ(41 << 20, max_buffer_forward());
  EXPECT_EQ(8 << 20, max_buffer_backward());
  EXPECT_EQ(48 << 20, buffer_size());

  data_source_->SetBitrate(80 << 20);  // 80 mbit / s
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(80 << 20, data_source_bitrate());
  EXPECT_EQ(50 << 20, preload_low());
  EXPECT_EQ(51 << 20, preload_high());
  EXPECT_EQ(51 << 20, max_buffer_forward());
  EXPECT_EQ(20 << 20, max_buffer_backward());
  EXPECT_EQ(71 << 20, buffer_size());
}

TEST_F(MultiBufferDataSourceTest, CheckBufferSizeForSmallFiles) {
  InitializeWith206Response();

  data_source_->SetBitrate(1 << 20);  // 1 mbit / s
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(1 << 20, data_source_bitrate());
  EXPECT_EQ(2 << 20, preload_low());
  EXPECT_EQ(3 << 20, preload_high());
  EXPECT_EQ(25 << 20, max_buffer_forward());
  EXPECT_EQ(kFileSize * 2, max_buffer_backward());
  EXPECT_EQ(5013504 /* file size rounded up to blocks size */, buffer_size());

  data_source_->SetBitrate(80 << 20);  // 80 mbit / s
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(80 << 20, data_source_bitrate());
  EXPECT_EQ(50 << 20, preload_low());
  EXPECT_EQ(51 << 20, preload_high());
  EXPECT_EQ(51 << 20, max_buffer_forward());
  EXPECT_EQ(20 << 20, max_buffer_backward());
  EXPECT_EQ(5013504 /* file size rounded up to blocks size */, buffer_size());
}

TEST_F(MultiBufferDataSourceTest, CheckBufferSizeAfterReadingALot) {
  In
"""


```