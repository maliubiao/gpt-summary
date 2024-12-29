Response:
Let's break down the thought process for analyzing this C++ code and generating the detailed explanation.

**1. Understanding the Core Purpose:**

The first step is to quickly read the code and its comments to grasp the central theme. The class name `SharedDictionaryNetworkTransaction` immediately suggests it's involved in handling network transactions and shared dictionaries. The copyright notice and `#include` statements confirm it's part of the Chromium project's network stack.

**2. Identifying Key Functionality:**

Next, I'd scan the public methods to identify the main actions the class performs. Methods like `Start`, `Read`, `Restart...`, `GetResponseInfo`, and `ModifyRequestHeaders` stand out. This gives a high-level overview of the class's role in managing network requests.

**3. Deeper Dive into `Start`:**

The `Start` method is crucial as it initiates the transaction. The logic involving `LOAD_CAN_USE_SHARED_DICTIONARY` and `request->dictionary_getter` is key. This indicates a conditional behavior based on whether shared dictionaries are enabled for the request. The calls to `SetModifyRequestHeadersCallback` and the subsequent `OnStartCompleted` suggest a two-stage initialization process.

**4. Analyzing `ModifyRequestHeaders`:**

This method is where the shared dictionary magic happens. The logic around fetching the dictionary (using `shared_dictionary_getter_`), checking protocol and certificate requirements, adding the `Available-Dictionary` header, and potentially reading the dictionary into memory (`shared_dictionary_->ReadAll`) are central to its functionality. The various `if` conditions based on feature flags are important to note.

**5. Examining the `Read` Method:**

The `Read` method handles fetching the response body. The conditional logic based on `shared_dictionary_used_response_info_` and `dictionary_status_` is crucial. The instantiation of `SharedDictionaryHeaderCheckerSourceStream` and either `BrotliSourceStreamWithDictionary` or `ZstdSourceStreamWithDictionary` is the core of the decompression process.

**6. Tracing the Data Flow:**

I'd mentally trace how data flows through the class. The `HttpRequestInfo` comes in, the dictionary is fetched, headers are modified, the network transaction starts, the response headers are examined, and finally, the potentially decompressed response body is read.

**7. Identifying Relationships and Dependencies:**

The `#include` statements reveal the class's dependencies. Key dependencies include:

* `HttpTransaction`: The underlying network transaction mechanism.
* `SharedDictionary...`: Classes related to shared dictionary management.
* `SourceStream` and its implementations (`BrotliSourceStream`, `ZstdSourceStream`):  For handling compressed data.
* `HttpRequestHeaders`, `HttpResponseHeaders`: For manipulating HTTP headers.
* `base` library components: For utilities like callbacks, strings, and feature flags.

**8. Addressing Specific Requirements of the Prompt:**

Now that I have a good understanding of the code, I'd address each part of the prompt systematically:

* **Functionality:** Summarize the core tasks identified earlier.
* **Relationship with JavaScript:** Think about how shared dictionaries might be exposed to or used by JavaScript. The `fetch` API and browser-level compression hints are relevant points.
* **Logical Reasoning (Input/Output):**  Construct simple scenarios to illustrate the conditional behavior in `Start` and `Read`. Focus on the presence or absence of shared dictionaries and the resulting actions.
* **User/Programming Errors:** Consider common mistakes related to configuring shared dictionaries, such as incorrect headers, missing dictionaries, or feature flag issues.
* **User Operation Trace (Debugging):**  Outline the steps a user might take that would lead to this code being executed. Starting with a network request and focusing on scenarios where shared dictionaries are involved is crucial.

**9. Structuring the Output:**

Finally, organize the information in a clear and logical manner, using headings and bullet points to improve readability. Provide concrete examples and explanations for each point. Use the code snippets and comments to support the analysis.

**Self-Correction/Refinement during the Process:**

* **Initial thought:**  Perhaps focus heavily on low-level details of compression.
* **Correction:** Realize the primary role of this class is *managing* the shared dictionary aspect of the transaction, not the core compression algorithms themselves. The decompression is delegated to the `SourceStream` implementations.
* **Initial thought:**  Maybe overcomplicate the JavaScript interaction.
* **Correction:** Focus on the general concepts of how browsers can use shared dictionaries, rather than diving into specific low-level APIs (which might not directly involve this C++ class).
* **Initial thought:**  Not explicitly link user actions to the code execution.
* **Correction:**  Add a section explaining how user actions trigger network requests that might involve shared dictionaries, providing a clearer debugging path.

By following these steps, I can systematically analyze the provided C++ code and generate a comprehensive and accurate explanation that addresses all aspects of the prompt. The key is to start with a high-level understanding and gradually delve into the details, while always keeping the overall purpose of the class in mind.
This C++ source code file, `shared_dictionary_network_transaction.cc`, within the Chromium network stack implements a network transaction specifically designed to handle **shared dictionaries** for content compression. Let's break down its functionalities:

**Core Functionality:**

1. **Wraps a Regular Network Transaction:** It acts as a wrapper around a standard `HttpTransaction`. This means it intercepts and potentially modifies the behavior of a regular network request when shared dictionaries are involved.

2. **Checks for Shared Dictionary Usage:** It examines the `HttpRequestInfo` to determine if the current request is eligible to use shared dictionaries. This is controlled by the `LOAD_CAN_USE_SHARED_DICTIONARY` flag and the presence of a `dictionary_getter` function.

3. **Fetches Shared Dictionaries:** If eligible, it uses the provided `dictionary_getter` (a callback function) to retrieve the relevant shared dictionary based on the request's isolation key and URL.

4. **Modifies Request Headers:**
   - Adds the `Available-Dictionary` header to the request, indicating the hash of the available shared dictionary. This allows the server to know if a suitable dictionary is available on the client-side.
   - Adds `Accept-Encoding` headers to signal support for `shared-brotli` and optionally `shared-zstd` content encodings.

5. **Handles Server Responses with Shared Dictionaries:**
   - Checks the `Content-Encoding` header of the response. If it matches `shared-brotli` or `shared-zstd`, it knows the response body is compressed using a shared dictionary.
   - Creates a specialized `SourceStream` (either `BrotliSourceStreamWithDictionary` or `ZstdSourceStreamWithDictionary`) to decompress the response body using the fetched shared dictionary.

6. **Manages Dictionary Loading:**
   - It handles the asynchronous loading of the shared dictionary data into memory.
   - While the dictionary is loading, subsequent `Read` calls will be held pending.

7. **Provides Transparency:** For requests that don't use shared dictionaries, it largely passes through calls to the underlying `HttpTransaction`.

8. **Metrics and Logging:** It uses histograms (`UMA_HISTOGRAM_...`) to track the usage and performance of shared dictionaries.

**Relationship with JavaScript Functionality:**

This C++ code is part of the browser's underlying network stack and is **not directly interacted with by JavaScript code**. However, its functionality directly impacts how web content is fetched and processed, which is indirectly observable by JavaScript.

* **`fetch` API and Compression:** When a JavaScript application uses the `fetch` API to make a request, the browser's network stack (including this code) handles the actual HTTP transaction. If the server responds with content encoded using a shared dictionary, this code will decompress it before the response body is made available to the JavaScript code. The JavaScript will receive the decompressed data as if no shared dictionary was involved.

* **Example:**

   ```javascript
   fetch('https://example.com/resource.txt')
     .then(response => response.text())
     .then(data => console.log(data));
   ```

   In this scenario, if `https://example.com/resource.txt` is served with `Content-Encoding: shared-brotli` and a shared dictionary was successfully used, the `SharedDictionaryNetworkTransaction` would handle the decompression in the background. The `response.text()` method in the JavaScript code would then return the *decompressed* text content. The JavaScript code is unaware of the underlying shared dictionary mechanism.

**Logical Reasoning (Hypothetical Input and Output):**

**Scenario 1: Shared Dictionary Available and Used**

* **Input (Hypothetical):**
    - `HttpRequestInfo`: `load_flags` include `LOAD_CAN_USE_SHARED_DICTIONARY`, `dictionary_getter` is provided, request URL is `https://example.com/page.html`.
    - `dictionary_getter` successfully returns a `SharedDictionary` object with hash "ABCDEF123".
    - Server responds with `Content-Encoding: shared-brotli`.
* **Output:**
    - Request headers sent to the server include: `Available-Dictionary: :ABCDEF123:` and `Accept-Encoding: shared-brotli`.
    - The response body is decompressed using the provided shared dictionary.
    - The `GetResponseInfo()` will indicate `did_use_shared_dictionary = true`.
    - `Read()` calls will return the decompressed content.

**Scenario 2: Shared Dictionary Available but Not Used (Server Doesn't Support)**

* **Input (Hypothetical):**
    - Same `HttpRequestInfo` as above.
    - `dictionary_getter` successfully returns a `SharedDictionary` object.
    - Server responds with `Content-Encoding: br` (standard Brotli) or no `Content-Encoding`.
* **Output:**
    - Request headers sent to the server include: `Available-Dictionary: :ABCDEF123:` and `Accept-Encoding: shared-brotli`.
    - The `Content-Encoding` check in `OnStartCompleted` will fail.
    - The underlying `HttpTransaction` will handle the response as a normal compressed or uncompressed response.
    - `GetResponseInfo()` will indicate `did_use_shared_dictionary = false`.

**Scenario 3: Shared Dictionary Not Available**

* **Input (Hypothetical):**
    - `HttpRequestInfo`: `load_flags` include `LOAD_CAN_USE_SHARED_DICTIONARY`, `dictionary_getter` is provided.
    - `dictionary_getter` returns nullopt (no dictionary found).
* **Output:**
    - The code will bypass the shared dictionary logic in `Start`.
    - The request will proceed as a normal HTTP request without the `Available-Dictionary` header.
    - `GetResponseInfo()` will indicate `did_use_shared_dictionary = false`.

**User or Programming Common Usage Errors:**

1. **Incorrect Server Configuration:** The server needs to be configured to:
   - Store and serve shared dictionaries.
   - Recognize the `Available-Dictionary` header.
   - Respond with `Content-Encoding: shared-brotli` or `shared-zstd` when using a shared dictionary.
   - **Example Error:** If the server sends `Content-Encoding: gzip` even though the client sent an `Available-Dictionary` header, the client will not attempt to use the shared dictionary for decompression.

2. **Missing or Incorrect Dictionary Data:** If the `dictionary_getter` fails to retrieve a valid shared dictionary, or if the dictionary data is corrupted, decompression will fail.
   - **Example Error:**  A website might incorrectly configure the dictionary URLs or the logic for serving dictionaries based on isolation keys.

3. **Feature Flags Disabled:** The functionality of shared dictionaries is often controlled by feature flags in Chromium. If the necessary flags are disabled, this code will not be executed.
   - **Example Error:** A developer might be testing with a Chromium build where the `kCompressionDictionaryTransport` feature is disabled.

4. **Incorrect `LOAD_FLAGS`:** If the request is initiated without the `LOAD_CAN_USE_SHARED_DICTIONARY` flag, the shared dictionary logic will be skipped.
   - **Example Error:**  A component initiating a network request might not be aware of or correctly set the load flags to enable shared dictionary usage.

**User Operation Steps to Reach This Code (Debugging Clues):**

1. **User navigates to a website or performs an action that triggers a network request:** This is the initial step for any network transaction.

2. **The browser checks if shared dictionaries can be used for this request:** This involves checking:
   - Feature flags related to shared dictionaries.
   - The presence of a suitable shared dictionary in the browser's cache or storage, based on the request's origin and other isolation parameters.

3. **The `HttpRequestInfo` for the request is created, potentially with `LOAD_CAN_USE_SHARED_DICTIONARY` set:** This flag is a key indicator that shared dictionaries are intended to be used. The `dictionary_getter` callback will also be set.

4. **A `SharedDictionaryNetworkTransaction` is instantiated:** If the conditions in step 2 are met, this specific type of network transaction will be created to handle the request.

5. **The `Start()` method of `SharedDictionaryNetworkTransaction` is called:** This initiates the shared dictionary specific logic.

6. **The `dictionary_getter` callback is executed:** This attempts to retrieve the relevant shared dictionary.

7. **The `ModifyRequestHeaders()` method is called:**  If a dictionary is found, the `Available-Dictionary` and `Accept-Encoding` headers are added.

8. **The underlying `HttpTransaction` performs the network request:** The modified headers are sent to the server.

9. **The server responds, potentially with `Content-Encoding: shared-brotli` or `shared-zstd`:**

10. **The `OnStartCompleted()` method checks the response headers:** If the content encoding indicates a shared dictionary, the decompression logic is prepared.

11. **The `Read()` method is called to retrieve the response body:** This is where the specialized decompression `SourceStream` is used.

**Debugging Tips:**

* **NetLog:** Chromium's NetLog (`chrome://net-export/`) is invaluable for debugging network issues. It will show the request and response headers, including the `Available-Dictionary` and `Content-Encoding` headers, and any errors related to shared dictionary loading or decompression.
* **Breakpoints:** Setting breakpoints in `SharedDictionaryNetworkTransaction::Start`, `ModifyRequestHeaders`, `OnStartCompleted`, and `Read` can help trace the execution flow and inspect the state of variables.
* **Feature Flags:** Ensure the necessary feature flags related to shared dictionaries are enabled in `chrome://flags/`.
* **Dictionary Storage Inspection:** Investigate how shared dictionaries are stored and managed in the browser's profile. This might involve looking at internal data structures or using specialized debugging tools.

In summary, `shared_dictionary_network_transaction.cc` plays a crucial role in enabling efficient content delivery by leveraging shared dictionaries for compression within the Chromium network stack. It seamlessly integrates with the regular network transaction process, making the use of shared dictionaries largely transparent to higher-level code, including JavaScript.

Prompt: 
```
这是目录为net/shared_dictionary/shared_dictionary_network_transaction.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2023 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/shared_dictionary/shared_dictionary_network_transaction.h"

#include <optional>
#include <string>
#include <string_view>

#include "base/base64.h"
#include "base/feature_list.h"
#include "base/functional/bind.h"
#include "base/functional/callback_helpers.h"
#include "base/metrics/histogram_functions.h"
#include "base/metrics/histogram_macros.h"
#include "base/notreached.h"
#include "base/strings/strcat.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_util.h"
#include "base/types/expected.h"
#include "net/base/completion_once_callback.h"
#include "net/base/features.h"
#include "net/base/hash_value.h"
#include "net/base/io_buffer.h"
#include "net/base/load_flags.h"
#include "net/base/net_errors.h"
#include "net/base/transport_info.h"
#include "net/base/url_util.h"
#include "net/cert/x509_certificate.h"
#include "net/filter/brotli_source_stream.h"
#include "net/filter/filter_source_stream.h"
#include "net/filter/source_stream.h"
#include "net/filter/zstd_source_stream.h"
#include "net/http/http_request_info.h"
#include "net/http/structured_headers.h"
#include "net/shared_dictionary/shared_dictionary_constants.h"
#include "net/shared_dictionary/shared_dictionary_header_checker_source_stream.h"
#include "net/shared_dictionary/shared_dictionary_isolation_key.h"
#include "net/ssl/ssl_private_key.h"

namespace net {

namespace {

// Convert the interface from HttpTransaction to SourceStream.
class ProxyingSourceStream : public SourceStream {
 public:
  explicit ProxyingSourceStream(HttpTransaction* transaction)
      : SourceStream(SourceStream::TYPE_NONE), transaction_(transaction) {}

  ProxyingSourceStream(const ProxyingSourceStream&) = delete;
  ProxyingSourceStream& operator=(const ProxyingSourceStream&) = delete;

  ~ProxyingSourceStream() override = default;

  // SourceStream implementation:
  int Read(IOBuffer* dest_buffer,
           int buffer_size,
           CompletionOnceCallback callback) override {
    DCHECK(transaction_);
    return transaction_->Read(dest_buffer, buffer_size, std::move(callback));
  }

  std::string Description() const override { return std::string(); }

  bool MayHaveMoreBytes() const override { return true; }

 private:
  const raw_ptr<HttpTransaction> transaction_;
};

void AddAcceptEncoding(HttpRequestHeaders* request_headers,
                       std::string_view encoding_header) {
  std::optional<std::string> accept_encoding =
      request_headers->GetHeader(HttpRequestHeaders::kAcceptEncoding);
  request_headers->SetHeader(
      HttpRequestHeaders::kAcceptEncoding,
      accept_encoding ? base::StrCat({*accept_encoding, ", ", encoding_header})
                      : std::string(encoding_header));
}

}  // namespace

SharedDictionaryNetworkTransaction::PendingReadTask::PendingReadTask(
    IOBuffer* buf,
    int buf_len,
    CompletionOnceCallback callback)
    : buf(buf), buf_len(buf_len), callback(std::move(callback)) {}

SharedDictionaryNetworkTransaction::PendingReadTask::~PendingReadTask() =
    default;

SharedDictionaryNetworkTransaction::SharedDictionaryNetworkTransaction(
    std::unique_ptr<HttpTransaction> network_transaction,
    bool enable_shared_zstd)
    : enable_shared_zstd_(enable_shared_zstd),
      network_transaction_(std::move(network_transaction)) {
  network_transaction_->SetConnectedCallback(
      base::BindRepeating(&SharedDictionaryNetworkTransaction::OnConnected,
                          base::Unretained(this)));
}

SharedDictionaryNetworkTransaction::~SharedDictionaryNetworkTransaction() =
    default;

int SharedDictionaryNetworkTransaction::Start(const HttpRequestInfo* request,
                                              CompletionOnceCallback callback,
                                              const NetLogWithSource& net_log) {
  if (!(request->load_flags & LOAD_CAN_USE_SHARED_DICTIONARY) ||
      !request->dictionary_getter) {
    return network_transaction_->Start(request, std::move(callback), net_log);
  }
  std::optional<SharedDictionaryIsolationKey> isolation_key =
      SharedDictionaryIsolationKey::MaybeCreate(request->network_isolation_key,
                                                request->frame_origin);
  shared_dictionary_getter_ = base::BindRepeating(request->dictionary_getter,
                                                   isolation_key, request->url);

  // Safe to bind unretained `this` because the callback is owned by
  // `network_transaction_` which is owned by `this`.
  network_transaction_->SetModifyRequestHeadersCallback(base::BindRepeating(
      &SharedDictionaryNetworkTransaction::ModifyRequestHeaders,
      base::Unretained(this), request->url));
  return network_transaction_->Start(
      request,
      base::BindOnce(&SharedDictionaryNetworkTransaction::OnStartCompleted,
                     base::Unretained(this), std::move(callback)),
      net_log);
}

SharedDictionaryNetworkTransaction::SharedDictionaryEncodingType
SharedDictionaryNetworkTransaction::ParseSharedDictionaryEncodingType(
    const HttpResponseHeaders& headers) {
  std::optional<std::string> content_encoding =
      headers.GetNormalizedHeader("Content-Encoding");
  if (!content_encoding) {
    return SharedDictionaryEncodingType::kNotUsed;
  } else if (content_encoding ==
             shared_dictionary::kSharedBrotliContentEncodingName) {
    return SharedDictionaryEncodingType::kSharedBrotli;
  } else if (enable_shared_zstd_ &&
             content_encoding ==
                 shared_dictionary::kSharedZstdContentEncodingName) {
    return SharedDictionaryEncodingType::kSharedZstd;
  }
  return SharedDictionaryEncodingType::kNotUsed;
}

void SharedDictionaryNetworkTransaction::OnStartCompleted(
    CompletionOnceCallback callback,
    int result) {
  if (shared_dictionary_) {
    base::UmaHistogramSparse(
        base::StrCat({"Net.SharedDictionaryTransaction.NetResultWithDict.",
                      cert_is_issued_by_known_root_
                          ? "KnownRootCert"
                          : "UnknownRootCertOrNoCert"}),
        -result);
  }

  if (result != OK || !shared_dictionary_) {
    std::move(callback).Run(result);
    return;
  }

  shared_dictionary_encoding_type_ = ParseSharedDictionaryEncodingType(
      *network_transaction_->GetResponseInfo()->headers);
  if (shared_dictionary_encoding_type_ ==
      SharedDictionaryEncodingType::kNotUsed) {
    std::move(callback).Run(result);
    return;
  }

  shared_dictionary_used_response_info_ = std::make_unique<HttpResponseInfo>(
      *network_transaction_->GetResponseInfo());
  shared_dictionary_used_response_info_->did_use_shared_dictionary = true;
  std::move(callback).Run(result);
}

void SharedDictionaryNetworkTransaction::ModifyRequestHeaders(
    const GURL& request_url,
    HttpRequestHeaders* request_headers) {
  // `shared_dictionary_` may have been already set if this transaction was
  // restarted
  if (!shared_dictionary_) {
    shared_dictionary_ = shared_dictionary_getter_.Run();
  }
  if (!shared_dictionary_) {
    return;
  }

  if (!IsLocalhost(request_url)) {
    if (!base::FeatureList::IsEnabled(
            features::kCompressionDictionaryTransportOverHttp1) &&
        negotiated_protocol_ != kProtoHTTP2 &&
        negotiated_protocol_ != kProtoQUIC) {
      shared_dictionary_.reset();
      return;
    }
    if (!base::FeatureList::IsEnabled(
            features::kCompressionDictionaryTransportOverHttp2) &&
        negotiated_protocol_ == kProtoHTTP2) {
      shared_dictionary_.reset();
      return;
    }
  }
  if (base::FeatureList::IsEnabled(
          features::kCompressionDictionaryTransportRequireKnownRootCert) &&
      !cert_is_issued_by_known_root_ && !IsLocalhost(request_url)) {
    shared_dictionary_.reset();
    return;
  }

  // `is_shared_dictionary_read_allowed_callback_` triggers a notification of
  // the shared dictionary usage to the browser process. So we need to call
  // `is_shared_dictionary_read_allowed_callback_` after checking the result
  // of `GetDictionarySync()`.
  CHECK(is_shared_dictionary_read_allowed_callback_);
  if (!is_shared_dictionary_read_allowed_callback_.Run()) {
    shared_dictionary_.reset();
    return;
  }
  dictionary_hash_base64_ = base::StrCat(
      {":", base::Base64Encode(shared_dictionary_->hash().data), ":"});
  request_headers->SetHeader(shared_dictionary::kAvailableDictionaryHeaderName,
                             dictionary_hash_base64_);
  if (enable_shared_zstd_) {
    AddAcceptEncoding(
        request_headers,
        base::StrCat({shared_dictionary::kSharedBrotliContentEncodingName, ", ",
                      shared_dictionary::kSharedZstdContentEncodingName}));
  } else {
    AddAcceptEncoding(request_headers,
                      shared_dictionary::kSharedBrotliContentEncodingName);
  }

  if (!shared_dictionary_->id().empty()) {
    std::optional<std::string> serialized_id =
        structured_headers::SerializeItem(shared_dictionary_->id());
    if (serialized_id) {
      request_headers->SetHeader("Dictionary-ID", *serialized_id);
    }
  }

  if (dictionary_status_ == DictionaryStatus::kNoDictionary) {
    dictionary_status_ = DictionaryStatus::kReading;
    auto split_callback = base::SplitOnceCallback(base::BindOnce(
        [](base::WeakPtr<SharedDictionaryNetworkTransaction> self,
           base::Time read_start_time, int result) {
          if (!self) {
            bool succeeded = result == OK;
            base::UmaHistogramTimes(
                base::StrCat({"Net.SharedDictionaryTransaction."
                              "AbortedWhileReadingDictionary.",
                              succeeded ? "Success" : "Failure"}),
                base::Time::Now() - read_start_time);
            return;
          }
          self->OnReadSharedDictionary(read_start_time, result);
        },
        weak_factory_.GetWeakPtr(), /*read_start_time=*/base::Time::Now()));

    int read_result =
        shared_dictionary_->ReadAll(std::move(split_callback.first));
    if (read_result != ERR_IO_PENDING) {
      std::move(split_callback.second).Run(read_result);
    }
  }
}

void SharedDictionaryNetworkTransaction::OnReadSharedDictionary(
    base::Time read_start_time,
    int result) {
  bool succeeded = result == OK;
  base::UmaHistogramTimes(
      base::StrCat({"Net.SharedDictionaryTransaction.DictionaryReadLatency.",
                    succeeded ? "Success" : "Failure"}),
      base::Time::Now() - read_start_time);
  if (!succeeded) {
    dictionary_status_ = DictionaryStatus::kFailed;
  } else {
    dictionary_status_ = DictionaryStatus::kFinished;
    CHECK(shared_dictionary_->data());
  }
  if (pending_read_task_) {
    auto task = std::move(pending_read_task_);
    auto split_callback = base::SplitOnceCallback(std::move(task->callback));
    int ret =
        Read(task->buf.get(), task->buf_len, std::move(split_callback.first));
    if (ret != ERR_IO_PENDING) {
      std::move(split_callback.second).Run(ret);
    }
  }
}

int SharedDictionaryNetworkTransaction::RestartIgnoringLastError(
    CompletionOnceCallback callback) {
  shared_dictionary_used_response_info_.reset();
  return network_transaction_->RestartIgnoringLastError(
      base::BindOnce(&SharedDictionaryNetworkTransaction::OnStartCompleted,
                     base::Unretained(this), std::move(callback)));
}

int SharedDictionaryNetworkTransaction::RestartWithCertificate(
    scoped_refptr<X509Certificate> client_cert,
    scoped_refptr<SSLPrivateKey> client_private_key,
    CompletionOnceCallback callback) {
  shared_dictionary_used_response_info_.reset();
  return network_transaction_->RestartWithCertificate(
      std::move(client_cert), std::move(client_private_key),
      base::BindOnce(&SharedDictionaryNetworkTransaction::OnStartCompleted,
                     base::Unretained(this), std::move(callback)));
}

int SharedDictionaryNetworkTransaction::RestartWithAuth(
    const AuthCredentials& credentials,
    CompletionOnceCallback callback) {
  shared_dictionary_used_response_info_.reset();
  return network_transaction_->RestartWithAuth(
      credentials,
      base::BindOnce(&SharedDictionaryNetworkTransaction::OnStartCompleted,
                     base::Unretained(this), std::move(callback)));
}

bool SharedDictionaryNetworkTransaction::IsReadyToRestartForAuth() {
  return network_transaction_->IsReadyToRestartForAuth();
}

int SharedDictionaryNetworkTransaction::Read(IOBuffer* buf,
                                             int buf_len,
                                             CompletionOnceCallback callback) {
  if (!shared_dictionary_used_response_info_) {
    return network_transaction_->Read(buf, buf_len, std::move(callback));
  }

  switch (dictionary_status_) {
    case DictionaryStatus::kNoDictionary:
      NOTREACHED();
    case DictionaryStatus::kReading:
      CHECK(!pending_read_task_);
      pending_read_task_ =
          std::make_unique<PendingReadTask>(buf, buf_len, std::move(callback));
      return ERR_IO_PENDING;
    case DictionaryStatus::kFinished:
      if (!shared_compression_stream_) {
        // Wrap the source `network_transaction_` with a
        // SharedDictionaryHeaderCheckerSourceStream to check the header
        // of Dictionary-Compressed stream.
        std::unique_ptr<SourceStream> header_checker_source_stream =
            std::make_unique<SharedDictionaryHeaderCheckerSourceStream>(
                std::make_unique<ProxyingSourceStream>(
                    network_transaction_.get()),
                shared_dictionary_encoding_type_ ==
                        SharedDictionaryEncodingType::kSharedBrotli
                    ? SharedDictionaryHeaderCheckerSourceStream::Type::
                          kDictionaryCompressedBrotli
                    : SharedDictionaryHeaderCheckerSourceStream::Type::
                          kDictionaryCompressedZstd,
                shared_dictionary_->hash());
        if (shared_dictionary_encoding_type_ ==
            SharedDictionaryEncodingType::kSharedBrotli) {
          SCOPED_UMA_HISTOGRAM_TIMER_MICROS(
              "Network.SharedDictionary."
              "CreateBrotliSourceStreamWithDictionary");
          shared_compression_stream_ = CreateBrotliSourceStreamWithDictionary(
              std::move(header_checker_source_stream),
              shared_dictionary_->data(), shared_dictionary_->size());
        } else if (shared_dictionary_encoding_type_ ==
                   SharedDictionaryEncodingType::kSharedZstd) {
          SCOPED_UMA_HISTOGRAM_TIMER_MICROS(
              "Network.SharedDictionary.CreateZstdSourceStreamWithDictionary");
          shared_compression_stream_ = CreateZstdSourceStreamWithDictionary(
              std::move(header_checker_source_stream),
              shared_dictionary_->data(), shared_dictionary_->size());
        }

        UMA_HISTOGRAM_ENUMERATION("Network.SharedDictionary.EncodingType",
                                  shared_dictionary_encoding_type_);
      }
      // When NET_DISABLE_BROTLI or NET_DISABLE_ZSTD is set,
      // `shared_compression_stream_` can be null.
      if (!shared_compression_stream_) {
        return ERR_CONTENT_DECODING_FAILED;
      }
      return shared_compression_stream_->Read(buf, buf_len,
                                              std::move(callback));
    case DictionaryStatus::kFailed:
      return ERR_DICTIONARY_LOAD_FAILED;
  }
}

void SharedDictionaryNetworkTransaction::StopCaching() {
  network_transaction_->StopCaching();
}

int64_t SharedDictionaryNetworkTransaction::GetTotalReceivedBytes() const {
  return network_transaction_->GetTotalReceivedBytes();
}

int64_t SharedDictionaryNetworkTransaction::GetTotalSentBytes() const {
  return network_transaction_->GetTotalSentBytes();
}

int64_t SharedDictionaryNetworkTransaction::GetReceivedBodyBytes() const {
  return network_transaction_->GetReceivedBodyBytes();
}

void SharedDictionaryNetworkTransaction::DoneReading() {
  network_transaction_->DoneReading();
}

const HttpResponseInfo* SharedDictionaryNetworkTransaction::GetResponseInfo()
    const {
  if (shared_dictionary_used_response_info_) {
    return shared_dictionary_used_response_info_.get();
  }
  return network_transaction_->GetResponseInfo();
}

LoadState SharedDictionaryNetworkTransaction::GetLoadState() const {
  return network_transaction_->GetLoadState();
}

void SharedDictionaryNetworkTransaction::SetQuicServerInfo(
    QuicServerInfo* quic_server_info) {
  network_transaction_->SetQuicServerInfo(quic_server_info);
}

bool SharedDictionaryNetworkTransaction::GetLoadTimingInfo(
    LoadTimingInfo* load_timing_info) const {
  return network_transaction_->GetLoadTimingInfo(load_timing_info);
}

bool SharedDictionaryNetworkTransaction::GetRemoteEndpoint(
    IPEndPoint* endpoint) const {
  return network_transaction_->GetRemoteEndpoint(endpoint);
}

void SharedDictionaryNetworkTransaction::PopulateNetErrorDetails(
    NetErrorDetails* details) const {
  return network_transaction_->PopulateNetErrorDetails(details);
}

void SharedDictionaryNetworkTransaction::SetPriority(RequestPriority priority) {
  network_transaction_->SetPriority(priority);
}

void SharedDictionaryNetworkTransaction::
    SetWebSocketHandshakeStreamCreateHelper(
        WebSocketHandshakeStreamBase::CreateHelper* create_helper) {
  network_transaction_->SetWebSocketHandshakeStreamCreateHelper(create_helper);
}

void SharedDictionaryNetworkTransaction::SetBeforeNetworkStartCallback(
    BeforeNetworkStartCallback callback) {
  network_transaction_->SetBeforeNetworkStartCallback(std::move(callback));
}

void SharedDictionaryNetworkTransaction::SetRequestHeadersCallback(
    RequestHeadersCallback callback) {
  network_transaction_->SetRequestHeadersCallback(std::move(callback));
}

void SharedDictionaryNetworkTransaction::SetResponseHeadersCallback(
    ResponseHeadersCallback callback) {
  network_transaction_->SetResponseHeadersCallback(std::move(callback));
}

void SharedDictionaryNetworkTransaction::SetEarlyResponseHeadersCallback(
    ResponseHeadersCallback callback) {
  network_transaction_->SetEarlyResponseHeadersCallback(std::move(callback));
}

void SharedDictionaryNetworkTransaction::SetConnectedCallback(
    const ConnectedCallback& callback) {
  connected_callback_ = callback;
}

int SharedDictionaryNetworkTransaction::ResumeNetworkStart() {
  return network_transaction_->ResumeNetworkStart();
}

void SharedDictionaryNetworkTransaction::SetModifyRequestHeadersCallback(
    base::RepeatingCallback<void(HttpRequestHeaders*)> callback) {
  // This method should not be called for this class.
  NOTREACHED();
}

void SharedDictionaryNetworkTransaction::
    SetIsSharedDictionaryReadAllowedCallback(
        base::RepeatingCallback<bool()> callback) {
  is_shared_dictionary_read_allowed_callback_ = std::move(callback);
}

ConnectionAttempts SharedDictionaryNetworkTransaction::GetConnectionAttempts()
    const {
  return network_transaction_->GetConnectionAttempts();
}

void SharedDictionaryNetworkTransaction::CloseConnectionOnDestruction() {
  network_transaction_->CloseConnectionOnDestruction();
}

bool SharedDictionaryNetworkTransaction::IsMdlMatchForMetrics() const {
  return network_transaction_->IsMdlMatchForMetrics();
}

int SharedDictionaryNetworkTransaction::OnConnected(
    const TransportInfo& info,
    CompletionOnceCallback callback) {
  cert_is_issued_by_known_root_ = info.cert_is_issued_by_known_root;
  negotiated_protocol_ = info.negotiated_protocol;

  if (connected_callback_) {
    return connected_callback_.Run(info, std::move(callback));
  }
  return OK;
}

}  // namespace net

"""

```