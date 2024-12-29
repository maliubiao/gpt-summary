Response:
Let's break down the thought process for analyzing the `socket_bio_adapter.cc` file.

**1. Understanding the Core Purpose (The Big Picture):**

The first step is always to understand the main function of the code. The file name itself, "socket_bio_adapter," strongly suggests it's an adapter between sockets and something else. The presence of `#include "net/socket/socket.h"` and `#include "third_party/boringssl/src/include/openssl/bio.h"` immediately reveals the two key players: network sockets and OpenSSL's BIO (Basic Input/Output) abstraction.

Therefore, the core purpose is to bridge the gap between Chrome's `StreamSocket` and OpenSSL's BIO. This is a common pattern when integrating external libraries with different I/O models.

**2. Identifying Key Components and Data Structures:**

Next, examine the class definition `SocketBIOAdapter`. The member variables are crucial for understanding its internal state and how it works:

* `StreamSocket* socket_`:  Holds a pointer to the underlying network socket.
* `BIO* bio_`:  The OpenSSL BIO object being managed.
* `read_buffer_capacity_`, `write_buffer_capacity_`:  Sizes of the internal read and write buffers.
* `read_buffer_`, `write_buffer_`:  The actual buffers used for storing data. `GrowableIOBuffer` suggests a dynamic buffer for writing.
* `read_offset_`, `read_result_`: State related to reading from the socket.
* `write_error_`, `write_buffer_used_`: State related to writing to the socket.
* `delegate_`: A pointer to a `Delegate` interface, suggesting a callback mechanism for notifying other parts of the system about I/O events.
* `read_callback_`, `write_callback_`: Callbacks for asynchronous socket operations.

**3. Analyzing Key Methods and Their Roles:**

Now, focus on the key methods of the class:

* **Constructor (`SocketBIOAdapter`)**: Initializes the BIO object, sets up the association between the BIO and the adapter (`BIO_set_data`), and creates callbacks for socket operations.
* **Destructor (`~SocketBIOAdapter`)**: Cleans up resources, particularly the association with the BIO.
* **`BIORead`**:  The crucial method for reading data *from* the underlying socket and making it available to the BIO. This involves:
    * Checking for existing data.
    * Handling pending write errors (important for reporting errors that might otherwise be missed).
    * Initiating a read from the socket (`socket_->ReadIfReady` or `socket_->Read`).
    * Managing the read buffer.
    * Handling `ERR_IO_PENDING` for asynchronous operations.
* **`BIOWrite`**:  The crucial method for writing data *to* the underlying socket via the BIO. This involves:
    * Managing the write buffer (a ring buffer implementation).
    * Handling pending write errors.
    * Copying data from the BIO into the write buffer.
    * Initiating a write to the socket (`SocketWrite`).
    * Asynchronously notifying about read readiness if a write error occurred during a pending read.
* **`SocketWrite`**:  A helper method to actually send data from the write buffer to the socket. It handles retries and error conditions.
* **`HandleSocketReadResult` and `HandleSocketWriteResult`**:  Handle the results of asynchronous socket read and write operations, updating the internal state of the adapter.
* **`OnSocketReadComplete` and `OnSocketWriteComplete`**: Callbacks invoked when socket read and write operations complete, notifying the delegate.
* **`GetAdapter`**:  A static helper function to retrieve the `SocketBIOAdapter` instance associated with a given BIO.
* **`BIOWriteWrapper` and `BIOReadWrapper`**:  Static functions that act as the interface between the OpenSSL BIO and the `SocketBIOAdapter`'s `BIOWrite` and `BIORead` methods. These handle the conversion of `char*` and `int` to `base::span`.
* **`BIOCtrlWrapper`**: Handles control commands for the BIO.
* **`BIOMethod`**:  Returns the `BIO_METHOD` structure that defines the read, write, and control functions for this custom BIO type.

**4. Identifying the Relationship with JavaScript (and Browsers in General):**

Think about where TLS/SSL fits in a web browser. Secure connections (HTTPS) are fundamental. JavaScript interacts with these secure connections through APIs like `fetch` or `XMLHttpRequest`.

The connection:

* When a JavaScript makes an HTTPS request, the browser's network stack is involved.
* Part of establishing that secure connection involves TLS/SSL.
* OpenSSL (or BoringSSL, Chrome's fork) is used to handle the cryptographic aspects of TLS/SSL.
* The `SocketBIOAdapter` provides the I/O interface for OpenSSL to send and receive data over the underlying socket.

**5. Considering Error Handling and Common Mistakes:**

Look for error handling patterns (`write_error_`, `read_result_ < 0`). Think about what could go wrong when dealing with network sockets: connections closing unexpectedly, timeouts, etc. Consider how a programmer might misuse this (though it's mostly internal).

**6. Tracing User Actions (Debugging Clues):**

Think about user actions that would lead to network requests, especially secure ones. Typing an HTTPS URL, clicking a link to an HTTPS site, or JavaScript making an HTTPS `fetch` request are prime examples.

**7. Structuring the Output:**

Finally, organize the information logically:

* **Functionality Summary:** Briefly state the main purpose.
* **Relationship with JavaScript:** Explain how it fits into the browser's architecture and how JavaScript interacts with it indirectly.
* **Logic and Assumptions (Hypothetical Input/Output):** Provide concrete examples to illustrate how `BIORead` and `BIOWrite` work. This helps solidify understanding.
* **Common User/Programming Errors:**  Focus on potential issues related to socket handling.
* **User Actions (Debugging):** Provide a step-by-step trace from user interaction to the code.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** "It just reads and writes to a socket."  **Correction:** It's *adapting* the socket for use with OpenSSL's BIO, which has its own specific requirements and API.
* **Focusing too much on low-level details:**  Remember to connect it back to the user experience and JavaScript interaction.
* **Not being specific enough about error scenarios:**  Think about common network errors and how they would manifest.

By following these steps, systematically examining the code, and connecting the pieces, you can arrive at a comprehensive understanding of the `socket_bio_adapter.cc` file and its role in the Chromium network stack.
This file, `net/socket/socket_bio_adapter.cc`, implements an adapter called `SocketBIOAdapter` that bridges the gap between Chromium's `StreamSocket` and OpenSSL's `BIO` (Basic Input/Output) abstraction. Let's break down its functionalities:

**Core Functionality:**

1. **Adapting `StreamSocket` for OpenSSL's `BIO`:** The primary purpose is to allow OpenSSL (or BoringSSL, which Chromium uses) to perform TLS/SSL operations on a `StreamSocket`. OpenSSL's `BIO` provides an abstraction for input and output, and this adapter makes a `StreamSocket` look like a `BIO` to OpenSSL.

2. **Managing Read and Write Buffers:**  The adapter maintains internal read and write buffers (`read_buffer_`, `write_buffer_`) to handle data flow between the socket and the `BIO`. These buffers help in managing asynchronous I/O operations and provide a buffer for OpenSSL to read from and write to.

3. **Asynchronous I/O Handling:** It manages asynchronous read and write operations on the underlying `StreamSocket`. It uses callbacks (`OnSocketReadComplete`, `OnSocketWriteComplete`) to be notified when data is available to read or when a write operation completes.

4. **Handling `BIO` Read and Write Requests:** It implements the necessary functions (`BIOReadWrapper`, `BIOWriteWrapper`) that OpenSSL's `BIO` uses to read and write data. These wrappers translate the `BIO`'s requests into operations on the underlying `StreamSocket`.

5. **Error Handling:** It handles potential errors during socket read and write operations and communicates these errors back to the `BIO`.

6. **Traffic Annotation:** It includes a network traffic annotation (`kTrafficAnnotation`) to describe the purpose and data transmitted through this component.

**Relationship with JavaScript:**

While `SocketBIOAdapter` is a C++ component within Chromium's network stack, it plays a crucial role in enabling secure (HTTPS) connections that are heavily used by JavaScript in web browsers.

* **Indirect Role in HTTPS:** When JavaScript in a web page initiates an HTTPS request (e.g., using `fetch` or `XMLHttpRequest`), the browser's network stack is involved. If TLS/SSL is required for that connection, the `SocketBIOAdapter` is likely used under the hood.

* **No Direct JavaScript API:** JavaScript does not directly interact with `SocketBIOAdapter`. It's an internal implementation detail of the network stack.

**Example of Indirect Interaction:**

Imagine a JavaScript snippet:

```javascript
fetch('https://example.com/data.json')
  .then(response => response.json())
  .then(data => console.log(data));
```

Here's how `SocketBIOAdapter` might be involved:

1. **`fetch()` Initiation:** The JavaScript `fetch()` call triggers a network request.
2. **Socket Creation:** Chromium's network stack creates a `StreamSocket` to connect to `example.com` on port 443 (the standard HTTPS port).
3. **TLS Handshake:**  Because it's an HTTPS request, a TLS handshake needs to occur. OpenSSL/BoringSSL is used for this.
4. **`SocketBIOAdapter` Creation:** A `SocketBIOAdapter` is created, wrapping the `StreamSocket`. This allows OpenSSL to treat the socket as a `BIO`.
5. **OpenSSL I/O:** OpenSSL uses the `BIO` interface (and thus the `SocketBIOAdapter`) to send and receive TLS handshake messages and encrypted application data over the `StreamSocket`.
6. **Data Transfer:** Once the TLS connection is established, when the server sends the `data.json` response, OpenSSL reads the encrypted data from the `BIO` (which comes from the `SocketBIOAdapter` reading from the `StreamSocket`), decrypts it, and makes it available to the higher layers of the network stack, eventually reaching the JavaScript `fetch()` promise.

**Logic and Assumptions (Hypothetical Input/Output):**

Let's consider the `BIORead` and `BIOWrite` methods:

**Scenario: Reading Data**

* **Assumption Input:**  OpenSSL calls `BIORead` on the adapter's `BIO` with a buffer to read into. The underlying `StreamSocket` has some data available from the server.
* **Steps:**
    1. `BIORead` checks if there's already buffered data (`read_result_ > 0`).
    2. If not, it initiates a read from the `StreamSocket` using `socket_->ReadIfReady` or `socket_->Read`.
    3. The data is read into the internal `read_buffer_`.
    4. `BIORead` copies the requested number of bytes from `read_buffer_` to the output buffer provided by OpenSSL.
* **Hypothetical Output:** The number of bytes successfully read and copied into the output buffer.

**Scenario: Writing Data**

* **Assumption Input:** OpenSSL calls `BIOWrite` on the adapter's `BIO` with data to send. The underlying `StreamSocket` is ready to accept data.
* **Steps:**
    1. `BIOWrite` copies the data from the input buffer provided by OpenSSL into the internal `write_buffer_`.
    2. If the `write_buffer_` has enough data, `SocketWrite` is called to initiate a write operation on the `StreamSocket`.
    3. The data from `write_buffer_` is sent over the socket.
* **Hypothetical Output:** The number of bytes successfully copied into the `write_buffer_`.

**User or Programming Common Usage Errors:**

Since `SocketBIOAdapter` is an internal component, users don't directly interact with it. However, programming errors within Chromium's network stack that could lead to issues involving this adapter include:

1. **Incorrect Socket State:** Using the `SocketBIOAdapter` with a `StreamSocket` that is not in the appropriate state (e.g., not connected, already closed). This could lead to errors when trying to read or write.

    * **Example:**  Trying to perform TLS operations on a socket that hasn't completed the TCP handshake. The `SocketBIOAdapter` would likely encounter errors when attempting to read or write.

2. **Buffer Overflows/Underruns (Less likely due to careful implementation):**  Although the code uses `base::span` and careful size checks, errors in calculating buffer sizes or handling offsets could theoretically lead to issues.

3. **Incorrect Handling of Asynchronous Operations:** Failing to properly handle the completion callbacks for socket reads and writes could lead to data loss or unexpected behavior.

    * **Example:**  If the `Delegate` does not correctly manage the lifecycle of the `SocketBIOAdapter` or the underlying socket after a read or write completion, it could lead to use-after-free errors or other memory safety issues.

**User Operation Steps to Reach Here (Debugging Clues):**

A user action that leads to the `SocketBIOAdapter` being used typically involves establishing a secure network connection:

1. **User Enters HTTPS URL or Clicks HTTPS Link:** The user types an address starting with `https://` into the browser's address bar or clicks on a link pointing to an HTTPS website.
2. **DNS Resolution:** The browser performs a DNS lookup to find the IP address of the server.
3. **TCP Connection Establishment:** The browser initiates a TCP handshake with the server on port 443. A `StreamSocket` is created for this connection.
4. **TLS Handshake Initiation:**  The browser decides to establish a secure connection. This typically involves creating an instance of something like `SSLClientSocket` (or similar abstraction) which will utilize OpenSSL/BoringSSL.
5. **`SocketBIOAdapter` Creation:**  Within the TLS implementation, a `SocketBIOAdapter` is created, wrapping the `StreamSocket`. This allows OpenSSL to interact with the socket.
6. **TLS Handshake with `BIO` Operations:** OpenSSL uses the `BIO` interface (provided by the `SocketBIOAdapter`) to send and receive TLS handshake messages (ClientHello, ServerHello, Certificates, etc.) over the underlying TCP socket. This involves calls to `BIOReadWrapper` and `BIOWriteWrapper`, which delegate to the `SocketBIOAdapter`'s `BIORead` and `BIOWrite` methods.
7. **Data Transfer:** Once the TLS handshake is complete, when the server sends the requested web page or data, OpenSSL reads the encrypted data using the `BIO` interface, which ultimately reads from the `StreamSocket` through the `SocketBIOAdapter`.

**In summary, `SocketBIOAdapter` is a crucial internal component in Chromium's network stack that enables secure communication by adapting Chromium's socket abstraction for use with the OpenSSL/BoringSSL library. It manages the flow of data and asynchronous operations required for TLS/SSL connections, playing an invisible but vital role in everyday web browsing.**

Prompt: 
```
这是目录为net/socket/socket_bio_adapter.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/socket/socket_bio_adapter.h"

#include <stdio.h>
#include <string.h>

#include <algorithm>

#include "base/check_op.h"
#include "base/containers/span.h"
#include "base/debug/alias.h"
#include "base/functional/bind.h"
#include "base/location.h"
#include "base/notreached.h"
#include "base/numerics/safe_conversions.h"
#include "base/task/single_thread_task_runner.h"
#include "net/base/io_buffer.h"
#include "net/base/net_errors.h"
#include "net/socket/socket.h"
#include "net/socket/stream_socket.h"
#include "net/ssl/openssl_ssl_util.h"
#include "net/traffic_annotation/network_traffic_annotation.h"
#include "third_party/boringssl/src/include/openssl/bio.h"

namespace {

const net::NetworkTrafficAnnotationTag kTrafficAnnotation =
    net::DefineNetworkTrafficAnnotation("socket_bio_adapter", R"(
      semantics {
        sender: "Socket BIO Adapter"
        description:
          "SocketBIOAdapter is used only internal to //net code as an internal "
          "detail to implement a TLS connection for a Socket class, and is not "
          "being called directly outside of this abstraction."
        trigger:
          "Establishing a TLS connection to a remote endpoint. There are many "
          "different ways in which a TLS connection may be triggered, such as "
          "loading an HTTPS URL."
        data:
          "All data sent or received over a TLS connection. This traffic may "
          "either be the handshake or application data. During the handshake, "
          "the target host name, user's IP, data related to previous "
          "handshake, client certificates, and channel ID, may be sent. When "
          "the connection is used to load an HTTPS URL, the application data "
          "includes cookies, request headers, and the response body."
        destination: OTHER
        destination_other:
          "Any destination the implementing socket is connected to."
      }
      policy {
        cookies_allowed: NO
        setting: "This feature cannot be disabled."
        policy_exception_justification: "Essential for navigation."
      })");

}  // namespace

namespace net {

SocketBIOAdapter::SocketBIOAdapter(StreamSocket* socket,
                                   int read_buffer_capacity,
                                   int write_buffer_capacity,
                                   Delegate* delegate)
    : socket_(socket),
      read_buffer_capacity_(read_buffer_capacity),
      write_buffer_capacity_(write_buffer_capacity),
      delegate_(delegate) {
  bio_.reset(BIO_new(BIOMethod()));
  BIO_set_data(bio_.get(), this);
  BIO_set_init(bio_.get(), 1);

  read_callback_ = base::BindRepeating(&SocketBIOAdapter::OnSocketReadComplete,
                                       weak_factory_.GetWeakPtr());
  write_callback_ = base::BindRepeating(
      &SocketBIOAdapter::OnSocketWriteComplete, weak_factory_.GetWeakPtr());
}

SocketBIOAdapter::~SocketBIOAdapter() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  // BIOs are reference-counted and may outlive the adapter. Clear the pointer
  // so future operations fail.
  BIO_set_data(bio_.get(), nullptr);
}

bool SocketBIOAdapter::HasPendingReadData() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  return read_result_ > 0;
}

size_t SocketBIOAdapter::GetAllocationSize() const {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  size_t buffer_size = 0;
  if (read_buffer_)
    buffer_size += read_buffer_capacity_;

  if (write_buffer_)
    buffer_size += write_buffer_capacity_;
  return buffer_size;
}

int SocketBIOAdapter::BIORead(base::span<uint8_t> out) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  if (out.empty()) {
    return 0;
  }

  // If there is no result available synchronously, report any Write() errors
  // that were observed. Otherwise the application may have encountered a socket
  // error while writing that would otherwise not be reported until the
  // application attempted to write again - which it may never do. See
  // https://crbug.com/249848.
  if (write_error_ != OK && write_error_ != ERR_IO_PENDING &&
      (read_result_ == 0 || read_result_ == ERR_IO_PENDING)) {
    OpenSSLPutNetError(FROM_HERE, write_error_);
    return -1;
  }

  if (read_result_ == 0) {
    // Instantiate the read buffer and read from the socket. Although only |len|
    // bytes were requested, intentionally read to the full buffer size. The SSL
    // layer reads the record header and body in separate reads to avoid
    // overreading, but issuing one is more efficient. SSL sockets are not
    // reused after shutdown for non-SSL traffic, so overreading is fine.
    CHECK(!read_buffer_);
    CHECK_EQ(0u, read_offset_);
    read_buffer_ =
        base::MakeRefCounted<IOBufferWithSize>(read_buffer_capacity_);
    read_result_ = ERR_IO_PENDING;
    int result = socket_->ReadIfReady(
        read_buffer_.get(), read_buffer_capacity_,
        base::BindOnce(&SocketBIOAdapter::OnSocketReadIfReadyComplete,
                       weak_factory_.GetWeakPtr()));
    if (result == ERR_IO_PENDING)
      read_buffer_ = nullptr;
    if (result == ERR_READ_IF_READY_NOT_IMPLEMENTED) {
      result = socket_->Read(read_buffer_.get(), read_buffer_capacity_,
                             read_callback_);
    }
    if (result != ERR_IO_PENDING) {
      // `HandleSocketReadResult` will update `read_result_` based on `result`.
      HandleSocketReadResult(result);
    }
  }

  // There is a pending Read(). Inform the caller to retry when it completes.
  if (read_result_ == ERR_IO_PENDING) {
    BIO_set_retry_read(bio());
    return -1;
  }

  // If the last Read() failed, report the error.
  if (read_result_ < 0) {
    OpenSSLPutNetError(FROM_HERE, read_result_);
    return -1;
  }

  // Report the result of the last Read() if non-empty.
  const auto read_result_s = static_cast<size_t>(read_result_);
  CHECK_LT(read_offset_, read_result_s);
  base::span<const uint8_t> read_data = read_buffer_->span().subspan(
      read_offset_, std::min(out.size(), read_result_s - read_offset_));
  out.copy_prefix_from(read_data);
  read_offset_ += read_data.size();

  // Release the buffer when empty.
  if (read_offset_ == read_result_s) {
    read_buffer_ = nullptr;
    read_offset_ = 0;
    read_result_ = 0;
  }

  return read_data.size();
}

void SocketBIOAdapter::HandleSocketReadResult(int result) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  CHECK_NE(ERR_IO_PENDING, result);
  CHECK_EQ(ERR_IO_PENDING, read_result_);

  // If an EOF, canonicalize to ERR_CONNECTION_CLOSED here, so that higher
  // levels don't report success.
  if (result == 0)
    result = ERR_CONNECTION_CLOSED;

  read_result_ = result;

  // The read buffer is no longer needed.
  if (read_result_ <= 0)
    read_buffer_ = nullptr;
}

void SocketBIOAdapter::OnSocketReadComplete(int result) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  CHECK_EQ(ERR_IO_PENDING, read_result_);

  HandleSocketReadResult(result);
  delegate_->OnReadReady();
}

void SocketBIOAdapter::OnSocketReadIfReadyComplete(int result) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  CHECK_EQ(ERR_IO_PENDING, read_result_);
  CHECK_GE(OK, result);

  // Do not use HandleSocketReadResult() because result == OK doesn't mean EOF.
  read_result_ = result;

  delegate_->OnReadReady();
}

int SocketBIOAdapter::BIOWrite(base::span<const uint8_t> in) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  if (in.empty()) {
    return 0;
  }

  // If the write buffer is not empty, there must be a pending Write() to flush
  // it.
  CHECK(write_buffer_used_ == 0 || write_error_ == ERR_IO_PENDING);

  // If a previous Write() failed, report the error.
  if (write_error_ != OK && write_error_ != ERR_IO_PENDING) {
    OpenSSLPutNetError(FROM_HERE, write_error_);
    return -1;
  }

  // Instantiate the write buffer if needed.
  if (!write_buffer_) {
    CHECK_EQ(0u, write_buffer_used_);
    write_buffer_ = base::MakeRefCounted<GrowableIOBuffer>();
    write_buffer_->SetCapacity(write_buffer_capacity_);
  }

  // If the ring buffer is full, inform the caller to try again later.
  if (write_buffer_used_ == static_cast<size_t>(write_buffer_->capacity())) {
    BIO_set_retry_write(bio());
    return -1;
  }

  int bytes_copied = 0;

  // If there is space after the offset, fill it.
  const auto remaining_capacity =
      base::checked_cast<size_t>(write_buffer_->RemainingCapacity());
  if (write_buffer_used_ < remaining_capacity) {
    base::span<const uint8_t> chunk =
        in.first(std::min(remaining_capacity - write_buffer_used_, in.size()));
    write_buffer_->span().subspan(write_buffer_used_).copy_prefix_from(chunk);
    in = in.subspan(chunk.size());
    bytes_copied += chunk.size();
    write_buffer_used_ += chunk.size();
  }

  // If there is still space for remaining data, try to wrap around.
  if (in.size() > 0 && write_buffer_used_ < base::checked_cast<size_t>(
                                                write_buffer_->capacity())) {
    // If there were any room after the offset, the previous branch would have
    // filled it.
    CHECK_LE(remaining_capacity, write_buffer_used_);
    const size_t write_offset = write_buffer_used_ - remaining_capacity;
    base::span<const uint8_t> chunk = in.first(
        std::min(in.size(), write_buffer_->capacity() - write_buffer_used_));
    write_buffer_->everything().subspan(write_offset).copy_prefix_from(chunk);
    in = in.subspan(chunk.size());
    bytes_copied += chunk.size();
    write_buffer_used_ += chunk.size();
  }

  // Either the buffer is now full or there is no more input.
  CHECK(in.empty() ||
        write_buffer_used_ == static_cast<size_t>(write_buffer_->capacity()));

  // Schedule a socket Write() if necessary. (The ring buffer may previously
  // have been empty.)
  SocketWrite();

  // If a read-interrupting write error was synchronously discovered,
  // asynchronously notify OnReadReady. See https://crbug.com/249848. Avoid
  // reentrancy by deferring it to a later event loop iteration.
  if (write_error_ != OK && write_error_ != ERR_IO_PENDING &&
      read_result_ == ERR_IO_PENDING) {
    base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
        FROM_HERE, base::BindOnce(&SocketBIOAdapter::CallOnReadReady,
                                  weak_factory_.GetWeakPtr()));
  }

  return bytes_copied;
}

void SocketBIOAdapter::SocketWrite() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  while (write_error_ == OK && write_buffer_used_ > 0) {
    const size_t write_buffer_used_old = write_buffer_used_;
    const auto write_size = static_cast<int>(std::min(
        write_buffer_used_,
        base::checked_cast<size_t>(write_buffer_->RemainingCapacity())));

    // TODO(crbug.com/40064248): Remove this once the crash is resolved.
    char debug[128];
    snprintf(debug, sizeof(debug),
             "offset=%d;remaining=%d;used=%zu;write_size=%d",
             write_buffer_->offset(), write_buffer_->RemainingCapacity(),
             write_buffer_used_, write_size);
    base::debug::Alias(debug);

    write_error_ = ERR_IO_PENDING;
    int result = socket_->Write(write_buffer_.get(), write_size,
                                write_callback_, kTrafficAnnotation);

    // TODO(crbug.com/40064248): Remove this once the crash is resolved.
    char debug2[32];
    snprintf(debug2, sizeof(debug2), "result=%d", result);
    base::debug::Alias(debug2);

    // If `write_buffer_used_` changed across a call to the underlying socket,
    // something went very wrong.
    //
    // TODO(crbug.com/40064248): Remove this once the crash is resolved.
    CHECK_EQ(write_buffer_used_old, write_buffer_used_);
    if (result != ERR_IO_PENDING) {
      // `HandleSocketWriteResult` will update `write_error_` based on `result.
      HandleSocketWriteResult(result);
    }
  }
}

void SocketBIOAdapter::HandleSocketWriteResult(int result) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  CHECK_NE(ERR_IO_PENDING, result);
  CHECK_EQ(ERR_IO_PENDING, write_error_);

  if (result < 0) {
    write_error_ = result;

    // The write buffer is no longer needed.
    write_buffer_ = nullptr;
    write_buffer_used_ = 0;
    return;
  }

  // Advance the ring buffer.
  CHECK_LE(static_cast<size_t>(result), write_buffer_used_);
  CHECK_LE(result, write_buffer_->RemainingCapacity());
  write_buffer_->set_offset(write_buffer_->offset() + result);
  write_buffer_used_ -= result;
  if (write_buffer_->RemainingCapacity() == 0)
    write_buffer_->set_offset(0);
  write_error_ = OK;

  // Release the write buffer if empty.
  if (write_buffer_used_ == 0)
    write_buffer_ = nullptr;
}

void SocketBIOAdapter::OnSocketWriteComplete(int result) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  CHECK_EQ(ERR_IO_PENDING, write_error_);

  bool was_full =
      write_buffer_used_ == static_cast<size_t>(write_buffer_->capacity());

  HandleSocketWriteResult(result);
  SocketWrite();

  // If transitioning from being unable to accept data to being able to, signal
  // OnWriteReady.
  if (was_full) {
    base::WeakPtr<SocketBIOAdapter> guard(weak_factory_.GetWeakPtr());
    delegate_->OnWriteReady();
    // OnWriteReady may delete the adapter.
    if (!guard)
      return;
  }

  // Write errors are fed back into BIO_read once the read buffer is empty. If
  // BIO_read is currently blocked, signal early that a read result is ready.
  if (result < 0 && read_result_ == ERR_IO_PENDING)
    delegate_->OnReadReady();
}

void SocketBIOAdapter::CallOnReadReady() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  if (read_result_ == ERR_IO_PENDING)
    delegate_->OnReadReady();
}

SocketBIOAdapter* SocketBIOAdapter::GetAdapter(BIO* bio) {
  SocketBIOAdapter* adapter =
      reinterpret_cast<SocketBIOAdapter*>(BIO_get_data(bio));
  if (adapter) {
    CHECK_EQ(bio, adapter->bio());
  }
  return adapter;
}

// TODO(tsepez): should be declared UNSAFE_BUFFER_USAGE in header.
int SocketBIOAdapter::BIOWriteWrapper(BIO* bio, const char* in, int len) {
  BIO_clear_retry_flags(bio);

  SocketBIOAdapter* adapter = GetAdapter(bio);
  if (!adapter) {
    OpenSSLPutNetError(FROM_HERE, ERR_UNEXPECTED);
    return -1;
  }

  return adapter->BIOWrite(base::as_bytes(
      // SAFETY: The caller must ensure `in` points to `len` bytes.
      // TODO(crbug.com/354307327): Spanify this method.
      UNSAFE_TODO(base::span(in, base::checked_cast<size_t>(len)))));
}

// TODO(tsepez): should be declared UNSAFE_BUFFER_USAGE in header.
int SocketBIOAdapter::BIOReadWrapper(BIO* bio, char* out, int len) {
  BIO_clear_retry_flags(bio);

  SocketBIOAdapter* adapter = GetAdapter(bio);
  if (!adapter) {
    OpenSSLPutNetError(FROM_HERE, ERR_UNEXPECTED);
    return -1;
  }

  return adapter->BIORead(base::as_writable_bytes(
      // SAFETY: The caller must ensure `out` points to `len` bytes.
      // TODO(crbug.com/354307327): Spanify this method.
      UNSAFE_TODO(base::span(out, base::checked_cast<size_t>(len)))));
}

long SocketBIOAdapter::BIOCtrlWrapper(BIO* bio,
                                      int cmd,
                                      long larg,
                                      void* parg) {
  switch (cmd) {
    case BIO_CTRL_FLUSH:
      // The SSL stack requires BIOs handle BIO_flush.
      return 1;
  }

  NOTIMPLEMENTED();
  return 0;
}

const BIO_METHOD* SocketBIOAdapter::BIOMethod() {
  static const BIO_METHOD* kMethod = []() {
    BIO_METHOD* method = BIO_meth_new(0, nullptr);
    CHECK(method);
    CHECK(BIO_meth_set_write(method, SocketBIOAdapter::BIOWriteWrapper));
    CHECK(BIO_meth_set_read(method, SocketBIOAdapter::BIOReadWrapper));
    CHECK(BIO_meth_set_ctrl(method, SocketBIOAdapter::BIOCtrlWrapper));
    return method;
  }();
  return kMethod;
}

}  // namespace net

"""

```