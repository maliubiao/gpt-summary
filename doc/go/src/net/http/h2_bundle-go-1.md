Response:
Let's break down the thought process for analyzing this Go code snippet.

**1. Initial Scan and Keyword Recognition:**

My first step is a quick scan for recognizable keywords and patterns related to HTTP/2 and TLS. I see:

* `http2cipher_TLS_*`:  This immediately screams "TLS cipher suites."  The sheer number of them reinforces this.
* `http2ClientConnPool`:  The name strongly suggests managing a pool of client connections, likely for connection reuse in HTTP/2.
* `GetClientConn`, `MarkDead`, `closeIdleConnections`: These are common operations associated with connection pooling.
* `http2Transport`, `http2Server`:  These are likely the core types for handling HTTP/2 transport and server logic, respectively.
* `sync.Mutex`: Indicates thread-safe operations, common in connection management.
* `dialing`, `conns`, `keys`: These look like internal data structures for the connection pool.
* `http2dialCall`: Likely represents an in-progress attempt to establish a new connection.
* `http2addConnCall`:  Appears to handle adding a pre-existing connection to the pool.
* `http2http2Config`:  This suggests configuration related to HTTP/2 settings.
* `MaxConcurrentStreams`, `MaxReadFrameSize`, etc.:  These are standard HTTP/2 settings.
* `http2dataChunkPools`:  Indicates a pool of byte slices for efficient memory management, likely for handling request/response bodies.
* `http2dataBuffer`: A custom buffer type.
* `http2ErrCode`: Represents HTTP/2 error codes.
* `http2ConnectionError`, `http2StreamError`: Types representing HTTP/2 specific errors.
* `http2inflow`:  Related to flow control.

**2. Grouping by Functionality:**

Based on the keywords, I mentally group the code into functional areas:

* **Cipher Suites:** The large block of `http2cipher_TLS_*` constants.
* **Client Connection Pooling:**  The `http2ClientConnPool` struct and related methods (`GetClientConn`, `MarkDead`, `closeIdleConnections`, `addConnIfNeeded`).
* **Connection Dialing:** `http2dialCall` and related functions.
* **Adding Existing Connections:** `http2addConnCall`.
* **Configuration:** `http2http2Config` and its related functions (`configFromServer`, `configFromTransport`, `http2fillNetHTTPConfig`).
* **Data Buffering:** `http2dataChunkPools` and `http2dataBuffer`.
* **Error Handling:** `http2ErrCode`, `http2ConnectionError`, `http2StreamError`, `http2connError`.
* **Flow Control:** `http2inflow`.

**3. Inferring Purpose within Each Group:**

* **Cipher Suites:** This section is clearly about defining the supported TLS cipher suites for HTTP/2 connections. The function `http2isGoodCipher` likely checks if a given cipher suite is acceptable.
* **Client Connection Pooling:** This implements a mechanism to reuse established HTTP/2 connections to the same server. This improves performance by avoiding the overhead of creating a new connection for every request. The different states (idle, dialing, active) are managed here.
* **Connection Dialing:** This handles the asynchronous process of establishing a new connection when one isn't available in the pool. It prevents multiple concurrent attempts to connect to the same server.
* **Adding Existing Connections:** This addresses a potential scenario where the underlying TCP connection is established outside the HTTP/2 layer (e.g., by HTTP/1.1). It integrates these connections into the HTTP/2 connection pool.
* **Configuration:** This section deals with merging and applying various HTTP/2 configuration options from both the standard `net/http` package and the internal HTTP/2 implementation. It ensures consistent and valid settings.
* **Data Buffering:** This implements a custom buffer management scheme to handle incoming DATA frames efficiently. The chunking and pooling likely aim to minimize memory allocation and GC overhead.
* **Error Handling:** This defines specific error types and codes relevant to HTTP/2, providing more detailed error information than generic `error` values.
* **Flow Control:** This manages the receiving side of HTTP/2 flow control, allowing the server to signal to the client how much data it is willing to receive.

**4. Identifying Key Interactions and Relationships:**

I notice how the connection pool interacts with the dialing and adding connection logic. The configuration is used to set parameters for the connection and stream handling. The data buffer is used within the connection handling to read incoming data. Error handling is integrated throughout the process.

**5. Formulating the Summary:**

Based on the groupings and inferred purposes, I can now synthesize a concise summary. I want to capture the core functionalities:

* **TLS Cipher Suite Support:** Defining and validating the cryptographic algorithms used for secure connections.
* **Client Connection Pooling:** Implementing connection reuse for efficiency.
* **Connection Management:** Handling the lifecycle of connections, including dialing and adding pre-existing ones.
* **Configuration:** Managing HTTP/2 settings.
* **Data Handling:** Efficiently buffering request/response data.
* **Error Reporting:** Providing specific HTTP/2 error information.
* **Flow Control (Receiving):** Managing the amount of data the server is willing to accept.

Essentially, the code snippet represents a significant portion of the HTTP/2 client-side implementation in Go's `net/http` package, focusing on connection management, security setup, data handling, and configuration.

**Self-Correction/Refinement:**

Initially, I might have focused too much on individual structures. The "归纳一下它的功能" (summarize its function) prompt pushes me to think at a higher level of abstraction, focusing on *what* the code accomplishes rather than just *how*. I also make sure to emphasize the "client-side" aspect based on the `http2ClientConnPool` naming and the context of the `net/http` package. The "第2部分" also suggests it's part of a larger module, so I try to frame the summary within that context.
这个go语言代码片段主要负责 **HTTP/2 客户端连接的管理和配置**。

具体来说，它的功能可以归纳为以下几点：

1. **定义和校验支持的TLS加密套件 (Cipher Suites)：**  代码开头定义了一系列 `http2cipher_TLS_...` 的常量，这些常量代表了 HTTP/2 协议支持的各种 TLS 加密算法组合。`http2isGoodCipher` 函数用于判断给定的加密套件是否被认为是“好”的，即是否在支持的列表中。这部分确保了客户端只使用安全的加密连接。

2. **实现客户端连接池 (Client Connection Pool)：** `http2clientConnPool` 结构体及其相关方法实现了 HTTP/2 客户端连接的复用。它的目的是为了提高性能，避免为每个新的 HTTP/2 请求都建立新的 TCP 连接和 TLS 握手。
    * `GetClientConn`:  从连接池中获取可用的连接，如果连接池为空或者没有空闲连接，则尝试建立新的连接。
    * `MarkDead`: 标记一个连接为失效，可能因为它遇到了错误。
    * `closeIdleConnections`: 关闭连接池中空闲的连接，以释放资源。
    * `addConnIfNeeded`:  在需要时将一个新建立的连接添加到连接池中，避免重复添加。

3. **管理连接的建立 (Dialing)：** `http2dialCall` 结构体和相关方法负责异步地建立新的 HTTP/2 连接。它使用了 `singleflight` 模式（尽管代码中有TODO注释），确保对于同一个地址，只有一个连接建立请求在进行中。

4. **处理已存在的连接 (Adding Existing Connections)：**  `addConnIfNeeded` 函数允许将一个已经建立的 `net.Conn` (可能是 HTTP/1.1 升级上来的连接)  集成到 HTTP/2 的连接池中。

5. **定义和管理 HTTP/2 配置 (Configuration)：** `http2http2Config` 结构体用于存储 HTTP/2 的各种配置参数，例如最大并发流数、帧大小限制、超时时间等。
    * `configFromServer` 和 `configFromTransport` 函数用于将 `net/http` 包中的 `Server` 和 `Transport` 结构体中的 HTTP/2 配置合并到 `http2http2Config` 中。
    * `http2fillNetHTTPConfig` 函数用于从 `net/http.HTTP2Config` 结构体中填充配置信息。
    * `http2setConfigDefaults` 函数设置默认的配置值。

6. **实现数据缓冲 (Data Buffering)：**  `http2dataChunkPools` 定义了一组 `sync.Pool`，用于复用数据块，减少内存分配和垃圾回收的压力。 `http2dataBuffer` 结构体实现了一个基于数据块的 `io.ReadWriter`，用于接收和读取 HTTP/2 的 DATA 帧数据。

7. **定义 HTTP/2 错误类型 (Error Types)：** 代码定义了 `http2ErrCode` 以及 `http2ConnectionError` 和 `http2StreamError` 等结构体，用于表示 HTTP/2 特有的连接错误和流错误。

8. **实现入站流量控制 (Inflow Control)：** `http2inflow` 结构体用于管理入站流量控制窗口，跟踪已接收但尚未被应用层读取的数据量，并决定何时发送 WINDOW_UPDATE 帧给对端，告知对端可以发送更多数据。

**它是什么go语言功能的实现？**

这个代码片段是 Go 语言 `net/http` 包中 **HTTP/2 客户端支持** 的核心实现部分。它利用了 Go 语言的以下特性：

* **结构体 (struct)：**  用于组织数据和方法，例如 `http2ClientConnPool` 和 `http2http2Config`。
* **接口 (interface)：**  例如 `http2ClientConnPool` 和 `http2clientConnPoolIdleCloser`，定义了连接池的行为规范。
* **方法 (method)：**  关联到结构体的函数，用于操作结构体的数据。
* **并发 (concurrency)：** 使用 `sync.Mutex` 进行互斥锁保护，确保连接池的线程安全。使用 `go` 关键字启动 goroutine 来处理异步的连接建立操作。
* **sync.Pool：** 用于对象复用，减少内存分配。
* **错误处理 (error handling)：**  定义了特定的错误类型，并使用 `errors` 包进行错误处理。

**代码举例说明 (连接池获取连接):**

假设我们有一个 `http2Transport` 实例 `t` 和一个 `http2clientConnPool` 实例 `pool`。

```go
package main

import (
	"context"
	"fmt"
	"net/http"
	"net/url"

	"golang.org/x/net/http2"
)

func main() {
	t := &http2.Transport{} // 实际应用中需要进行更详细的配置
	pool := &http2.clientConnPool{t: t}

	reqURL, _ := url.Parse("https://example.com")
	req := &http.Request{
		Method: "GET",
		URL:    reqURL,
		Host:   reqURL.Host,
	}
	addr := "example.com:443" // 实际应用中需要根据 URL 解析

	cc, err := pool.GetClientConn(req, addr)
	if err != nil {
		fmt.Println("获取连接失败:", err)
		return
	}
	fmt.Println("成功获取到连接:", cc)

	// 使用连接发送请求...

	// 假设请求完成，需要释放连接 (虽然在这个简化例子中没有明确的释放操作)
}
```

**假设输入与输出:**

* **输入:**  一个 `http.Request` 对象，目标地址字符串 "example.com:443"。
* **假设:** 连接池中没有到 "example.com:443" 的空闲连接。
* **输出:**
    * 如果成功建立连接，则返回一个 `*http2.ClientConn` 对象，并且连接被标记为正在使用。
    * 如果建立连接失败（例如，网络错误），则返回 `nil` 和一个 `error`。

**代码推理:**

`pool.GetClientConn(req, addr)` 会首先检查连接池中是否有到 `addr` 的空闲连接。如果没有，它会调用 `p.getStartDialLocked` 尝试建立新的连接。 `getStartDialLocked` 会检查是否有正在进行的连接建立请求，如果没有，则启动一个新的 goroutine 调用 `call.dial` 来建立连接。  一旦连接建立成功，`addConnLocked` 会将连接添加到连接池中。最终，`GetClientConn` 返回这个新建立的连接。

**命令行参数的具体处理:**

这段代码本身不直接处理命令行参数。HTTP/2 的配置通常通过 `net/http` 包中的 `Server` 或 `Transport` 结构体的字段进行配置，这些配置可能是通过代码硬编码，或者从配置文件读取后设置的。

**使用者易犯错的点 (假设的角度，因为没有直接的使用者交互):**

虽然这段代码是内部实现，但如果使用者直接操作或扩展 `http2.Transport`，可能会犯以下错误：

* **不正确地配置 TLS:**  如果 `TLSClientConfig` 配置不当，例如没有提供有效的证书，或者使用的加密套件与服务器不兼容，可能会导致连接失败。
* **不理解连接池的行为:**  错误地认为每次请求都会建立新连接，或者不正确地处理连接的生命周期，可能导致性能问题或者连接泄漏。
* **修改内部配置而不理解其影响:**  直接修改 `http2Transport` 或 `http2http2Config` 中的字段，而不理解其背后的含义，可能导致意想不到的行为或破坏协议的正确性。

**归纳一下它的功能 (针对第2部分):**

这个代码片段是 `go/src/net/http/h2_bundle.go` 文件的第二部分，它的主要功能是 **构建 HTTP/2 客户端连接的基础设施**。 它定义了连接池的管理逻辑，包括获取、标记失效、关闭空闲连接，以及异步地建立新连接的机制。  此外，它还处理了将已存在的连接集成到连接池中的情况。  这部分代码是 HTTP/2 客户端高效、可靠运行的关键组成部分，它通过连接复用和合理的连接管理来提升性能。

### 提示词
```
这是路径为go/src/net/http/h2_bundle.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共13部分，请归纳一下它的功能
```

### 源代码
```go
er_TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256,
		http2cipher_TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256,
		http2cipher_TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256,
		http2cipher_TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256,
		http2cipher_TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256,
		http2cipher_TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256,
		http2cipher_TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256,
		http2cipher_TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256,
		http2cipher_TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256,
		http2cipher_TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256,
		http2cipher_TLS_EMPTY_RENEGOTIATION_INFO_SCSV,
		http2cipher_TLS_ECDH_ECDSA_WITH_NULL_SHA,
		http2cipher_TLS_ECDH_ECDSA_WITH_RC4_128_SHA,
		http2cipher_TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA,
		http2cipher_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA,
		http2cipher_TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA,
		http2cipher_TLS_ECDHE_ECDSA_WITH_NULL_SHA,
		http2cipher_TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
		http2cipher_TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,
		http2cipher_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		http2cipher_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		http2cipher_TLS_ECDH_RSA_WITH_NULL_SHA,
		http2cipher_TLS_ECDH_RSA_WITH_RC4_128_SHA,
		http2cipher_TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA,
		http2cipher_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA,
		http2cipher_TLS_ECDH_RSA_WITH_AES_256_CBC_SHA,
		http2cipher_TLS_ECDHE_RSA_WITH_NULL_SHA,
		http2cipher_TLS_ECDHE_RSA_WITH_RC4_128_SHA,
		http2cipher_TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
		http2cipher_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		http2cipher_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		http2cipher_TLS_ECDH_anon_WITH_NULL_SHA,
		http2cipher_TLS_ECDH_anon_WITH_RC4_128_SHA,
		http2cipher_TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA,
		http2cipher_TLS_ECDH_anon_WITH_AES_128_CBC_SHA,
		http2cipher_TLS_ECDH_anon_WITH_AES_256_CBC_SHA,
		http2cipher_TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA,
		http2cipher_TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA,
		http2cipher_TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA,
		http2cipher_TLS_SRP_SHA_WITH_AES_128_CBC_SHA,
		http2cipher_TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA,
		http2cipher_TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA,
		http2cipher_TLS_SRP_SHA_WITH_AES_256_CBC_SHA,
		http2cipher_TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA,
		http2cipher_TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA,
		http2cipher_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
		http2cipher_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
		http2cipher_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256,
		http2cipher_TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384,
		http2cipher_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
		http2cipher_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
		http2cipher_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256,
		http2cipher_TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384,
		http2cipher_TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256,
		http2cipher_TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384,
		http2cipher_TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256,
		http2cipher_TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384,
		http2cipher_TLS_ECDHE_PSK_WITH_RC4_128_SHA,
		http2cipher_TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA,
		http2cipher_TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA,
		http2cipher_TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA,
		http2cipher_TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256,
		http2cipher_TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384,
		http2cipher_TLS_ECDHE_PSK_WITH_NULL_SHA,
		http2cipher_TLS_ECDHE_PSK_WITH_NULL_SHA256,
		http2cipher_TLS_ECDHE_PSK_WITH_NULL_SHA384,
		http2cipher_TLS_RSA_WITH_ARIA_128_CBC_SHA256,
		http2cipher_TLS_RSA_WITH_ARIA_256_CBC_SHA384,
		http2cipher_TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256,
		http2cipher_TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384,
		http2cipher_TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256,
		http2cipher_TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384,
		http2cipher_TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256,
		http2cipher_TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384,
		http2cipher_TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256,
		http2cipher_TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384,
		http2cipher_TLS_DH_anon_WITH_ARIA_128_CBC_SHA256,
		http2cipher_TLS_DH_anon_WITH_ARIA_256_CBC_SHA384,
		http2cipher_TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256,
		http2cipher_TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384,
		http2cipher_TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256,
		http2cipher_TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384,
		http2cipher_TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256,
		http2cipher_TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384,
		http2cipher_TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256,
		http2cipher_TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384,
		http2cipher_TLS_RSA_WITH_ARIA_128_GCM_SHA256,
		http2cipher_TLS_RSA_WITH_ARIA_256_GCM_SHA384,
		http2cipher_TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256,
		http2cipher_TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384,
		http2cipher_TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256,
		http2cipher_TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384,
		http2cipher_TLS_DH_anon_WITH_ARIA_128_GCM_SHA256,
		http2cipher_TLS_DH_anon_WITH_ARIA_256_GCM_SHA384,
		http2cipher_TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256,
		http2cipher_TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384,
		http2cipher_TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256,
		http2cipher_TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384,
		http2cipher_TLS_PSK_WITH_ARIA_128_CBC_SHA256,
		http2cipher_TLS_PSK_WITH_ARIA_256_CBC_SHA384,
		http2cipher_TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256,
		http2cipher_TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384,
		http2cipher_TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256,
		http2cipher_TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384,
		http2cipher_TLS_PSK_WITH_ARIA_128_GCM_SHA256,
		http2cipher_TLS_PSK_WITH_ARIA_256_GCM_SHA384,
		http2cipher_TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256,
		http2cipher_TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384,
		http2cipher_TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256,
		http2cipher_TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384,
		http2cipher_TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256,
		http2cipher_TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384,
		http2cipher_TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256,
		http2cipher_TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384,
		http2cipher_TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256,
		http2cipher_TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384,
		http2cipher_TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256,
		http2cipher_TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384,
		http2cipher_TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256,
		http2cipher_TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384,
		http2cipher_TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256,
		http2cipher_TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384,
		http2cipher_TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256,
		http2cipher_TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384,
		http2cipher_TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256,
		http2cipher_TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384,
		http2cipher_TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256,
		http2cipher_TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384,
		http2cipher_TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256,
		http2cipher_TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384,
		http2cipher_TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256,
		http2cipher_TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384,
		http2cipher_TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256,
		http2cipher_TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384,
		http2cipher_TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256,
		http2cipher_TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384,
		http2cipher_TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256,
		http2cipher_TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384,
		http2cipher_TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256,
		http2cipher_TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384,
		http2cipher_TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256,
		http2cipher_TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384,
		http2cipher_TLS_RSA_WITH_AES_128_CCM,
		http2cipher_TLS_RSA_WITH_AES_256_CCM,
		http2cipher_TLS_RSA_WITH_AES_128_CCM_8,
		http2cipher_TLS_RSA_WITH_AES_256_CCM_8,
		http2cipher_TLS_PSK_WITH_AES_128_CCM,
		http2cipher_TLS_PSK_WITH_AES_256_CCM,
		http2cipher_TLS_PSK_WITH_AES_128_CCM_8,
		http2cipher_TLS_PSK_WITH_AES_256_CCM_8:
		return true
	default:
		return false
	}
}

// ClientConnPool manages a pool of HTTP/2 client connections.
type http2ClientConnPool interface {
	// GetClientConn returns a specific HTTP/2 connection (usually
	// a TLS-TCP connection) to an HTTP/2 server. On success, the
	// returned ClientConn accounts for the upcoming RoundTrip
	// call, so the caller should not omit it. If the caller needs
	// to, ClientConn.RoundTrip can be called with a bogus
	// new(http.Request) to release the stream reservation.
	GetClientConn(req *Request, addr string) (*http2ClientConn, error)
	MarkDead(*http2ClientConn)
}

// clientConnPoolIdleCloser is the interface implemented by ClientConnPool
// implementations which can close their idle connections.
type http2clientConnPoolIdleCloser interface {
	http2ClientConnPool
	closeIdleConnections()
}

var (
	_ http2clientConnPoolIdleCloser = (*http2clientConnPool)(nil)
	_ http2clientConnPoolIdleCloser = http2noDialClientConnPool{}
)

// TODO: use singleflight for dialing and addConnCalls?
type http2clientConnPool struct {
	t *http2Transport

	mu sync.Mutex // TODO: maybe switch to RWMutex
	// TODO: add support for sharing conns based on cert names
	// (e.g. share conn for googleapis.com and appspot.com)
	conns        map[string][]*http2ClientConn // key is host:port
	dialing      map[string]*http2dialCall     // currently in-flight dials
	keys         map[*http2ClientConn][]string
	addConnCalls map[string]*http2addConnCall // in-flight addConnIfNeeded calls
}

func (p *http2clientConnPool) GetClientConn(req *Request, addr string) (*http2ClientConn, error) {
	return p.getClientConn(req, addr, http2dialOnMiss)
}

const (
	http2dialOnMiss   = true
	http2noDialOnMiss = false
)

func (p *http2clientConnPool) getClientConn(req *Request, addr string, dialOnMiss bool) (*http2ClientConn, error) {
	// TODO(dneil): Dial a new connection when t.DisableKeepAlives is set?
	if http2isConnectionCloseRequest(req) && dialOnMiss {
		// It gets its own connection.
		http2traceGetConn(req, addr)
		const singleUse = true
		cc, err := p.t.dialClientConn(req.Context(), addr, singleUse)
		if err != nil {
			return nil, err
		}
		return cc, nil
	}
	for {
		p.mu.Lock()
		for _, cc := range p.conns[addr] {
			if cc.ReserveNewRequest() {
				// When a connection is presented to us by the net/http package,
				// the GetConn hook has already been called.
				// Don't call it a second time here.
				if !cc.getConnCalled {
					http2traceGetConn(req, addr)
				}
				cc.getConnCalled = false
				p.mu.Unlock()
				return cc, nil
			}
		}
		if !dialOnMiss {
			p.mu.Unlock()
			return nil, http2ErrNoCachedConn
		}
		http2traceGetConn(req, addr)
		call := p.getStartDialLocked(req.Context(), addr)
		p.mu.Unlock()
		<-call.done
		if http2shouldRetryDial(call, req) {
			continue
		}
		cc, err := call.res, call.err
		if err != nil {
			return nil, err
		}
		if cc.ReserveNewRequest() {
			return cc, nil
		}
	}
}

// dialCall is an in-flight Transport dial call to a host.
type http2dialCall struct {
	_ http2incomparable
	p *http2clientConnPool
	// the context associated with the request
	// that created this dialCall
	ctx  context.Context
	done chan struct{}    // closed when done
	res  *http2ClientConn // valid after done is closed
	err  error            // valid after done is closed
}

// requires p.mu is held.
func (p *http2clientConnPool) getStartDialLocked(ctx context.Context, addr string) *http2dialCall {
	if call, ok := p.dialing[addr]; ok {
		// A dial is already in-flight. Don't start another.
		return call
	}
	call := &http2dialCall{p: p, done: make(chan struct{}), ctx: ctx}
	if p.dialing == nil {
		p.dialing = make(map[string]*http2dialCall)
	}
	p.dialing[addr] = call
	go call.dial(call.ctx, addr)
	return call
}

// run in its own goroutine.
func (c *http2dialCall) dial(ctx context.Context, addr string) {
	const singleUse = false // shared conn
	c.res, c.err = c.p.t.dialClientConn(ctx, addr, singleUse)

	c.p.mu.Lock()
	delete(c.p.dialing, addr)
	if c.err == nil {
		c.p.addConnLocked(addr, c.res)
	}
	c.p.mu.Unlock()

	close(c.done)
}

// addConnIfNeeded makes a NewClientConn out of c if a connection for key doesn't
// already exist. It coalesces concurrent calls with the same key.
// This is used by the http1 Transport code when it creates a new connection. Because
// the http1 Transport doesn't de-dup TCP dials to outbound hosts (because it doesn't know
// the protocol), it can get into a situation where it has multiple TLS connections.
// This code decides which ones live or die.
// The return value used is whether c was used.
// c is never closed.
func (p *http2clientConnPool) addConnIfNeeded(key string, t *http2Transport, c net.Conn) (used bool, err error) {
	p.mu.Lock()
	for _, cc := range p.conns[key] {
		if cc.CanTakeNewRequest() {
			p.mu.Unlock()
			return false, nil
		}
	}
	call, dup := p.addConnCalls[key]
	if !dup {
		if p.addConnCalls == nil {
			p.addConnCalls = make(map[string]*http2addConnCall)
		}
		call = &http2addConnCall{
			p:    p,
			done: make(chan struct{}),
		}
		p.addConnCalls[key] = call
		go call.run(t, key, c)
	}
	p.mu.Unlock()

	<-call.done
	if call.err != nil {
		return false, call.err
	}
	return !dup, nil
}

type http2addConnCall struct {
	_    http2incomparable
	p    *http2clientConnPool
	done chan struct{} // closed when done
	err  error
}

func (c *http2addConnCall) run(t *http2Transport, key string, nc net.Conn) {
	cc, err := t.NewClientConn(nc)

	p := c.p
	p.mu.Lock()
	if err != nil {
		c.err = err
	} else {
		cc.getConnCalled = true // already called by the net/http package
		p.addConnLocked(key, cc)
	}
	delete(p.addConnCalls, key)
	p.mu.Unlock()
	close(c.done)
}

// p.mu must be held
func (p *http2clientConnPool) addConnLocked(key string, cc *http2ClientConn) {
	for _, v := range p.conns[key] {
		if v == cc {
			return
		}
	}
	if p.conns == nil {
		p.conns = make(map[string][]*http2ClientConn)
	}
	if p.keys == nil {
		p.keys = make(map[*http2ClientConn][]string)
	}
	p.conns[key] = append(p.conns[key], cc)
	p.keys[cc] = append(p.keys[cc], key)
}

func (p *http2clientConnPool) MarkDead(cc *http2ClientConn) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, key := range p.keys[cc] {
		vv, ok := p.conns[key]
		if !ok {
			continue
		}
		newList := http2filterOutClientConn(vv, cc)
		if len(newList) > 0 {
			p.conns[key] = newList
		} else {
			delete(p.conns, key)
		}
	}
	delete(p.keys, cc)
}

func (p *http2clientConnPool) closeIdleConnections() {
	p.mu.Lock()
	defer p.mu.Unlock()
	// TODO: don't close a cc if it was just added to the pool
	// milliseconds ago and has never been used. There's currently
	// a small race window with the HTTP/1 Transport's integration
	// where it can add an idle conn just before using it, and
	// somebody else can concurrently call CloseIdleConns and
	// break some caller's RoundTrip.
	for _, vv := range p.conns {
		for _, cc := range vv {
			cc.closeIfIdle()
		}
	}
}

func http2filterOutClientConn(in []*http2ClientConn, exclude *http2ClientConn) []*http2ClientConn {
	out := in[:0]
	for _, v := range in {
		if v != exclude {
			out = append(out, v)
		}
	}
	// If we filtered it out, zero out the last item to prevent
	// the GC from seeing it.
	if len(in) != len(out) {
		in[len(in)-1] = nil
	}
	return out
}

// noDialClientConnPool is an implementation of http2.ClientConnPool
// which never dials. We let the HTTP/1.1 client dial and use its TLS
// connection instead.
type http2noDialClientConnPool struct{ *http2clientConnPool }

func (p http2noDialClientConnPool) GetClientConn(req *Request, addr string) (*http2ClientConn, error) {
	return p.getClientConn(req, addr, http2noDialOnMiss)
}

// shouldRetryDial reports whether the current request should
// retry dialing after the call finished unsuccessfully, for example
// if the dial was canceled because of a context cancellation or
// deadline expiry.
func http2shouldRetryDial(call *http2dialCall, req *Request) bool {
	if call.err == nil {
		// No error, no need to retry
		return false
	}
	if call.ctx == req.Context() {
		// If the call has the same context as the request, the dial
		// should not be retried, since any cancellation will have come
		// from this request.
		return false
	}
	if !errors.Is(call.err, context.Canceled) && !errors.Is(call.err, context.DeadlineExceeded) {
		// If the call error is not because of a context cancellation or a deadline expiry,
		// the dial should not be retried.
		return false
	}
	// Only retry if the error is a context cancellation error or deadline expiry
	// and the context associated with the call was canceled or expired.
	return call.ctx.Err() != nil
}

// http2Config is a package-internal version of net/http.HTTP2Config.
//
// http.HTTP2Config was added in Go 1.24.
// When running with a version of net/http that includes HTTP2Config,
// we merge the configuration with the fields in Transport or Server
// to produce an http2Config.
//
// Zero valued fields in http2Config are interpreted as in the
// net/http.HTTPConfig documentation.
//
// Precedence order for reconciling configurations is:
//
//   - Use the net/http.{Server,Transport}.HTTP2Config value, when non-zero.
//   - Otherwise use the http2.{Server.Transport} value.
//   - If the resulting value is zero or out of range, use a default.
type http2http2Config struct {
	MaxConcurrentStreams         uint32
	MaxDecoderHeaderTableSize    uint32
	MaxEncoderHeaderTableSize    uint32
	MaxReadFrameSize             uint32
	MaxUploadBufferPerConnection int32
	MaxUploadBufferPerStream     int32
	SendPingTimeout              time.Duration
	PingTimeout                  time.Duration
	WriteByteTimeout             time.Duration
	PermitProhibitedCipherSuites bool
	CountError                   func(errType string)
}

// configFromServer merges configuration settings from
// net/http.Server.HTTP2Config and http2.Server.
func http2configFromServer(h1 *Server, h2 *http2Server) http2http2Config {
	conf := http2http2Config{
		MaxConcurrentStreams:         h2.MaxConcurrentStreams,
		MaxEncoderHeaderTableSize:    h2.MaxEncoderHeaderTableSize,
		MaxDecoderHeaderTableSize:    h2.MaxDecoderHeaderTableSize,
		MaxReadFrameSize:             h2.MaxReadFrameSize,
		MaxUploadBufferPerConnection: h2.MaxUploadBufferPerConnection,
		MaxUploadBufferPerStream:     h2.MaxUploadBufferPerStream,
		SendPingTimeout:              h2.ReadIdleTimeout,
		PingTimeout:                  h2.PingTimeout,
		WriteByteTimeout:             h2.WriteByteTimeout,
		PermitProhibitedCipherSuites: h2.PermitProhibitedCipherSuites,
		CountError:                   h2.CountError,
	}
	http2fillNetHTTPServerConfig(&conf, h1)
	http2setConfigDefaults(&conf, true)
	return conf
}

// configFromServer merges configuration settings from h2 and h2.t1.HTTP2
// (the net/http Transport).
func http2configFromTransport(h2 *http2Transport) http2http2Config {
	conf := http2http2Config{
		MaxEncoderHeaderTableSize: h2.MaxEncoderHeaderTableSize,
		MaxDecoderHeaderTableSize: h2.MaxDecoderHeaderTableSize,
		MaxReadFrameSize:          h2.MaxReadFrameSize,
		SendPingTimeout:           h2.ReadIdleTimeout,
		PingTimeout:               h2.PingTimeout,
		WriteByteTimeout:          h2.WriteByteTimeout,
	}

	// Unlike most config fields, where out-of-range values revert to the default,
	// Transport.MaxReadFrameSize clips.
	if conf.MaxReadFrameSize < http2minMaxFrameSize {
		conf.MaxReadFrameSize = http2minMaxFrameSize
	} else if conf.MaxReadFrameSize > http2maxFrameSize {
		conf.MaxReadFrameSize = http2maxFrameSize
	}

	if h2.t1 != nil {
		http2fillNetHTTPTransportConfig(&conf, h2.t1)
	}
	http2setConfigDefaults(&conf, false)
	return conf
}

func http2setDefault[T ~int | ~int32 | ~uint32 | ~int64](v *T, minval, maxval, defval T) {
	if *v < minval || *v > maxval {
		*v = defval
	}
}

func http2setConfigDefaults(conf *http2http2Config, server bool) {
	http2setDefault(&conf.MaxConcurrentStreams, 1, math.MaxUint32, http2defaultMaxStreams)
	http2setDefault(&conf.MaxEncoderHeaderTableSize, 1, math.MaxUint32, http2initialHeaderTableSize)
	http2setDefault(&conf.MaxDecoderHeaderTableSize, 1, math.MaxUint32, http2initialHeaderTableSize)
	if server {
		http2setDefault(&conf.MaxUploadBufferPerConnection, http2initialWindowSize, math.MaxInt32, 1<<20)
	} else {
		http2setDefault(&conf.MaxUploadBufferPerConnection, http2initialWindowSize, math.MaxInt32, http2transportDefaultConnFlow)
	}
	if server {
		http2setDefault(&conf.MaxUploadBufferPerStream, 1, math.MaxInt32, 1<<20)
	} else {
		http2setDefault(&conf.MaxUploadBufferPerStream, 1, math.MaxInt32, http2transportDefaultStreamFlow)
	}
	http2setDefault(&conf.MaxReadFrameSize, http2minMaxFrameSize, http2maxFrameSize, http2defaultMaxReadFrameSize)
	http2setDefault(&conf.PingTimeout, 1, math.MaxInt64, 15*time.Second)
}

// adjustHTTP1MaxHeaderSize converts a limit in bytes on the size of an HTTP/1 header
// to an HTTP/2 MAX_HEADER_LIST_SIZE value.
func http2adjustHTTP1MaxHeaderSize(n int64) int64 {
	// http2's count is in a slightly different unit and includes 32 bytes per pair.
	// So, take the net/http.Server value and pad it up a bit, assuming 10 headers.
	const perFieldOverhead = 32 // per http2 spec
	const typicalHeaders = 10   // conservative
	return n + typicalHeaders*perFieldOverhead
}

// fillNetHTTPServerConfig sets fields in conf from srv.HTTP2.
func http2fillNetHTTPServerConfig(conf *http2http2Config, srv *Server) {
	http2fillNetHTTPConfig(conf, srv.HTTP2)
}

// fillNetHTTPServerConfig sets fields in conf from tr.HTTP2.
func http2fillNetHTTPTransportConfig(conf *http2http2Config, tr *Transport) {
	http2fillNetHTTPConfig(conf, tr.HTTP2)
}

func http2fillNetHTTPConfig(conf *http2http2Config, h2 *HTTP2Config) {
	if h2 == nil {
		return
	}
	if h2.MaxConcurrentStreams != 0 {
		conf.MaxConcurrentStreams = uint32(h2.MaxConcurrentStreams)
	}
	if h2.MaxEncoderHeaderTableSize != 0 {
		conf.MaxEncoderHeaderTableSize = uint32(h2.MaxEncoderHeaderTableSize)
	}
	if h2.MaxDecoderHeaderTableSize != 0 {
		conf.MaxDecoderHeaderTableSize = uint32(h2.MaxDecoderHeaderTableSize)
	}
	if h2.MaxConcurrentStreams != 0 {
		conf.MaxConcurrentStreams = uint32(h2.MaxConcurrentStreams)
	}
	if h2.MaxReadFrameSize != 0 {
		conf.MaxReadFrameSize = uint32(h2.MaxReadFrameSize)
	}
	if h2.MaxReceiveBufferPerConnection != 0 {
		conf.MaxUploadBufferPerConnection = int32(h2.MaxReceiveBufferPerConnection)
	}
	if h2.MaxReceiveBufferPerStream != 0 {
		conf.MaxUploadBufferPerStream = int32(h2.MaxReceiveBufferPerStream)
	}
	if h2.SendPingTimeout != 0 {
		conf.SendPingTimeout = h2.SendPingTimeout
	}
	if h2.PingTimeout != 0 {
		conf.PingTimeout = h2.PingTimeout
	}
	if h2.WriteByteTimeout != 0 {
		conf.WriteByteTimeout = h2.WriteByteTimeout
	}
	if h2.PermitProhibitedCipherSuites {
		conf.PermitProhibitedCipherSuites = true
	}
	if h2.CountError != nil {
		conf.CountError = h2.CountError
	}
}

// Buffer chunks are allocated from a pool to reduce pressure on GC.
// The maximum wasted space per dataBuffer is 2x the largest size class,
// which happens when the dataBuffer has multiple chunks and there is
// one unread byte in both the first and last chunks. We use a few size
// classes to minimize overheads for servers that typically receive very
// small request bodies.
//
// TODO: Benchmark to determine if the pools are necessary. The GC may have
// improved enough that we can instead allocate chunks like this:
// make([]byte, max(16<<10, expectedBytesRemaining))
var http2dataChunkPools = [...]sync.Pool{
	{New: func() interface{} { return new([1 << 10]byte) }},
	{New: func() interface{} { return new([2 << 10]byte) }},
	{New: func() interface{} { return new([4 << 10]byte) }},
	{New: func() interface{} { return new([8 << 10]byte) }},
	{New: func() interface{} { return new([16 << 10]byte) }},
}

func http2getDataBufferChunk(size int64) []byte {
	switch {
	case size <= 1<<10:
		return http2dataChunkPools[0].Get().(*[1 << 10]byte)[:]
	case size <= 2<<10:
		return http2dataChunkPools[1].Get().(*[2 << 10]byte)[:]
	case size <= 4<<10:
		return http2dataChunkPools[2].Get().(*[4 << 10]byte)[:]
	case size <= 8<<10:
		return http2dataChunkPools[3].Get().(*[8 << 10]byte)[:]
	default:
		return http2dataChunkPools[4].Get().(*[16 << 10]byte)[:]
	}
}

func http2putDataBufferChunk(p []byte) {
	switch len(p) {
	case 1 << 10:
		http2dataChunkPools[0].Put((*[1 << 10]byte)(p))
	case 2 << 10:
		http2dataChunkPools[1].Put((*[2 << 10]byte)(p))
	case 4 << 10:
		http2dataChunkPools[2].Put((*[4 << 10]byte)(p))
	case 8 << 10:
		http2dataChunkPools[3].Put((*[8 << 10]byte)(p))
	case 16 << 10:
		http2dataChunkPools[4].Put((*[16 << 10]byte)(p))
	default:
		panic(fmt.Sprintf("unexpected buffer len=%v", len(p)))
	}
}

// dataBuffer is an io.ReadWriter backed by a list of data chunks.
// Each dataBuffer is used to read DATA frames on a single stream.
// The buffer is divided into chunks so the server can limit the
// total memory used by a single connection without limiting the
// request body size on any single stream.
type http2dataBuffer struct {
	chunks   [][]byte
	r        int   // next byte to read is chunks[0][r]
	w        int   // next byte to write is chunks[len(chunks)-1][w]
	size     int   // total buffered bytes
	expected int64 // we expect at least this many bytes in future Write calls (ignored if <= 0)
}

var http2errReadEmpty = errors.New("read from empty dataBuffer")

// Read copies bytes from the buffer into p.
// It is an error to read when no data is available.
func (b *http2dataBuffer) Read(p []byte) (int, error) {
	if b.size == 0 {
		return 0, http2errReadEmpty
	}
	var ntotal int
	for len(p) > 0 && b.size > 0 {
		readFrom := b.bytesFromFirstChunk()
		n := copy(p, readFrom)
		p = p[n:]
		ntotal += n
		b.r += n
		b.size -= n
		// If the first chunk has been consumed, advance to the next chunk.
		if b.r == len(b.chunks[0]) {
			http2putDataBufferChunk(b.chunks[0])
			end := len(b.chunks) - 1
			copy(b.chunks[:end], b.chunks[1:])
			b.chunks[end] = nil
			b.chunks = b.chunks[:end]
			b.r = 0
		}
	}
	return ntotal, nil
}

func (b *http2dataBuffer) bytesFromFirstChunk() []byte {
	if len(b.chunks) == 1 {
		return b.chunks[0][b.r:b.w]
	}
	return b.chunks[0][b.r:]
}

// Len returns the number of bytes of the unread portion of the buffer.
func (b *http2dataBuffer) Len() int {
	return b.size
}

// Write appends p to the buffer.
func (b *http2dataBuffer) Write(p []byte) (int, error) {
	ntotal := len(p)
	for len(p) > 0 {
		// If the last chunk is empty, allocate a new chunk. Try to allocate
		// enough to fully copy p plus any additional bytes we expect to
		// receive. However, this may allocate less than len(p).
		want := int64(len(p))
		if b.expected > want {
			want = b.expected
		}
		chunk := b.lastChunkOrAlloc(want)
		n := copy(chunk[b.w:], p)
		p = p[n:]
		b.w += n
		b.size += n
		b.expected -= int64(n)
	}
	return ntotal, nil
}

func (b *http2dataBuffer) lastChunkOrAlloc(want int64) []byte {
	if len(b.chunks) != 0 {
		last := b.chunks[len(b.chunks)-1]
		if b.w < len(last) {
			return last
		}
	}
	chunk := http2getDataBufferChunk(want)
	b.chunks = append(b.chunks, chunk)
	b.w = 0
	return chunk
}

// An ErrCode is an unsigned 32-bit error code as defined in the HTTP/2 spec.
type http2ErrCode uint32

const (
	http2ErrCodeNo                 http2ErrCode = 0x0
	http2ErrCodeProtocol           http2ErrCode = 0x1
	http2ErrCodeInternal           http2ErrCode = 0x2
	http2ErrCodeFlowControl        http2ErrCode = 0x3
	http2ErrCodeSettingsTimeout    http2ErrCode = 0x4
	http2ErrCodeStreamClosed       http2ErrCode = 0x5
	http2ErrCodeFrameSize          http2ErrCode = 0x6
	http2ErrCodeRefusedStream      http2ErrCode = 0x7
	http2ErrCodeCancel             http2ErrCode = 0x8
	http2ErrCodeCompression        http2ErrCode = 0x9
	http2ErrCodeConnect            http2ErrCode = 0xa
	http2ErrCodeEnhanceYourCalm    http2ErrCode = 0xb
	http2ErrCodeInadequateSecurity http2ErrCode = 0xc
	http2ErrCodeHTTP11Required     http2ErrCode = 0xd
)

var http2errCodeName = map[http2ErrCode]string{
	http2ErrCodeNo:                 "NO_ERROR",
	http2ErrCodeProtocol:           "PROTOCOL_ERROR",
	http2ErrCodeInternal:           "INTERNAL_ERROR",
	http2ErrCodeFlowControl:        "FLOW_CONTROL_ERROR",
	http2ErrCodeSettingsTimeout:    "SETTINGS_TIMEOUT",
	http2ErrCodeStreamClosed:       "STREAM_CLOSED",
	http2ErrCodeFrameSize:          "FRAME_SIZE_ERROR",
	http2ErrCodeRefusedStream:      "REFUSED_STREAM",
	http2ErrCodeCancel:             "CANCEL",
	http2ErrCodeCompression:        "COMPRESSION_ERROR",
	http2ErrCodeConnect:            "CONNECT_ERROR",
	http2ErrCodeEnhanceYourCalm:    "ENHANCE_YOUR_CALM",
	http2ErrCodeInadequateSecurity: "INADEQUATE_SECURITY",
	http2ErrCodeHTTP11Required:     "HTTP_1_1_REQUIRED",
}

func (e http2ErrCode) String() string {
	if s, ok := http2errCodeName[e]; ok {
		return s
	}
	return fmt.Sprintf("unknown error code 0x%x", uint32(e))
}

func (e http2ErrCode) stringToken() string {
	if s, ok := http2errCodeName[e]; ok {
		return s
	}
	return fmt.Sprintf("ERR_UNKNOWN_%d", uint32(e))
}

// ConnectionError is an error that results in the termination of the
// entire connection.
type http2ConnectionError http2ErrCode

func (e http2ConnectionError) Error() string {
	return fmt.Sprintf("connection error: %s", http2ErrCode(e))
}

// StreamError is an error that only affects one stream within an
// HTTP/2 connection.
type http2StreamError struct {
	StreamID uint32
	Code     http2ErrCode
	Cause    error // optional additional detail
}

// errFromPeer is a sentinel error value for StreamError.Cause to
// indicate that the StreamError was sent from the peer over the wire
// and wasn't locally generated in the Transport.
var http2errFromPeer = errors.New("received from peer")

func http2streamError(id uint32, code http2ErrCode) http2StreamError {
	return http2StreamError{StreamID: id, Code: code}
}

func (e http2StreamError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("stream error: stream ID %d; %v; %v", e.StreamID, e.Code, e.Cause)
	}
	return fmt.Sprintf("stream error: stream ID %d; %v", e.StreamID, e.Code)
}

// 6.9.1 The Flow Control Window
// "If a sender receives a WINDOW_UPDATE that causes a flow control
// window to exceed this maximum it MUST terminate either the stream
// or the connection, as appropriate. For streams, [...]; for the
// connection, a GOAWAY frame with a FLOW_CONTROL_ERROR code."
type http2goAwayFlowError struct{}

func (http2goAwayFlowError) Error() string { return "connection exceeded flow control window size" }

// connError represents an HTTP/2 ConnectionError error code, along
// with a string (for debugging) explaining why.
//
// Errors of this type are only returned by the frame parser functions
// and converted into ConnectionError(Code), after stashing away
// the Reason into the Framer's errDetail field, accessible via
// the (*Framer).ErrorDetail method.
type http2connError struct {
	Code   http2ErrCode // the ConnectionError error code
	Reason string       // additional reason
}

func (e http2connError) Error() string {
	return fmt.Sprintf("http2: connection error: %v: %v", e.Code, e.Reason)
}

type http2pseudoHeaderError string

func (e http2pseudoHeaderError) Error() string {
	return fmt.Sprintf("invalid pseudo-header %q", string(e))
}

type http2duplicatePseudoHeaderError string

func (e http2duplicatePseudoHeaderError) Error() string {
	return fmt.Sprintf("duplicate pseudo-header %q", string(e))
}

type http2headerFieldNameError string

func (e http2headerFieldNameError) Error() string {
	return fmt.Sprintf("invalid header field name %q", string(e))
}

type http2headerFieldValueError string

func (e http2headerFieldValueError) Error() string {
	return fmt.Sprintf("invalid header field value for %q", string(e))
}

var (
	http2errMixPseudoHeaderTypes = errors.New("mix of request and response pseudo headers")
	http2errPseudoAfterRegular   = errors.New("pseudo header field after regular")
)

// inflowMinRefresh is the minimum number of bytes we'll send for a
// flow control window update.
const http2inflowMinRefresh = 4 << 10

// inflow accounts for an inbound flow control window.
// It tracks both the latest window sent to the peer (used for enforcement)
// and the accumulated unsent window.
type http2inflow struct {
	avail  int32
	unsent int32
}

// init sets the initial window.
func (f *http2inflow) init(n int32) {
	f.avail = n
}

// add adds n bytes to the window, with a maximum window size of max,
// indicating that the peer can now send us more data.
// For example, the user read from a {Request,Response} body and consumed
// some of the buffered data, so the peer can now send more.
// It returns the number of bytes to send in a WINDOW_UPDATE frame to the peer.
// Window updates are accumulated and sent when the unsent capacity
// is at least inflowMinRefresh or will at least double the peer's available window.
func (f *http2inflow) add(n int) (connAdd int32) {
	if n < 0 {
		panic("negative update")
	}
	unsent := int64(f.unsent) + int64(n)
	//
```