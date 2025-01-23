Response:
Let's break down the thought process for analyzing this Go code.

**1. Understanding the Request:**

The request asks for the functionality of a Go file (`go/src/net/http/example_test.go`), including inferring the Go features it demonstrates, providing code examples, discussing command-line arguments (if applicable), and highlighting potential pitfalls for users. The answer should be in Chinese.

**2. Initial Skim and Categorization:**

The first step is to quickly skim through the code and identify the different `Example` functions. Each `Example` function typically showcases a specific feature of the `net/http` package. I'd mentally (or physically) group them:

* **Connection Handling:** `ExampleHijacker`
* **Requesting Resources:** `ExampleGet`
* **Serving Static Files:** `ExampleFileServer`, `ExampleFileServer_stripPrefix`, `ExampleStripPrefix`
* **Routing and Handling:** `ExampleServeMux_Handle`, `ExampleHandleFunc`, `ExampleNotFoundHandler`
* **Response Manipulation:** `ExampleResponseWriter_trailers`
* **Server Lifecycle:** `ExampleServer_Shutdown`
* **Secure Connections:** `ExampleListenAndServeTLS`
* **Basic Server:** `ExampleListenAndServe`
* **Protocol Negotiation:** `ExampleProtocols_http1`, `ExampleProtocols_http1or2`
* **Custom Handlers:** `newPeopleHandler` (though it's used in `ExampleNotFoundHandler`)

**3. Analyzing Each Example Individually:**

For each `Example` function, I'd perform the following steps:

* **Identify the core functionality:** What is the main purpose of this example?  What `net/http` functions or types are being used?
* **Explain the functionality in Chinese:**  Clearly and concisely describe what the code does. Use relevant technical terms.
* **Infer the Go feature demonstrated:** Connect the example to a specific Go concept or `net/http` functionality (e.g., HTTP hijacking, file serving, request routing, TLS, etc.).
* **Provide a simple code example (if needed):**  If the example is self-contained and demonstrates the feature well, I might skip creating an entirely separate example. However, if clarification or a different use case is necessary, I'd create a simplified illustration.
* **Determine input and output (for code inference):**  Think about how the example would be used. What kind of HTTP requests would trigger it? What would the server send back?  This is where "假设的输入与输出" comes in.
* **Check for command-line arguments:** Scan the example for usage of `os.Args` or other mechanisms for handling command-line input. Most of these examples *don't* directly use command-line arguments for their core function, so I'd note that. `ExampleFileServer` is an exception because the directory to serve is hardcoded in the example but could be a command-line argument in a real application.
* **Identify potential user errors:**  Think about common mistakes developers might make when using this feature. For example, forgetting to close the connection in `ExampleHijacker` is a classic pitfall. Not understanding the matching behavior of `ServeMux` is another.
* **Translate and format the answer in Chinese:** Ensure the explanations are clear, grammatically correct, and use appropriate terminology. Use markdown formatting for readability.

**4. Specific Example - `ExampleHijacker` Breakdown:**

Let's illustrate the detailed analysis for `ExampleHijacker`:

* **Skim:**  Sees `http.HandleFunc`, `http.Hijacker`, `conn.Close()`, `bufrw.WriteString`, `bufrw.ReadString`.
* **Core Functionality:** Handles requests to `/hijack` by taking over the underlying TCP connection. It sends a message, reads a response, and sends another message.
* **Go Feature:** HTTP hijacking.
* **Explanation:** Describes the process of hijacking the connection, sending raw TCP data.
* **Code Example (Mental):**  I could imagine a client using `net.Dial` to connect to the server on `/hijack` and then sending and receiving raw TCP data. However, the example itself is pretty illustrative, so I might skip a separate client-side example for brevity in this case.
* **Input/Output:**
    * **Input:** An HTTP GET request to `/hijack`.
    * **Output:** The initial HTTP response headers *before* the hijack, then the raw TCP exchange: "Now we're speaking raw TCP. Say hi: ", the client's input, and "You said: [client input]\nBye.\n".
* **Command-line Arguments:** None directly used.
* **Potential Errors:**  Forgetting `defer conn.Close()`.
* **Chinese Translation:** Translate the findings into clear Chinese, highlighting the key concepts.

**5. Iteration and Refinement:**

After analyzing each example, I'd review the entire answer to ensure consistency, clarity, and accuracy. I would double-check the Chinese translations and formatting.

**Self-Correction/Refinement Example:**

Initially, I might have just said `ExampleFileServer` serves static files. But then I'd refine it to explain that it uses `http.FileServer` and `http.Dir`, and that the path `/usr/share/doc` is hardcoded in the *example* but a real application would likely get this from configuration or command-line arguments. This adds more depth to the explanation. Similarly, for `ExampleServeMux_Handle`, I would emphasize the pattern matching rules of `ServeMux`, particularly the "/" case.

By following this systematic approach, I can effectively analyze the given Go code and provide a comprehensive answer to the user's request.
这段代码是 Go 语言 `net/http` 包的示例代码，用于演示该包的一些核心功能。它包含了多个以 `Example` 开头的函数，每个函数展示了 `net/http` 包中一个特定的用法或特性。

以下是每个 `Example` 函数的功能以及它所演示的 Go 语言特性：

**1. `ExampleHijacker()`**

* **功能:**  演示了如何劫持 HTTP 连接，允许服务器直接操作底层的 TCP 连接，绕过 HTTP 的请求-响应模型。
* **Go 语言特性:**  展示了 `http.ResponseWriter` 接口中的 `http.Hijacker` 接口。通过类型断言，可以获取底层的 `net.Conn` 连接。
* **代码举例:**
   ```go
   package main

   import (
       "bufio"
       "fmt"
       "log"
       "net/http"
   )

   func handler(w http.ResponseWriter, r *http.Request) {
       hj, ok := w.(http.Hijacker)
       if !ok {
           http.Error(w, "webserver doesn't support hijacking", http.StatusInternalServerError)
           return
       }
       conn, bufrw, err := hj.Hijack()
       if err != nil {
           http.Error(w, err.Error(), http.StatusInternalServerError)
           return
       }
       defer conn.Close()
       bufrw.WriteString("Now we're speaking raw TCP. Say hi: \n")
       bufrw.Flush()
       s, err := bufrw.ReadString('\n')
       if err != nil {
           log.Printf("error reading string: %v", err)
           return
       }
       fmt.Fprintf(bufrw, "You said: %q\nBye.\n", s)
       bufrw.Flush()
   }

   func main() {
       http.HandleFunc("/hijack", handler)
       log.Fatal(http.ListenAndServe(":8080", nil))
   }
   ```
   **假设的输入与输出:**
   * **输入 (使用 `nc` 命令连接):** `nc localhost 8080` 后，发送 `GET /hijack HTTP/1.1\r\nHost: localhost:8080\r\n\r\n`
   * **输出 (`nc` 命令的显示):**
     ```
     HTTP/1.1 200 OK
     Date: Tue, 16 May 2023 08:00:00 GMT
     Content-Type: text/plain; charset=utf-8
     Connection: close

     Now we're speaking raw TCP. Say hi:
     你好
     You said: "你好\n"
     Bye.
     ```

**2. `ExampleGet()`**

* **功能:**  演示了如何使用 `http.Get` 函数发起一个 HTTP GET 请求并获取响应。
* **Go 语言特性:**  展示了 `http.Get` 函数的使用，以及如何读取响应体和处理错误。
* **代码举例:**  这段代码本身就是一个很好的例子，无需额外补充。

**3. `ExampleFileServer()`**

* **功能:**  演示了如何使用 `http.FileServer` 提供静态文件服务。
* **Go 语言特性:**  展示了 `http.FileServer` 函数和 `http.Dir` 类型，用于指定文件系统的根目录。
* **代码举例:**  这段代码本身就是一个很好的例子，无需额外补充。
* **命令行参数:**  `http.Dir("/usr/share/doc")`  指定了提供服务的目录。在实际应用中，这个路径可能会通过命令行参数或配置文件来指定。例如，你可以创建一个接受目录路径作为参数的程序：
   ```go
   package main

   import (
       "log"
       "net/http"
       "os"
   )

   func main() {
       if len(os.Args) != 2 {
           log.Fatalf("Usage: %s <directory>", os.Args[0])
       }
       dir := os.Args[1]
       log.Fatal(http.ListenAndServe(":8080", http.FileServer(http.Dir(dir))))
   }
   ```
   **运行:** `go run main.go /path/to/your/files`

**4. `ExampleFileServer_stripPrefix()` 和 `ExampleStripPrefix()`**

* **功能:**  演示了如何使用 `http.StripPrefix` 来去除请求 URL 的前缀，以便 `FileServer` 可以正确地找到文件。
* **Go 语言特性:**  展示了 `http.StripPrefix` 函数，它返回一个 `http.Handler`，该处理器会在将请求传递给下一个处理器之前修改请求的 URL 路径。
* **代码举例:**  这段代码本身就是一个很好的例子，无需额外补充。

**5. `ExampleServeMux_Handle()`**

* **功能:**  演示了如何使用 `http.ServeMux` 手动注册不同的处理器来处理不同的请求路径。
* **Go 语言特性:**  展示了 `http.NewServeMux` 创建多路复用器，以及 `mux.Handle` 函数用于注册处理器。
* **代码举例:**  这段代码本身就是一个很好的例子，无需额外补充。

**6. `ExampleResponseWriter_trailers()`**

* **功能:**  演示了如何在 HTTP 响应中发送 Trailers（尾部）。Trailers 是在响应主体之后发送的头部信息，通常用于在不知道主体长度的情况下发送一些元数据。
* **Go 语言特性:**  展示了 `http.ResponseWriter` 的 `Header().Set("Trailer", ...)` 和 `Header().Add("Trailer", ...)` 方法来声明 Trailers，以及如何在写入响应主体后设置 Trailer 的值。
* **代码举例:**  这段代码本身就是一个很好的例子，无需额外补充。

**7. `ExampleServer_Shutdown()`**

* **功能:**  演示了如何优雅地关闭 HTTP 服务器，等待所有活跃连接处理完毕。
* **Go 语言特性:**  展示了 `http.Server` 类型的 `Shutdown` 方法，它接收一个 `context.Context` 参数，可以设置关闭的超时时间。同时演示了如何监听操作系统信号（如 `SIGINT`）来触发关闭操作。
* **代码举例:**  这段代码本身就是一个很好的例子，无需额外补充。

**8. `ExampleListenAndServeTLS()`**

* **功能:**  演示了如何使用 `http.ListenAndServeTLS` 启动一个支持 TLS (HTTPS) 的服务器。
* **Go 语言特性:**  展示了 `http.ListenAndServeTLS` 函数，需要提供证书文件 (`cert.pem`) 和私钥文件 (`key.pem`) 的路径。
* **代码举例:**  这段代码本身就是一个很好的例子，无需额外补充。

**9. `ExampleListenAndServe()`**

* **功能:**  演示了如何使用 `http.ListenAndServe` 启动一个基本的 HTTP 服务器。
* **Go 语言特性:**  展示了 `http.HandleFunc` 函数用于注册处理特定路径请求的函数，以及 `http.ListenAndServe` 函数启动服务器。
* **代码举例:**  这段代码本身就是一个很好的例子，无需额外补充。

**10. `ExampleHandleFunc()`**

* **功能:**  演示了如何使用 `http.HandleFunc` 注册处理函数来处理不同的 URL 路径。
* **Go 语言特性:**  进一步展示了 `http.HandleFunc` 的用法，可以直接注册函数作为处理器。
* **代码举例:**  这段代码本身就是一个很好的例子，无需额外补充。

**11. `ExampleNotFoundHandler()`**

* **功能:**  演示了如何使用 `http.NotFoundHandler` 来返回 404 错误。
* **Go 语言特性:**  展示了 `http.NotFoundHandler` 函数，它返回一个简单的处理器，当请求的路径没有匹配到任何已注册的处理器时，该处理器会返回 404 状态码。
* **代码举例:**  这段代码本身就是一个很好的例子，无需额外补充。

**12. `ExampleProtocols_http1()` 和 `ExampleProtocols_http1or2()`**

* **功能:**  演示了如何配置 `http.Server` 和 `http.Client` 支持的 HTTP 协议版本（HTTP/1.x 和 HTTP/2）。
* **Go 语言特性:**  展示了 `http.Server` 和 `http.Transport` 的 `Protocols` 字段，可以使用 `http.Protocols` 类型来设置支持的协议。
* **代码举例:**  这段代码本身就是一个很好的例子，无需额外补充。

**使用者易犯错的点:**

* **`ExampleHijacker()`:  忘记关闭连接。**  在劫持连接后，服务器需要负责管理底层的 TCP 连接，包括在完成操作后显式关闭连接 (`conn.Close()`)，否则可能导致资源泄漏。
* **`ExampleFileServer()`:  路径问题。**  `http.Dir` 接收的是文件系统路径，需要确保路径的正确性。初学者可能会混淆 URL 路径和文件系统路径。
* **`ExampleServeMux_Handle()`:  模式匹配的顺序和特性。**  `ServeMux` 的匹配是基于最长前缀匹配的。例如，如果同时注册了 `/` 和 `/api/`，访问 `/api/users` 会匹配到 `/api/` 的处理器。理解这一点很重要，否则可能会导致请求被错误地处理。
* **`ExampleResponseWriter_trailers()`:  在写入头部后才能声明 Trailers。** 必须在调用 `WriteHeader` 或任何导致头部被发送的方法（如第一次调用 `Write`）之前声明 Trailers。并且需要在响应主体发送完成后设置 Trailer 的值。
* **`ExampleServer_Shutdown()`:  没有正确处理关闭错误。**  `srv.Shutdown` 可能返回错误，例如超时错误。需要适当地处理这些错误。
* **`ExampleListenAndServeTLS()`:  证书和私钥的路径错误。**  需要确保 `cert.pem` 和 `key.pem` 文件存在且路径正确。生成证书和私钥也是一个需要注意的步骤。

总而言之，这段代码是学习和理解 Go 语言 `net/http` 包各种特性的绝佳资源。通过这些示例，开发者可以快速上手构建 HTTP 客户端和服务器应用。

### 提示词
```
这是路径为go/src/net/http/example_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package http_test

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
)

func ExampleHijacker() {
	http.HandleFunc("/hijack", func(w http.ResponseWriter, r *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "webserver doesn't support hijacking", http.StatusInternalServerError)
			return
		}
		conn, bufrw, err := hj.Hijack()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		// Don't forget to close the connection:
		defer conn.Close()
		bufrw.WriteString("Now we're speaking raw TCP. Say hi: ")
		bufrw.Flush()
		s, err := bufrw.ReadString('\n')
		if err != nil {
			log.Printf("error reading string: %v", err)
			return
		}
		fmt.Fprintf(bufrw, "You said: %q\nBye.\n", s)
		bufrw.Flush()
	})
}

func ExampleGet() {
	res, err := http.Get("http://www.google.com/robots.txt")
	if err != nil {
		log.Fatal(err)
	}
	body, err := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode > 299 {
		log.Fatalf("Response failed with status code: %d and\nbody: %s\n", res.StatusCode, body)
	}
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s", body)
}

func ExampleFileServer() {
	// Simple static webserver:
	log.Fatal(http.ListenAndServe(":8080", http.FileServer(http.Dir("/usr/share/doc"))))
}

func ExampleFileServer_stripPrefix() {
	// To serve a directory on disk (/tmp) under an alternate URL
	// path (/tmpfiles/), use StripPrefix to modify the request
	// URL's path before the FileServer sees it:
	http.Handle("/tmpfiles/", http.StripPrefix("/tmpfiles/", http.FileServer(http.Dir("/tmp"))))
}

func ExampleStripPrefix() {
	// To serve a directory on disk (/tmp) under an alternate URL
	// path (/tmpfiles/), use StripPrefix to modify the request
	// URL's path before the FileServer sees it:
	http.Handle("/tmpfiles/", http.StripPrefix("/tmpfiles/", http.FileServer(http.Dir("/tmp"))))
}

type apiHandler struct{}

func (apiHandler) ServeHTTP(http.ResponseWriter, *http.Request) {}

func ExampleServeMux_Handle() {
	mux := http.NewServeMux()
	mux.Handle("/api/", apiHandler{})
	mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		// The "/" pattern matches everything, so we need to check
		// that we're at the root here.
		if req.URL.Path != "/" {
			http.NotFound(w, req)
			return
		}
		fmt.Fprintf(w, "Welcome to the home page!")
	})
}

// HTTP Trailers are a set of key/value pairs like headers that come
// after the HTTP response, instead of before.
func ExampleResponseWriter_trailers() {
	mux := http.NewServeMux()
	mux.HandleFunc("/sendstrailers", func(w http.ResponseWriter, req *http.Request) {
		// Before any call to WriteHeader or Write, declare
		// the trailers you will set during the HTTP
		// response. These three headers are actually sent in
		// the trailer.
		w.Header().Set("Trailer", "AtEnd1, AtEnd2")
		w.Header().Add("Trailer", "AtEnd3")

		w.Header().Set("Content-Type", "text/plain; charset=utf-8") // normal header
		w.WriteHeader(http.StatusOK)

		w.Header().Set("AtEnd1", "value 1")
		io.WriteString(w, "This HTTP response has both headers before this text and trailers at the end.\n")
		w.Header().Set("AtEnd2", "value 2")
		w.Header().Set("AtEnd3", "value 3") // These will appear as trailers.
	})
}

func ExampleServer_Shutdown() {
	var srv http.Server

	idleConnsClosed := make(chan struct{})
	go func() {
		sigint := make(chan os.Signal, 1)
		signal.Notify(sigint, os.Interrupt)
		<-sigint

		// We received an interrupt signal, shut down.
		if err := srv.Shutdown(context.Background()); err != nil {
			// Error from closing listeners, or context timeout:
			log.Printf("HTTP server Shutdown: %v", err)
		}
		close(idleConnsClosed)
	}()

	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		// Error starting or closing listener:
		log.Fatalf("HTTP server ListenAndServe: %v", err)
	}

	<-idleConnsClosed
}

func ExampleListenAndServeTLS() {
	http.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		io.WriteString(w, "Hello, TLS!\n")
	})

	// One can use generate_cert.go in crypto/tls to generate cert.pem and key.pem.
	log.Printf("About to listen on 8443. Go to https://127.0.0.1:8443/")
	err := http.ListenAndServeTLS(":8443", "cert.pem", "key.pem", nil)
	log.Fatal(err)
}

func ExampleListenAndServe() {
	// Hello world, the web server

	helloHandler := func(w http.ResponseWriter, req *http.Request) {
		io.WriteString(w, "Hello, world!\n")
	}

	http.HandleFunc("/hello", helloHandler)
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func ExampleHandleFunc() {
	h1 := func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, "Hello from a HandleFunc #1!\n")
	}
	h2 := func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, "Hello from a HandleFunc #2!\n")
	}

	http.HandleFunc("/", h1)
	http.HandleFunc("/endpoint", h2)

	log.Fatal(http.ListenAndServe(":8080", nil))
}

func newPeopleHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "This is the people handler.")
	})
}

func ExampleNotFoundHandler() {
	mux := http.NewServeMux()

	// Create sample handler to returns 404
	mux.Handle("/resources", http.NotFoundHandler())

	// Create sample handler that returns 200
	mux.Handle("/resources/people/", newPeopleHandler())

	log.Fatal(http.ListenAndServe(":8080", mux))
}

func ExampleProtocols_http1() {
	srv := http.Server{
		Addr: ":8443",
	}

	// Serve only HTTP/1.
	srv.Protocols = new(http.Protocols)
	srv.Protocols.SetHTTP1(true)

	log.Fatal(srv.ListenAndServeTLS("cert.pem", "key.pem"))
}

func ExampleProtocols_http1or2() {
	t := http.DefaultTransport.(*http.Transport).Clone()

	// Use either HTTP/1 and HTTP/2.
	t.Protocols = new(http.Protocols)
	t.Protocols.SetHTTP1(true)
	t.Protocols.SetHTTP2(true)

	cli := &http.Client{Transport: t}
	res, err := cli.Get("http://www.google.com/robots.txt")
	if err != nil {
		log.Fatal(err)
	}
	res.Body.Close()
}
```