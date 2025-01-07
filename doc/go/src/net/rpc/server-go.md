Response:
Let's break down the thought process for answering the request about `go/src/net/rpc/server.go`.

**1. Understanding the Core Request:**

The request asks for the functionalities of the provided Go code snippet, focusing on `net/rpc/server.go`. It also asks for examples, code inference, command-line argument handling (though this specific snippet doesn't directly handle them), common mistakes, and all in Chinese.

**2. Initial Reading and High-Level Understanding:**

The first step is to read through the code and the accompanying comments. The comments are very informative and provide a good overview of the `rpc` package's purpose: enabling remote procedure calls over a network. Key concepts that emerge are:

* **Server Registration:**  The ability to register objects, making their methods callable remotely.
* **Method Requirements:**  Specific criteria for methods to be exposed (exported, argument types, return type).
* **Codecs:**  The use of `encoding/gob` by default for data serialization.
* **Connection Handling:**  `ServeConn`, `ServeCodec`, `Accept` for managing connections.
* **HTTP Support:**  `ServeHTTP`, `HandleHTTP` for handling RPC over HTTP.
* **Request/Response Structure:** The `Request` and `Response` structs.

**3. Categorizing Functionalities:**

To organize the answer, I mentally categorize the functionalities:

* **Core RPC Mechanics:**  Registration, method discovery, request processing, response sending.
* **Connection Management:**  Handling individual connections, accepting new connections.
* **HTTP Integration:**  Specific functionalities for using RPC over HTTP.
* **Data Handling:**  Serialization and deserialization (though the provided snippet focuses on the server side).
* **Internal Structures:**  Understanding the `Server`, `service`, and `methodType` structs.

**4. Detailing Each Functionality:**

For each category, I go through the code and comments to extract specific functionalities.

* **Server Creation:**  `NewServer()`.
* **Service Registration:** `Register()`, `RegisterName()`. I note the validation rules for methods.
* **Request Processing:**  `ServeConn()`, `ServeCodec()`, `ServeRequest()`. I pay attention to how requests are read, dispatched, and responses are sent.
* **Connection Acceptance:** `Accept()`.
* **HTTP Handling:** `ServeHTTP()`, `HandleHTTP()`.
* **Data Encoding/Decoding (Implicit):** While not explicitly in this snippet, the comments mention `encoding/gob`, and `ServerCodec` interface hints at pluggable codecs.
* **Internal Structures:** I explain the purpose of `Server`, `service`, `methodType`, `Request`, and `Response`.

**5. Code Examples and Inference:**

The request asks for code examples to illustrate the functionalities. I choose key examples:

* **Service Registration:** Demonstrating `Register()` with a simple `Arith` service.
* **Serving over TCP:** Showing the basic setup using `net.Listen` and `server.Accept`.
* **Serving over HTTP:**  Illustrating `rpc.HandleHTTP` and `http.ListenAndServe`.

For code inference, the example of method signature requirements is a good choice, as it directly relates to the `suitableMethods` function. I create a plausible scenario and deduce the expected input and output based on the rules.

**6. Command-Line Arguments:**

This specific code snippet doesn't handle command-line arguments directly. It's important to acknowledge this and explain *why* (it's a library, not an executable). I mention that the *application using* this library would handle command-line arguments for things like port numbers.

**7. Common Mistakes:**

I analyze the code and the documented constraints to identify potential pitfalls for users:

* **Incorrect Method Signatures:** This is a frequent source of errors. I provide a clear example.
* **Registering the Same Type Multiple Times:**  Highlighting the error condition.
* **Forgetting to Call `http.Serve()` for HTTP RPC:** A common oversight.

**8. Structuring the Answer (Chinese):**

Since the request is in Chinese, I write the answer in Chinese, using clear and concise language. I organize the answer logically with headings and bullet points for readability. I make sure to translate technical terms accurately.

**9. Review and Refinement:**

After drafting the answer, I review it to ensure accuracy, completeness, and clarity. I double-check the code examples and explanations. I make sure the language is natural and easy to understand for a Chinese speaker familiar with programming concepts. I ensure I have addressed all aspects of the original request.

**Self-Correction/Refinement Example During the Process:**

Initially, I might have focused too much on the low-level details of the `ServerCodec` implementation. However, realizing the request asks for *functionalities*, I shifted the focus to the higher-level actions the server performs (registering, serving, etc.) and only touched upon the codec as the mechanism for data handling. Similarly, I initially considered providing a complex example of a custom codec, but decided against it to keep the explanation focused and avoid unnecessary detail for this particular request. The aim was to provide a comprehensive yet digestible explanation.
这个文件 `go/src/net/rpc/server.go` 是 Go 语言 `net/rpc` 包中关于 RPC 服务端实现的核心部分。它定义了如何注册服务、处理客户端请求以及发送响应。

以下是该文件的主要功能，并附带代码示例和推理：

**1. 定义 RPC 服务端的核心结构 `Server`:**

   - `Server` 结构体负责管理注册的服务、处理请求和维护空闲的请求和响应对象，以提高效率。

   ```go
   type Server struct {
       serviceMap sync.Map   // map[string]*service  存储注册的服务
       reqLock    sync.Mutex // protects freeReq
       freeReq    *Request
       respLock   sync.Mutex // protects freeResp
       freeResp   *Response
   }
   ```

**2. 服务注册 (`Register`, `RegisterName`):**

   - 允许开发者将实现了特定方法的对象注册为 RPC 服务。
   - `Register` 使用接收者（receiver）的实际类型名称作为服务名称。
   - `RegisterName` 允许开发者指定服务名称。
   - 注册时会检查方法是否符合 RPC 调用的规范（导出、两个参数、第二个参数是指针、返回 `error`）。

   ```go
   // 假设我们有以下结构体和方法：
   package main

   import "errors"
   import "net/rpc"
   import "log"
   import "net"

   type Args struct {
       A, B int
   }

   type Quotient struct {
       Quo, Rem int
   }

   type Arith int

   func (t *Arith) Multiply(args *Args, reply *int) error {
       *reply = args.A * args.B
       return nil
   }

   func main() {
       arith := new(Arith)
       err := rpc.Register(arith) // 使用类型名 "Arith" 作为服务名
       if err != nil {
           log.Fatal("注册错误:", err)
       }

       // 或者使用 RegisterName 指定服务名
       // err = rpc.RegisterName("Calculator", arith)
       // if err != nil {
       //     log.Fatal("注册错误:", err)
       // }

       l, err := net.Listen("tcp", ":1234")
       if err != nil {
           log.Fatal("监听错误:", err)
       }
       rpc.Accept(l) // 开始接受连接并处理请求
   }
   ```
   **假设输入：**  客户端调用服务名为 "Arith"，方法为 "Multiply"，参数 `Args{A: 5, B: 3}`。
   **预期输出：** 服务端 `Multiply` 方法执行，`reply` 指针指向的值变为 `15`，返回 `nil`。

**3. 确定可调用的方法 (`suitableMethods`):**

   - `suitableMethods` 函数用于检查给定类型中哪些方法符合 RPC 调用的标准。
   - 它会遍历类型的所有方法，并检查方法的导出性、参数类型和返回类型。

   ```go
   // 代码推理：假设有以下类型
   type MyService struct {}

   func (m *MyService) ValidMethod(arg int, reply *string) error {
       *reply = "Hello"
       return nil
   }

   func (m MyService) InvalidMethod1(arg int, reply *string) error { // 接收者不是指针
       *reply = "Hello"
       return nil
   }

   func (m *MyService) InvalidMethod2(arg int) { // 缺少 reply 参数和 error 返回值
   }

   // 调用 suitableMethods(reflect.TypeOf(MyService{})) 将不会包含 InvalidMethod1 和 InvalidMethod2。
   ```

**4. 处理客户端连接 (`ServeConn`, `ServeCodec`):**

   - `ServeConn` 函数在一个单独的连接上运行 RPC 服务。它使用 `encoding/gob` 编码器/解码器。
   - `ServeCodec` 函数与 `ServeConn` 类似，但允许使用自定义的 `ServerCodec` 进行请求和响应的编解码。
   - 这两个函数都阻塞执行，直到连接关闭。通常在 `go routine` 中调用。

   ```go
   // 代码示例见上面的服务注册部分，`rpc.Accept(l)` 内部会调用 `server.ServeConn(conn)`。
   ```

**5. 处理单个请求 (`ServeRequest`):**

   - `ServeRequest` 函数同步处理一个请求，并且在完成时不关闭 `ServerCodec`。

**6. 读取请求 (`readRequest`, `readRequestHeader`):**

   - `readRequestHeader` 从 `ServerCodec` 读取请求头信息（服务名、方法名、序列号等）。
   - `readRequest` 在读取请求头后，根据请求头中的信息查找对应的服务和方法，并解码请求体中的参数。

**7. 发送响应 (`sendResponse`):**

   - `sendResponse` 函数将处理结果编码并通过 `ServerCodec` 发送回客户端。
   - 如果方法执行过程中发生错误，错误信息也会被编码到响应中。

**8. 调用服务方法 (`service.call`):**

   - `service.call` 函数负责实际调用已注册服务对象的对应方法。
   - 它使用反射来动态调用方法，并将方法的返回值（`error`）通过 `sendResponse` 发送回客户端。

**9. HTTP 支持 (`ServeHTTP`, `HandleHTTP`):**

   - `ServeHTTP` 方法实现了 `http.Handler` 接口，允许 RPC 服务通过 HTTP 进行访问。它只接受 `CONNECT` 方法。
   - `HandleHTTP` 函数注册 HTTP 处理程序，将指定的路径映射到 RPC 服务处理逻辑。默认路径是 `/_goRPC_` 用于 RPC 请求，`/debug/rpc` 用于调试。

   ```go
   // 代码示例：
   package main

   import "net/rpc"
   import "log"
   import "net/http"
   import "net"

   // ... (Args, Quotient, Arith 定义同上)

   func main() {
       arith := new(Arith)
       rpc.Register(arith)
       rpc.HandleHTTP() // 注册 HTTP 处理程序

       l, err := net.Listen("tcp", ":1234")
       if err != nil {
           log.Fatal("监听错误:", err)
       }
       log.Println("等待连接...")
       err = http.Serve(l, nil) // 启动 HTTP 服务
       if err != nil {
           log.Fatal("HTTP 服务错误:", err)
       }
   }
   ```
   **命令行参数:**  `HandleHTTP` 函数本身不直接处理命令行参数。但是，启动 HTTP 服务时，通常需要通过命令行参数指定监听的地址和端口。例如，上面的例子中，端口 `:1234` 是硬编码的，但实际应用中可能会从命令行参数读取。

**10. `ServerCodec` 接口和 `gobServerCodec` 实现:**

    - `ServerCodec` 是一个接口，定义了服务端编解码器的行为，包括读取请求头、读取请求体、写入响应和关闭连接。
    - `gobServerCodec` 是 `ServerCodec` 接口的 `gob` 编码实现。`gob` 是 Go 语言内置的二进制编码方式。

**使用者易犯错的点：**

1. **方法签名不符合规范：** 这是最常见的错误。如果注册的方法不满足两个导出参数（第二个是指针）且返回 `error` 的条件，该方法将不会被注册为 RPC 可调用方法。

   ```go
   type MyService struct {}

   // 错误示例：reply 不是指针
   func (m *MyService) BadMethod(arg int, reply string) error {
       reply = "Error"
       return nil
   }

   // 错误示例：返回值不是 error
   func (m *MyService) AnotherBadMethod(arg int, reply *string) string {
       *reply = "Success"
       return "OK"
   }
   ```
   如果尝试调用 `BadMethod` 或 `AnotherBadMethod`，服务端会返回 "can't find method" 的错误。

2. **尝试注册相同类型的多个服务：**  `rpc.Register` 会检查是否已经注册了相同类型的服务。如果尝试重复注册，会返回错误。

   ```go
   type MyService struct{}
   service1 := new(MyService)
   service2 := new(MyService)

   rpc.Register(service1) // 成功
   err := rpc.Register(service2) // 报错：rpc: service already defined: MyService
   ```

3. **忘记启动 HTTP 服务（当使用 HTTP RPC 时）：**  调用 `rpc.HandleHTTP()` 只是注册了处理程序，还需要调用 `http.Serve()` 或 `http.ListenAndServe()` 来真正启动 HTTP 服务，监听端口并处理请求。

   ```go
   // 错误示例：忘记 http.Serve()
   package main

   import "net/rpc"
   import "log"
   import "net/http"
   import "net"

   type Arith int
   // ... (Multiply 方法定义)

   func main() {
       arith := new(Arith)
       rpc.Register(arith)
       rpc.HandleHTTP()

       l, err := net.Listen("tcp", ":1234")
       if err != nil {
           log.Fatal("监听错误:", err)
       }
       // 缺少 http.Serve(l, nil) 或 http.ListenAndServe(":1234", nil)
       log.Println("等待连接... 但 HTTP 服务未启动") // 客户端无法连接
   }
   ```

总而言之，`go/src/net/rpc/server.go` 文件是 Go RPC 框架服务端的骨干，它负责接收连接、解析请求、调度方法调用并将结果返回给客户端。 理解这个文件的功能对于开发和调试 Go RPC 服务至关重要。

Prompt: 
```
这是路径为go/src/net/rpc/server.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/*
Package rpc provides access to the exported methods of an object across a
network or other I/O connection.  A server registers an object, making it visible
as a service with the name of the type of the object.  After registration, exported
methods of the object will be accessible remotely.  A server may register multiple
objects (services) of different types but it is an error to register multiple
objects of the same type.

Only methods that satisfy these criteria will be made available for remote access;
other methods will be ignored:

  - the method's type is exported.
  - the method is exported.
  - the method has two arguments, both exported (or builtin) types.
  - the method's second argument is a pointer.
  - the method has return type error.

In effect, the method must look schematically like

	func (t *T) MethodName(argType T1, replyType *T2) error

where T1 and T2 can be marshaled by encoding/gob.
These requirements apply even if a different codec is used.
(In the future, these requirements may soften for custom codecs.)

The method's first argument represents the arguments provided by the caller; the
second argument represents the result parameters to be returned to the caller.
The method's return value, if non-nil, is passed back as a string that the client
sees as if created by [errors.New].  If an error is returned, the reply parameter
will not be sent back to the client.

The server may handle requests on a single connection by calling [ServeConn].  More
typically it will create a network listener and call [Accept] or, for an HTTP
listener, [HandleHTTP] and [http.Serve].

A client wishing to use the service establishes a connection and then invokes
[NewClient] on the connection.  The convenience function [Dial] ([DialHTTP]) performs
both steps for a raw network connection (an HTTP connection).  The resulting
[Client] object has two methods, [Call] and Go, that specify the service and method to
call, a pointer containing the arguments, and a pointer to receive the result
parameters.

The Call method waits for the remote call to complete while the Go method
launches the call asynchronously and signals completion using the Call
structure's Done channel.

Unless an explicit codec is set up, package [encoding/gob] is used to
transport the data.

Here is a simple example.  A server wishes to export an object of type Arith:

	package server

	import "errors"

	type Args struct {
		A, B int
	}

	type Quotient struct {
		Quo, Rem int
	}

	type Arith int

	func (t *Arith) Multiply(args *Args, reply *int) error {
		*reply = args.A * args.B
		return nil
	}

	func (t *Arith) Divide(args *Args, quo *Quotient) error {
		if args.B == 0 {
			return errors.New("divide by zero")
		}
		quo.Quo = args.A / args.B
		quo.Rem = args.A % args.B
		return nil
	}

The server calls (for HTTP service):

	arith := new(Arith)
	rpc.Register(arith)
	rpc.HandleHTTP()
	l, err := net.Listen("tcp", ":1234")
	if err != nil {
		log.Fatal("listen error:", err)
	}
	go http.Serve(l, nil)

At this point, clients can see a service "Arith" with methods "Arith.Multiply" and
"Arith.Divide".  To invoke one, a client first dials the server:

	client, err := rpc.DialHTTP("tcp", serverAddress + ":1234")
	if err != nil {
		log.Fatal("dialing:", err)
	}

Then it can make a remote call:

	// Synchronous call
	args := &server.Args{7,8}
	var reply int
	err = client.Call("Arith.Multiply", args, &reply)
	if err != nil {
		log.Fatal("arith error:", err)
	}
	fmt.Printf("Arith: %d*%d=%d", args.A, args.B, reply)

or

	// Asynchronous call
	quotient := new(Quotient)
	divCall := client.Go("Arith.Divide", args, quotient, nil)
	replyCall := <-divCall.Done	// will be equal to divCall
	// check errors, print, etc.

A server implementation will often provide a simple, type-safe wrapper for the
client.

The net/rpc package is frozen and is not accepting new features.
*/
package rpc

import (
	"bufio"
	"encoding/gob"
	"errors"
	"go/token"
	"io"
	"log"
	"net"
	"net/http"
	"reflect"
	"strings"
	"sync"
)

const (
	// Defaults used by HandleHTTP
	DefaultRPCPath   = "/_goRPC_"
	DefaultDebugPath = "/debug/rpc"
)

// Precompute the reflect type for error.
var typeOfError = reflect.TypeFor[error]()

type methodType struct {
	sync.Mutex // protects counters
	method     reflect.Method
	ArgType    reflect.Type
	ReplyType  reflect.Type
	numCalls   uint
}

type service struct {
	name   string                 // name of service
	rcvr   reflect.Value          // receiver of methods for the service
	typ    reflect.Type           // type of the receiver
	method map[string]*methodType // registered methods
}

// Request is a header written before every RPC call. It is used internally
// but documented here as an aid to debugging, such as when analyzing
// network traffic.
type Request struct {
	ServiceMethod string   // format: "Service.Method"
	Seq           uint64   // sequence number chosen by client
	next          *Request // for free list in Server
}

// Response is a header written before every RPC return. It is used internally
// but documented here as an aid to debugging, such as when analyzing
// network traffic.
type Response struct {
	ServiceMethod string    // echoes that of the Request
	Seq           uint64    // echoes that of the request
	Error         string    // error, if any.
	next          *Response // for free list in Server
}

// Server represents an RPC Server.
type Server struct {
	serviceMap sync.Map   // map[string]*service
	reqLock    sync.Mutex // protects freeReq
	freeReq    *Request
	respLock   sync.Mutex // protects freeResp
	freeResp   *Response
}

// NewServer returns a new [Server].
func NewServer() *Server {
	return &Server{}
}

// DefaultServer is the default instance of [*Server].
var DefaultServer = NewServer()

// Is this type exported or a builtin?
func isExportedOrBuiltinType(t reflect.Type) bool {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	// PkgPath will be non-empty even for an exported type,
	// so we need to check the type name as well.
	return token.IsExported(t.Name()) || t.PkgPath() == ""
}

// Register publishes in the server the set of methods of the
// receiver value that satisfy the following conditions:
//   - exported method of exported type
//   - two arguments, both of exported type
//   - the second argument is a pointer
//   - one return value, of type error
//
// It returns an error if the receiver is not an exported type or has
// no suitable methods. It also logs the error using package log.
// The client accesses each method using a string of the form "Type.Method",
// where Type is the receiver's concrete type.
func (server *Server) Register(rcvr any) error {
	return server.register(rcvr, "", false)
}

// RegisterName is like [Register] but uses the provided name for the type
// instead of the receiver's concrete type.
func (server *Server) RegisterName(name string, rcvr any) error {
	return server.register(rcvr, name, true)
}

// logRegisterError specifies whether to log problems during method registration.
// To debug registration, recompile the package with this set to true.
const logRegisterError = false

func (server *Server) register(rcvr any, name string, useName bool) error {
	s := new(service)
	s.typ = reflect.TypeOf(rcvr)
	s.rcvr = reflect.ValueOf(rcvr)
	sname := name
	if !useName {
		sname = reflect.Indirect(s.rcvr).Type().Name()
	}
	if sname == "" {
		s := "rpc.Register: no service name for type " + s.typ.String()
		log.Print(s)
		return errors.New(s)
	}
	if !useName && !token.IsExported(sname) {
		s := "rpc.Register: type " + sname + " is not exported"
		log.Print(s)
		return errors.New(s)
	}
	s.name = sname

	// Install the methods
	s.method = suitableMethods(s.typ, logRegisterError)

	if len(s.method) == 0 {
		str := ""

		// To help the user, see if a pointer receiver would work.
		method := suitableMethods(reflect.PointerTo(s.typ), false)
		if len(method) != 0 {
			str = "rpc.Register: type " + sname + " has no exported methods of suitable type (hint: pass a pointer to value of that type)"
		} else {
			str = "rpc.Register: type " + sname + " has no exported methods of suitable type"
		}
		log.Print(str)
		return errors.New(str)
	}

	if _, dup := server.serviceMap.LoadOrStore(sname, s); dup {
		return errors.New("rpc: service already defined: " + sname)
	}
	return nil
}

// suitableMethods returns suitable Rpc methods of typ. It will log
// errors if logErr is true.
func suitableMethods(typ reflect.Type, logErr bool) map[string]*methodType {
	methods := make(map[string]*methodType)
	for m := 0; m < typ.NumMethod(); m++ {
		method := typ.Method(m)
		mtype := method.Type
		mname := method.Name
		// Method must be exported.
		if !method.IsExported() {
			continue
		}
		// Method needs three ins: receiver, *args, *reply.
		if mtype.NumIn() != 3 {
			if logErr {
				log.Printf("rpc.Register: method %q has %d input parameters; needs exactly three\n", mname, mtype.NumIn())
			}
			continue
		}
		// First arg need not be a pointer.
		argType := mtype.In(1)
		if !isExportedOrBuiltinType(argType) {
			if logErr {
				log.Printf("rpc.Register: argument type of method %q is not exported: %q\n", mname, argType)
			}
			continue
		}
		// Second arg must be a pointer.
		replyType := mtype.In(2)
		if replyType.Kind() != reflect.Pointer {
			if logErr {
				log.Printf("rpc.Register: reply type of method %q is not a pointer: %q\n", mname, replyType)
			}
			continue
		}
		// Reply type must be exported.
		if !isExportedOrBuiltinType(replyType) {
			if logErr {
				log.Printf("rpc.Register: reply type of method %q is not exported: %q\n", mname, replyType)
			}
			continue
		}
		// Method needs one out.
		if mtype.NumOut() != 1 {
			if logErr {
				log.Printf("rpc.Register: method %q has %d output parameters; needs exactly one\n", mname, mtype.NumOut())
			}
			continue
		}
		// The return type of the method must be error.
		if returnType := mtype.Out(0); returnType != typeOfError {
			if logErr {
				log.Printf("rpc.Register: return type of method %q is %q, must be error\n", mname, returnType)
			}
			continue
		}
		methods[mname] = &methodType{method: method, ArgType: argType, ReplyType: replyType}
	}
	return methods
}

// A value sent as a placeholder for the server's response value when the server
// receives an invalid request. It is never decoded by the client since the Response
// contains an error when it is used.
var invalidRequest = struct{}{}

func (server *Server) sendResponse(sending *sync.Mutex, req *Request, reply any, codec ServerCodec, errmsg string) {
	resp := server.getResponse()
	// Encode the response header
	resp.ServiceMethod = req.ServiceMethod
	if errmsg != "" {
		resp.Error = errmsg
		reply = invalidRequest
	}
	resp.Seq = req.Seq
	sending.Lock()
	err := codec.WriteResponse(resp, reply)
	if debugLog && err != nil {
		log.Println("rpc: writing response:", err)
	}
	sending.Unlock()
	server.freeResponse(resp)
}

func (m *methodType) NumCalls() (n uint) {
	m.Lock()
	n = m.numCalls
	m.Unlock()
	return n
}

func (s *service) call(server *Server, sending *sync.Mutex, wg *sync.WaitGroup, mtype *methodType, req *Request, argv, replyv reflect.Value, codec ServerCodec) {
	if wg != nil {
		defer wg.Done()
	}
	mtype.Lock()
	mtype.numCalls++
	mtype.Unlock()
	function := mtype.method.Func
	// Invoke the method, providing a new value for the reply.
	returnValues := function.Call([]reflect.Value{s.rcvr, argv, replyv})
	// The return value for the method is an error.
	errInter := returnValues[0].Interface()
	errmsg := ""
	if errInter != nil {
		errmsg = errInter.(error).Error()
	}
	server.sendResponse(sending, req, replyv.Interface(), codec, errmsg)
	server.freeRequest(req)
}

type gobServerCodec struct {
	rwc    io.ReadWriteCloser
	dec    *gob.Decoder
	enc    *gob.Encoder
	encBuf *bufio.Writer
	closed bool
}

func (c *gobServerCodec) ReadRequestHeader(r *Request) error {
	return c.dec.Decode(r)
}

func (c *gobServerCodec) ReadRequestBody(body any) error {
	return c.dec.Decode(body)
}

func (c *gobServerCodec) WriteResponse(r *Response, body any) (err error) {
	if err = c.enc.Encode(r); err != nil {
		if c.encBuf.Flush() == nil {
			// Gob couldn't encode the header. Should not happen, so if it does,
			// shut down the connection to signal that the connection is broken.
			log.Println("rpc: gob error encoding response:", err)
			c.Close()
		}
		return
	}
	if err = c.enc.Encode(body); err != nil {
		if c.encBuf.Flush() == nil {
			// Was a gob problem encoding the body but the header has been written.
			// Shut down the connection to signal that the connection is broken.
			log.Println("rpc: gob error encoding body:", err)
			c.Close()
		}
		return
	}
	return c.encBuf.Flush()
}

func (c *gobServerCodec) Close() error {
	if c.closed {
		// Only call c.rwc.Close once; otherwise the semantics are undefined.
		return nil
	}
	c.closed = true
	return c.rwc.Close()
}

// ServeConn runs the server on a single connection.
// ServeConn blocks, serving the connection until the client hangs up.
// The caller typically invokes ServeConn in a go statement.
// ServeConn uses the gob wire format (see package gob) on the
// connection. To use an alternate codec, use [ServeCodec].
// See [NewClient]'s comment for information about concurrent access.
func (server *Server) ServeConn(conn io.ReadWriteCloser) {
	buf := bufio.NewWriter(conn)
	srv := &gobServerCodec{
		rwc:    conn,
		dec:    gob.NewDecoder(conn),
		enc:    gob.NewEncoder(buf),
		encBuf: buf,
	}
	server.ServeCodec(srv)
}

// ServeCodec is like [ServeConn] but uses the specified codec to
// decode requests and encode responses.
func (server *Server) ServeCodec(codec ServerCodec) {
	sending := new(sync.Mutex)
	wg := new(sync.WaitGroup)
	for {
		service, mtype, req, argv, replyv, keepReading, err := server.readRequest(codec)
		if err != nil {
			if debugLog && err != io.EOF {
				log.Println("rpc:", err)
			}
			if !keepReading {
				break
			}
			// send a response if we actually managed to read a header.
			if req != nil {
				server.sendResponse(sending, req, invalidRequest, codec, err.Error())
				server.freeRequest(req)
			}
			continue
		}
		wg.Add(1)
		go service.call(server, sending, wg, mtype, req, argv, replyv, codec)
	}
	// We've seen that there are no more requests.
	// Wait for responses to be sent before closing codec.
	wg.Wait()
	codec.Close()
}

// ServeRequest is like [ServeCodec] but synchronously serves a single request.
// It does not close the codec upon completion.
func (server *Server) ServeRequest(codec ServerCodec) error {
	sending := new(sync.Mutex)
	service, mtype, req, argv, replyv, keepReading, err := server.readRequest(codec)
	if err != nil {
		if !keepReading {
			return err
		}
		// send a response if we actually managed to read a header.
		if req != nil {
			server.sendResponse(sending, req, invalidRequest, codec, err.Error())
			server.freeRequest(req)
		}
		return err
	}
	service.call(server, sending, nil, mtype, req, argv, replyv, codec)
	return nil
}

func (server *Server) getRequest() *Request {
	server.reqLock.Lock()
	req := server.freeReq
	if req == nil {
		req = new(Request)
	} else {
		server.freeReq = req.next
		*req = Request{}
	}
	server.reqLock.Unlock()
	return req
}

func (server *Server) freeRequest(req *Request) {
	server.reqLock.Lock()
	req.next = server.freeReq
	server.freeReq = req
	server.reqLock.Unlock()
}

func (server *Server) getResponse() *Response {
	server.respLock.Lock()
	resp := server.freeResp
	if resp == nil {
		resp = new(Response)
	} else {
		server.freeResp = resp.next
		*resp = Response{}
	}
	server.respLock.Unlock()
	return resp
}

func (server *Server) freeResponse(resp *Response) {
	server.respLock.Lock()
	resp.next = server.freeResp
	server.freeResp = resp
	server.respLock.Unlock()
}

func (server *Server) readRequest(codec ServerCodec) (service *service, mtype *methodType, req *Request, argv, replyv reflect.Value, keepReading bool, err error) {
	service, mtype, req, keepReading, err = server.readRequestHeader(codec)
	if err != nil {
		if !keepReading {
			return
		}
		// discard body
		codec.ReadRequestBody(nil)
		return
	}

	// Decode the argument value.
	argIsValue := false // if true, need to indirect before calling.
	if mtype.ArgType.Kind() == reflect.Pointer {
		argv = reflect.New(mtype.ArgType.Elem())
	} else {
		argv = reflect.New(mtype.ArgType)
		argIsValue = true
	}
	// argv guaranteed to be a pointer now.
	if err = codec.ReadRequestBody(argv.Interface()); err != nil {
		return
	}
	if argIsValue {
		argv = argv.Elem()
	}

	replyv = reflect.New(mtype.ReplyType.Elem())

	switch mtype.ReplyType.Elem().Kind() {
	case reflect.Map:
		replyv.Elem().Set(reflect.MakeMap(mtype.ReplyType.Elem()))
	case reflect.Slice:
		replyv.Elem().Set(reflect.MakeSlice(mtype.ReplyType.Elem(), 0, 0))
	}
	return
}

func (server *Server) readRequestHeader(codec ServerCodec) (svc *service, mtype *methodType, req *Request, keepReading bool, err error) {
	// Grab the request header.
	req = server.getRequest()
	err = codec.ReadRequestHeader(req)
	if err != nil {
		req = nil
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return
		}
		err = errors.New("rpc: server cannot decode request: " + err.Error())
		return
	}

	// We read the header successfully. If we see an error now,
	// we can still recover and move on to the next request.
	keepReading = true

	dot := strings.LastIndex(req.ServiceMethod, ".")
	if dot < 0 {
		err = errors.New("rpc: service/method request ill-formed: " + req.ServiceMethod)
		return
	}
	serviceName := req.ServiceMethod[:dot]
	methodName := req.ServiceMethod[dot+1:]

	// Look up the request.
	svci, ok := server.serviceMap.Load(serviceName)
	if !ok {
		err = errors.New("rpc: can't find service " + req.ServiceMethod)
		return
	}
	svc = svci.(*service)
	mtype = svc.method[methodName]
	if mtype == nil {
		err = errors.New("rpc: can't find method " + req.ServiceMethod)
	}
	return
}

// Accept accepts connections on the listener and serves requests
// for each incoming connection. Accept blocks until the listener
// returns a non-nil error. The caller typically invokes Accept in a
// go statement.
func (server *Server) Accept(lis net.Listener) {
	for {
		conn, err := lis.Accept()
		if err != nil {
			log.Print("rpc.Serve: accept:", err.Error())
			return
		}
		go server.ServeConn(conn)
	}
}

// Register publishes the receiver's methods in the [DefaultServer].
func Register(rcvr any) error { return DefaultServer.Register(rcvr) }

// RegisterName is like [Register] but uses the provided name for the type
// instead of the receiver's concrete type.
func RegisterName(name string, rcvr any) error {
	return DefaultServer.RegisterName(name, rcvr)
}

// A ServerCodec implements reading of RPC requests and writing of
// RPC responses for the server side of an RPC session.
// The server calls [ServerCodec.ReadRequestHeader] and [ServerCodec.ReadRequestBody] in pairs
// to read requests from the connection, and it calls [ServerCodec.WriteResponse] to
// write a response back. The server calls [ServerCodec.Close] when finished with the
// connection. ReadRequestBody may be called with a nil
// argument to force the body of the request to be read and discarded.
// See [NewClient]'s comment for information about concurrent access.
type ServerCodec interface {
	ReadRequestHeader(*Request) error
	ReadRequestBody(any) error
	WriteResponse(*Response, any) error

	// Close can be called multiple times and must be idempotent.
	Close() error
}

// ServeConn runs the [DefaultServer] on a single connection.
// ServeConn blocks, serving the connection until the client hangs up.
// The caller typically invokes ServeConn in a go statement.
// ServeConn uses the gob wire format (see package gob) on the
// connection. To use an alternate codec, use [ServeCodec].
// See [NewClient]'s comment for information about concurrent access.
func ServeConn(conn io.ReadWriteCloser) {
	DefaultServer.ServeConn(conn)
}

// ServeCodec is like [ServeConn] but uses the specified codec to
// decode requests and encode responses.
func ServeCodec(codec ServerCodec) {
	DefaultServer.ServeCodec(codec)
}

// ServeRequest is like [ServeCodec] but synchronously serves a single request.
// It does not close the codec upon completion.
func ServeRequest(codec ServerCodec) error {
	return DefaultServer.ServeRequest(codec)
}

// Accept accepts connections on the listener and serves requests
// to [DefaultServer] for each incoming connection.
// Accept blocks; the caller typically invokes it in a go statement.
func Accept(lis net.Listener) { DefaultServer.Accept(lis) }

// Can connect to RPC service using HTTP CONNECT to rpcPath.
var connected = "200 Connected to Go RPC"

// ServeHTTP implements an [http.Handler] that answers RPC requests.
func (server *Server) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.Method != "CONNECT" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusMethodNotAllowed)
		io.WriteString(w, "405 must CONNECT\n")
		return
	}
	conn, _, err := w.(http.Hijacker).Hijack()
	if err != nil {
		log.Print("rpc hijacking ", req.RemoteAddr, ": ", err.Error())
		return
	}
	io.WriteString(conn, "HTTP/1.0 "+connected+"\n\n")
	server.ServeConn(conn)
}

// HandleHTTP registers an HTTP handler for RPC messages on rpcPath,
// and a debugging handler on debugPath.
// It is still necessary to invoke [http.Serve](), typically in a go statement.
func (server *Server) HandleHTTP(rpcPath, debugPath string) {
	http.Handle(rpcPath, server)
	http.Handle(debugPath, debugHTTP{server})
}

// HandleHTTP registers an HTTP handler for RPC messages to [DefaultServer]
// on [DefaultRPCPath] and a debugging handler on [DefaultDebugPath].
// It is still necessary to invoke [http.Serve](), typically in a go statement.
func HandleHTTP() {
	DefaultServer.HandleHTTP(DefaultRPCPath, DefaultDebugPath)
}

"""



```