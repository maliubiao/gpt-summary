Response: Let's break down the thought process for analyzing the provided Go code snippet.

**1. Initial Understanding - The Big Picture:**

The first thing I notice is the comment at the very top: "ProgCache implements Cache via JSON messages over stdin/stdout to a child helper process." This immediately tells me the core function of this code: it's a *proxy* or *interface* to an external caching process. Instead of directly implementing caching logic within the `go` command, it delegates that responsibility to another program.

**2. Identifying Key Components and Their Roles:**

I start skimming through the code, looking for important types, fields, and functions.

* **`ProgCache` struct:** This is the central structure. Its fields reveal how the communication with the child process is managed:
    * `cmd`:  Holds the `exec.Cmd` representing the child process.
    * `stdout`, `stdin`:  Handles the communication streams.
    * `bw`, `jenc`: Buffered writer and JSON encoder for sending data.
    * `can`:  A map to store the commands the child process supports. This hints at a protocol negotiation.
    * `fuzzDirCache`:  A separate cache for fuzzing, suggesting a specific use case.
    * Synchronization primitives (`sync.Mutex`, `atomic.Bool`, channels): Indicate concurrent operations and the need for thread safety.
    * `inFlight`: A map to track pending requests, crucial for asynchronous communication.
    * `outputFile`:  A mapping between output IDs and file paths, pointing to where cached data is stored (presumably by the child process).

* **`ProgCmd` type and constants (`cmdGet`, `cmdPut`, `cmdClose`):** These define the set of commands that can be sent to the child process, forming the core of the communication protocol.

* **`ProgRequest` and `ProgResponse` structs:** These are the data structures used for sending and receiving messages. The comments explain their purpose and fields. I pay attention to fields like `ID`, `Command`, `ActionID`, `OutputID`, `Body`, `BodySize`, `KnownCommands`, `Miss`, `DiskPath`, etc.

* **`startCacheProg` function:**  This is clearly responsible for launching the child process and initializing the `ProgCache`. The logic for parsing `GOCACHEPROG` arguments and the initial capability exchange stands out.

* **`readLoop` function:**  This function reads responses from the child process. Its presence confirms asynchronous communication.

* **`send` and `writeToChild` functions:** These handle sending requests to the child, including JSON encoding and handling potential errors.

* **Cache interface methods (`Get`, `Put`, `Close`, `FuzzDir`):**  These are the standard cache operations that `ProgCache` needs to implement. I look for how these operations translate into interactions with the child process (sending `cmdGet`, `cmdPut` requests).

**3. Inferring Functionality and Go Language Features:**

Based on the components, I can infer the following functionality:

* **External Caching:** The primary function is to delegate caching to an external process.
* **Process Management:**  Starting, communicating with, and potentially stopping a child process.
* **JSON-based Protocol:**  Communication uses JSON for structured messages.
* **Asynchronous Communication:** Requests are sent and responses are handled asynchronously using channels.
* **Capability Negotiation:** The initial exchange of `KnownCommands` determines the supported features.
* **Request/Response Handling:**  Each request has a unique ID to match it with the corresponding response.
* **Data Transfer:**  The `Body` field in `ProgRequest` indicates the transfer of data (for `put` operations). Base64 encoding is used for this.
* **Error Handling:**  Errors from the child process are propagated.

The Go features used are evident:

* **`os/exec`:** For running external commands.
* **`io`:** For handling input/output streams.
* **`bufio`:** For buffered writing.
* **`encoding/json`:** For encoding and decoding JSON.
* **`encoding/base64`:** For encoding binary data within JSON.
* **`context`:** For managing the lifecycle of the child process and requests.
* **`sync` and `sync/atomic`:** For concurrency control.
* **Channels (`chan`)**: For asynchronous communication.

**4. Constructing Examples and Explanations:**

Now that I have a good understanding, I can start forming the explanations, examples, and identifying potential pitfalls.

* **Functionality Listing:**  This is a straightforward summarization of the inferences from step 3.

* **Go Language Feature Implementation (Example):**  I choose a relevant function like `Put` and illustrate how it uses the inferred mechanisms: creating a request, sending it, and handling the response. I include the request and response structures to make the example concrete. I also mention the base64 encoding for the body.

* **Code Reasoning (Hypothetical Scenario):** I create a plausible scenario, like a cache miss in `Get`, and trace the execution flow, including the request sent and the expected response. This demonstrates how the code handles different situations.

* **Command-line Arguments:** I focus on how `startCacheProg` parses the `GOCACHEPROG` environment variable and uses `quoted.Split`. I explain the role of the program name and arguments.

* **Common Mistakes:**  I think about potential errors a user implementing or using such a system might make. For instance, a mismatch between the client and server regarding supported commands is a likely scenario, as is the child process exiting unexpectedly. I use the information in the code (like the `can` map and the `readLoop` error handling) to identify these potential problems.

**5. Review and Refinement:**

Finally, I review my explanations and examples for clarity, accuracy, and completeness. I make sure the examples are executable (even if they are conceptual) and the explanations are easy to understand. I double-check that I've addressed all the points raised in the initial prompt. For example, I ensured to mention the deprecated `ObjectID` and the reason for its existence and eventual removal.
好的，让我们来分析一下 `go/src/cmd/go/internal/cache/prog.go` 这个 Go 语言文件的功能。

**主要功能:**

该文件实现了 `ProgCache` 类型，它是一种 `Cache` 接口的实现，其核心功能是将 Go 语言构建过程中的缓存操作委托给一个独立的子进程（helper process）。 这个子进程可以通过标准输入/输出 (stdin/stdout) 与 `go` 命令进行基于 JSON 消息的通信。

**核心思想:**

这种设计允许 `go` 命令使用任何自定义的缓存策略或机制，而无需将这些策略直接集成到 `go` 命令的代码中。 用户可以通过配置 `GOCACHEPROG` 环境变量来指定这个子进程的可执行文件和参数。

**功能点详细说明:**

1. **启动和管理子进程:**
   - `startCacheProg` 函数负责启动通过 `GOCACHEPROG` 环境变量指定的子进程。
   - 它创建子进程的 `exec.Cmd` 对象，并建立与子进程标准输入和输出的管道连接。
   - 它会等待子进程启动，并通过一个初始的 JSON 消息来获取子进程支持的命令列表 (`KnownCommands`)。这是一种版本协商机制。

2. **与子进程进行 JSON 通信:**
   - `ProgCache` 使用 JSON 格式的消息与子进程进行通信。
   - `ProgRequest` 结构体定义了发送给子进程的请求消息格式，包括请求 ID、命令类型 (`ProgCmd`)、ActionID、OutputID、消息体 (`Body`) 等。
   - `ProgResponse` 结构体定义了子进程返回的响应消息格式，包括请求 ID、错误信息、支持的命令列表、缓存命中/未命中信息、数据大小、时间戳、磁盘路径等。
   - `send` 函数负责发送请求消息到子进程并接收响应。
   - `writeToChild` 函数负责将 `ProgRequest` 编码为 JSON 并发送到子进程的标准输入，如果请求包含消息体，还会将消息体进行 Base64 编码后发送。
   - `readLoop` 函数在一个 Goroutine 中运行，不断监听子进程的标准输出，解码 JSON 响应消息，并将响应发送到相应的等待通道。

3. **实现 `Cache` 接口:**
   - `ProgCache` 实现了 `go/src/cmd/go/internal/cache` 包中定义的 `Cache` 接口。这意味着它可以作为 `go` 命令的缓存后端使用。
   - 实现了 `Get` 方法，用于从缓存中获取指定 ActionID 对应的数据。它会向子进程发送一个 `cmdGet` 请求。
   - 实现了 `Put` 方法，用于将指定 ActionID 和数据存储到缓存中。它会向子进程发送一个 `cmdPut` 请求。
   - 实现了 `Close` 方法，用于关闭与子进程的连接，并通知子进程进行清理。
   - 实现了 `FuzzDir` 方法，但目前它直接调用内部 `fuzzDirCache` 的实现，可能在未来需要扩展以支持通过子进程管理 fuzzing 相关的缓存。

4. **处理缓存的 Get 和 Put 操作:**
   - 当调用 `ProgCache` 的 `Get` 方法时，它会创建一个 `ProgRequest`，命令类型为 `cmdGet`，并将 ActionID 发送给子进程。
   - 子进程根据 ActionID 查找缓存，如果找到，则返回包含 `OutputID` 和 `DiskPath` 的 `ProgResponse`。`ProgCache` 会记录 `OutputID` 和对应的磁盘路径。
   - 当调用 `ProgCache` 的 `Put` 方法时，它会创建一个 `ProgRequest`，命令类型为 `cmdPut`，包含 ActionID、OutputID 和要缓存的数据。数据会进行 Base64 编码后发送给子进程。
   - 子进程负责将数据存储到缓存中，并返回包含 `DiskPath` 的 `ProgResponse`。

5. **处理 `Close` 命令:**
   - 当调用 `ProgCache` 的 `Close` 方法时，它会向子进程发送一个 `cmdClose` 请求，允许子进程进行清理操作。
   - 然后，它会关闭与子进程的连接。

**它是什么 Go 语言功能的实现？**

`ProgCache` 是 Go 语言构建缓存功能的一种**可插拔的、基于外部进程**的实现方式。它允许用户使用自定义的缓存策略，而无需修改 `go` 命令的源代码。

**Go 代码示例说明:**

假设我们有一个实现了自定义缓存策略的 Go 程序 `mycacheprog`。该程序监听标准输入，接收 JSON 请求，并根据自己的策略进行缓存操作，然后将结果以 JSON 格式写回标准输出。

`mycacheprog` 的一个简化版本可能如下所示：

```go
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

type ProgCmd string

const (
	cmdGet   = ProgCmd("get")
	cmdPut   = ProgCmd("put")
	cmdClose = ProgCmd("close")
)

type ProgRequest struct {
	ID        int64
	Command   ProgCmd
	ActionID  []byte `json:",omitempty"`
	OutputID  []byte `json:",omitempty"`
	Body      string `json:"-"` // 简化为字符串
	BodySize  int64  `json:",omitempty"`
	ObjectID  []byte `json:",omitempty"`
}

type ProgResponse struct {
	ID            int64
	Err           string `json:",omitempty"`
	KnownCommands []ProgCmd `json:",omitempty"`
	Miss          bool       `json:",omitempty"`
	OutputID      []byte     `json:",omitempty"`
	Size          int64      `json:",omitempty"`
	Time          *time.Time `json:",omitempty"`
	DiskPath      string     `json:",omitempty"`
}

type CacheEntry struct {
	Data     string
	Size     int64
	CreateAt time.Time
}

var (
	cache = make(map[string]CacheEntry)
	mu    sync.Mutex
)

func main() {
	reader := bufio.NewReader(os.Stdin)
	writer := json.NewEncoder(os.Stdout)

	// 发送初始的 capabilities 消息
	writer.Encode(ProgResponse{ID: 0, KnownCommands: []ProgCmd{cmdGet, cmdPut, cmdClose}})

	for {
		var req ProgRequest
		err := json.NewDecoder(reader).Decode(&req)
		if err != nil {
			if err == io.EOF {
				return
			}
			writer.Encode(ProgResponse{ID: req.ID, Err: err.Error()})
			continue
		}

		switch req.Command {
		case cmdGet:
			handleGet(req, writer)
		case cmdPut:
			handlePut(req, writer)
		case cmdClose:
			return
		default:
			writer.Encode(ProgResponse{ID: req.ID, Err: fmt.Sprintf("unknown command: %s", req.Command)})
		}
	}
}

func handleGet(req ProgRequest, writer *json.Encoder) {
	mu.Lock()
	entry, ok := cache[string(req.ActionID)]
	mu.Unlock()

	if ok {
		writer.Encode(ProgResponse{
			ID:       req.ID,
			Miss:     false,
			OutputID: entry.Data[:16], // 简化
			Size:     entry.Size,
			Time:     &entry.CreateAt,
			DiskPath: "/tmp/cached/" + string(req.ActionID), // 模拟磁盘路径
		})
	} else {
		writer.Encode(ProgResponse{ID: req.ID, Miss: true})
	}
}

func handlePut(req ProgRequest, writer *json.Encoder) {
	mu.Lock()
	cache[string(req.ActionID)] = CacheEntry{
		Data:     req.Body,
		Size:     req.BodySize,
		CreateAt: time.Now(),
	}
	mu.Unlock()
	writer.Encode(ProgResponse{ID: req.ID, DiskPath: "/tmp/cached/" + string(req.ActionID)})
}
```

**假设的输入与输出 (针对 `ProgCache` 与 `mycacheprog` 的交互):**

**假设输入 (发送给 `mycacheprog` 的请求):**

```json
{"ID":1,"Command":"get","ActionID":"[1,2,3,4]"}
```

**假设输出 (从 `mycacheprog` 返回的响应 - 缓存未命中):**

```json
{"ID":1,"Miss":true}
```

**假设输入 (发送给 `mycacheprog` 的请求):**

```json
{"ID":2,"Command":"put","ActionID":"[1,2,3,4]","OutputID":"[5,6,7,8]","BodySize":10}
"dGVzdCBkYXRhCg=="
```

**假设输出 (从 `mycacheprog` 返回的响应 - 成功存储):**

```json
{"ID":2,"DiskPath":"/tmp/cached/[1,2,3,4]"}
```

**命令行参数的具体处理:**

`startCacheProg` 函数接收一个字符串 `progAndArgs`，这个字符串来源于环境变量 `GOCACHEPROG`。该函数使用 `cmd/internal/quoted.Split` 函数来解析这个字符串，将其分割成可执行文件名和参数列表。

例如，如果 `GOCACHEPROG` 的值为 `"mycacheprog -v --config /etc/cache.conf"`，则：

- `prog` 将会是 `"mycacheprog"`
- `args` 将会是 `["-v", "--config", "/etc/cache.conf"]`

然后，这些解析后的参数会用于创建 `exec.CommandContext` 对象，以便启动子进程。

**使用者易犯错的点:**

1. **子进程可执行文件不存在或路径错误:** 如果 `GOCACHEPROG` 指定的程序不存在或路径不正确，`go` 命令将无法启动子进程，并会报错。

   **示例:** 假设 `mycacheprog` 不在系统的 PATH 环境变量中，并且用户错误地设置了 `GOCACHEPROG="mycacheprog"`。`go build` 等命令将会失败，并显示类似 "error starting GOCACHEPROG program "mycacheprog": exec: "mycacheprog": executable file not found in $PATH" 的错误信息。

2. **子进程不支持 `go` 命令发送的命令:**  如果子进程在初始的 capabilities 消息中没有声明支持 `go` 命令尝试发送的命令（例如 `get` 或 `put`），`go` 命令将会报错。

   **示例:**  如果 `mycacheprog` 只实现了 `put` 命令，但 `go` 命令尝试执行一个需要 `get` 操作的场景，`ProgCache` 的 `Get` 方法会检查 `c.can[cmdGet]`，如果为 `false`，则会返回一个 `entryNotFoundError` 错误。

3. **子进程的 JSON 消息格式不正确:**  如果子进程发送的 JSON 响应消息格式与 `ProgResponse` 结构体不匹配，`go` 命令在解码 JSON 时会出错，导致构建过程失败。

   **示例:** 如果 `mycacheprog` 在处理 `get` 请求时，错误地将 `Miss` 字段发送为字符串 `"true"` 而不是布尔值 `true`，`go` 命令的 `readLoop` 函数在尝试 `jd.Decode(res)` 时会遇到类型转换错误。

4. **子进程过早退出或崩溃:** 如果子进程在 `go` 命令还在与其通信时意外退出或崩溃，`go` 命令会检测到连接中断，并可能导致构建过程失败。

   **示例:** 如果 `mycacheprog` 在处理一个 `put` 请求时发生 panic 并退出，`ProgCache` 的 `readLoop` 函数会捕获到 `io.EOF` 错误，并可能调用 `base.Fatalf` 终止 `go` 命令。

理解了 `ProgCache` 的工作原理和潜在的错误点，可以帮助开发者更好地利用 `GOCACHEPROG` 功能，或者在遇到相关问题时进行排查。

### 提示词
```
这是路径为go/src/cmd/go/internal/cache/prog.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```go
// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cache

import (
	"bufio"
	"cmd/go/internal/base"
	"cmd/internal/quoted"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"internal/goexperiment"
	"io"
	"log"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"time"
)

// ProgCache implements Cache via JSON messages over stdin/stdout to a child
// helper process which can then implement whatever caching policy/mechanism it
// wants.
//
// See https://github.com/golang/go/issues/59719
type ProgCache struct {
	cmd    *exec.Cmd
	stdout io.ReadCloser  // from the child process
	stdin  io.WriteCloser // to the child process
	bw     *bufio.Writer  // to stdin
	jenc   *json.Encoder  // to bw

	// can are the commands that the child process declared that it supports.
	// This is effectively the versioning mechanism.
	can map[ProgCmd]bool

	// fuzzDirCache is another Cache implementation to use for the FuzzDir
	// method. In practice this is the default GOCACHE disk-based
	// implementation.
	//
	// TODO(bradfitz): maybe this isn't ideal. But we'd need to extend the Cache
	// interface and the fuzzing callers to be less disk-y to do more here.
	fuzzDirCache Cache

	closing      atomic.Bool
	ctx          context.Context    // valid until Close via ctxClose
	ctxCancel    context.CancelFunc // called on Close
	readLoopDone chan struct{}      // closed when readLoop returns

	mu         sync.Mutex // guards following fields
	nextID     int64
	inFlight   map[int64]chan<- *ProgResponse
	outputFile map[OutputID]string // object => abs path on disk

	// writeMu serializes writing to the child process.
	// It must never be held at the same time as mu.
	writeMu sync.Mutex
}

// ProgCmd is a command that can be issued to a child process.
//
// If the interface needs to grow, we can add new commands or new versioned
// commands like "get2".
type ProgCmd string

const (
	cmdGet   = ProgCmd("get")
	cmdPut   = ProgCmd("put")
	cmdClose = ProgCmd("close")
)

// ProgRequest is the JSON-encoded message that's sent from cmd/go to
// the GOCACHEPROG child process over stdin. Each JSON object is on its
// own line. A ProgRequest of Type "put" with BodySize > 0 will be followed
// by a line containing a base64-encoded JSON string literal of the body.
type ProgRequest struct {
	// ID is a unique number per process across all requests.
	// It must be echoed in the ProgResponse from the child.
	ID int64

	// Command is the type of request.
	// The cmd/go tool will only send commands that were declared
	// as supported by the child.
	Command ProgCmd

	// ActionID is non-nil for get and puts.
	ActionID []byte `json:",omitempty"` // or nil if not used

	// OutputID is set for Type "put".
	//
	// Prior to Go 1.24, when GOCACHEPROG was still an experiment, this was
	// accidentally named ObjectID. It was renamed to OutputID in Go 1.24.
	OutputID []byte `json:",omitempty"` // or nil if not used

	// Body is the body for "put" requests. It's sent after the JSON object
	// as a base64-encoded JSON string when BodySize is non-zero.
	// It's sent as a separate JSON value instead of being a struct field
	// send in this JSON object so large values can be streamed in both directions.
	// The base64 string body of a ProgRequest will always be written
	// immediately after the JSON object and a newline.
	Body io.Reader `json:"-"`

	// BodySize is the number of bytes of Body. If zero, the body isn't written.
	BodySize int64 `json:",omitempty"`

	// ObjectID is the accidental spelling of OutputID that was used prior to Go
	// 1.24.
	//
	// Deprecated: use OutputID. This field is only populated temporarily for
	// backwards compatibility with Go 1.23 and earlier when
	// GOEXPERIMENT=gocacheprog is set. It will be removed in Go 1.25.
	ObjectID []byte `json:",omitempty"`
}

// ProgResponse is the JSON response from the child process to cmd/go.
//
// With the exception of the first protocol message that the child writes to its
// stdout with ID==0 and KnownCommands populated, these are only sent in
// response to a ProgRequest from cmd/go.
//
// ProgResponses can be sent in any order. The ID must match the request they're
// replying to.
type ProgResponse struct {
	ID  int64  // that corresponds to ProgRequest; they can be answered out of order
	Err string `json:",omitempty"` // if non-empty, the error

	// KnownCommands is included in the first message that cache helper program
	// writes to stdout on startup (with ID==0). It includes the
	// ProgRequest.Command types that are supported by the program.
	//
	// This lets us extend the protocol gracefully over time (adding "get2",
	// etc), or fail gracefully when needed. It also lets us verify the program
	// wants to be a cache helper.
	KnownCommands []ProgCmd `json:",omitempty"`

	// For Get requests.

	Miss     bool       `json:",omitempty"` // cache miss
	OutputID []byte     `json:",omitempty"`
	Size     int64      `json:",omitempty"` // in bytes
	Time     *time.Time `json:",omitempty"` // an Entry.Time; when the object was added to the docs

	// DiskPath is the absolute path on disk of the ObjectID corresponding
	// a "get" request's ActionID (on cache hit) or a "put" request's
	// provided ObjectID.
	DiskPath string `json:",omitempty"`
}

// startCacheProg starts the prog binary (with optional space-separated flags)
// and returns a Cache implementation that talks to it.
//
// It blocks a few seconds to wait for the child process to successfully start
// and advertise its capabilities.
func startCacheProg(progAndArgs string, fuzzDirCache Cache) Cache {
	if fuzzDirCache == nil {
		panic("missing fuzzDirCache")
	}
	args, err := quoted.Split(progAndArgs)
	if err != nil {
		base.Fatalf("GOCACHEPROG args: %v", err)
	}
	var prog string
	if len(args) > 0 {
		prog = args[0]
		args = args[1:]
	}

	ctx, ctxCancel := context.WithCancel(context.Background())

	cmd := exec.CommandContext(ctx, prog, args...)
	out, err := cmd.StdoutPipe()
	if err != nil {
		base.Fatalf("StdoutPipe to GOCACHEPROG: %v", err)
	}
	in, err := cmd.StdinPipe()
	if err != nil {
		base.Fatalf("StdinPipe to GOCACHEPROG: %v", err)
	}
	cmd.Stderr = os.Stderr
	cmd.Cancel = in.Close

	if err := cmd.Start(); err != nil {
		base.Fatalf("error starting GOCACHEPROG program %q: %v", prog, err)
	}

	pc := &ProgCache{
		ctx:          ctx,
		ctxCancel:    ctxCancel,
		fuzzDirCache: fuzzDirCache,
		cmd:          cmd,
		stdout:       out,
		stdin:        in,
		bw:           bufio.NewWriter(in),
		inFlight:     make(map[int64]chan<- *ProgResponse),
		outputFile:   make(map[OutputID]string),
		readLoopDone: make(chan struct{}),
	}

	// Register our interest in the initial protocol message from the child to
	// us, saying what it can do.
	capResc := make(chan *ProgResponse, 1)
	pc.inFlight[0] = capResc

	pc.jenc = json.NewEncoder(pc.bw)
	go pc.readLoop(pc.readLoopDone)

	// Give the child process a few seconds to report its capabilities. This
	// should be instant and not require any slow work by the program.
	timer := time.NewTicker(5 * time.Second)
	defer timer.Stop()
	for {
		select {
		case <-timer.C:
			log.Printf("# still waiting for GOCACHEPROG %v ...", prog)
		case capRes := <-capResc:
			can := map[ProgCmd]bool{}
			for _, cmd := range capRes.KnownCommands {
				can[cmd] = true
			}
			if len(can) == 0 {
				base.Fatalf("GOCACHEPROG %v declared no supported commands", prog)
			}
			pc.can = can
			return pc
		}
	}
}

func (c *ProgCache) readLoop(readLoopDone chan<- struct{}) {
	defer close(readLoopDone)
	jd := json.NewDecoder(c.stdout)
	for {
		res := new(ProgResponse)
		if err := jd.Decode(res); err != nil {
			if c.closing.Load() {
				return // quietly
			}
			if err == io.EOF {
				c.mu.Lock()
				inFlight := len(c.inFlight)
				c.mu.Unlock()
				base.Fatalf("GOCACHEPROG exited pre-Close with %v pending requests", inFlight)
			}
			base.Fatalf("error reading JSON from GOCACHEPROG: %v", err)
		}
		c.mu.Lock()
		ch, ok := c.inFlight[res.ID]
		delete(c.inFlight, res.ID)
		c.mu.Unlock()
		if ok {
			ch <- res
		} else {
			base.Fatalf("GOCACHEPROG sent response for unknown request ID %v", res.ID)
		}
	}
}

func (c *ProgCache) send(ctx context.Context, req *ProgRequest) (*ProgResponse, error) {
	resc := make(chan *ProgResponse, 1)
	if err := c.writeToChild(req, resc); err != nil {
		return nil, err
	}
	select {
	case res := <-resc:
		if res.Err != "" {
			return nil, errors.New(res.Err)
		}
		return res, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (c *ProgCache) writeToChild(req *ProgRequest, resc chan<- *ProgResponse) (err error) {
	c.mu.Lock()
	c.nextID++
	req.ID = c.nextID
	c.inFlight[req.ID] = resc
	c.mu.Unlock()

	defer func() {
		if err != nil {
			c.mu.Lock()
			delete(c.inFlight, req.ID)
			c.mu.Unlock()
		}
	}()

	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	if err := c.jenc.Encode(req); err != nil {
		return err
	}
	if err := c.bw.WriteByte('\n'); err != nil {
		return err
	}
	if req.Body != nil && req.BodySize > 0 {
		if err := c.bw.WriteByte('"'); err != nil {
			return err
		}
		e := base64.NewEncoder(base64.StdEncoding, c.bw)
		wrote, err := io.Copy(e, req.Body)
		if err != nil {
			return err
		}
		if err := e.Close(); err != nil {
			return nil
		}
		if wrote != req.BodySize {
			return fmt.Errorf("short write writing body to GOCACHEPROG for action %x, output %x: wrote %v; expected %v",
				req.ActionID, req.OutputID, wrote, req.BodySize)
		}
		if _, err := c.bw.WriteString("\"\n"); err != nil {
			return err
		}
	}
	if err := c.bw.Flush(); err != nil {
		return err
	}
	return nil
}

func (c *ProgCache) Get(a ActionID) (Entry, error) {
	if !c.can[cmdGet] {
		// They can't do a "get". Maybe they're a write-only cache.
		//
		// TODO(bradfitz,bcmills): figure out the proper error type here. Maybe
		// errors.ErrUnsupported? Is entryNotFoundError even appropriate? There
		// might be places where we rely on the fact that a recent Put can be
		// read through a corresponding Get. Audit callers and check, and document
		// error types on the Cache interface.
		return Entry{}, &entryNotFoundError{}
	}
	res, err := c.send(c.ctx, &ProgRequest{
		Command:  cmdGet,
		ActionID: a[:],
	})
	if err != nil {
		return Entry{}, err // TODO(bradfitz): or entryNotFoundError? Audit callers.
	}
	if res.Miss {
		return Entry{}, &entryNotFoundError{}
	}
	e := Entry{
		Size: res.Size,
	}
	if res.Time != nil {
		e.Time = *res.Time
	} else {
		e.Time = time.Now()
	}
	if res.DiskPath == "" {
		return Entry{}, &entryNotFoundError{errors.New("GOCACHEPROG didn't populate DiskPath on get hit")}
	}
	if copy(e.OutputID[:], res.OutputID) != len(res.OutputID) {
		return Entry{}, &entryNotFoundError{errors.New("incomplete ProgResponse OutputID")}
	}
	c.noteOutputFile(e.OutputID, res.DiskPath)
	return e, nil
}

func (c *ProgCache) noteOutputFile(o OutputID, diskPath string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.outputFile[o] = diskPath
}

func (c *ProgCache) OutputFile(o OutputID) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.outputFile[o]
}

func (c *ProgCache) Put(a ActionID, file io.ReadSeeker) (_ OutputID, size int64, _ error) {
	// Compute output ID.
	h := sha256.New()
	if _, err := file.Seek(0, 0); err != nil {
		return OutputID{}, 0, err
	}
	size, err := io.Copy(h, file)
	if err != nil {
		return OutputID{}, 0, err
	}
	var out OutputID
	h.Sum(out[:0])

	if _, err := file.Seek(0, 0); err != nil {
		return OutputID{}, 0, err
	}

	if !c.can[cmdPut] {
		// Child is a read-only cache. Do nothing.
		return out, size, nil
	}

	// For compatibility with Go 1.23/1.24 GOEXPERIMENT=gocacheprog users, also
	// populate the deprecated ObjectID field. This will be removed in Go 1.25.
	var deprecatedValue []byte
	if goexperiment.CacheProg {
		deprecatedValue = out[:]
	}

	res, err := c.send(c.ctx, &ProgRequest{
		Command:  cmdPut,
		ActionID: a[:],
		OutputID: out[:],
		ObjectID: deprecatedValue, // TODO(bradfitz): remove in Go 1.25
		Body:     file,
		BodySize: size,
	})
	if err != nil {
		return OutputID{}, 0, err
	}
	if res.DiskPath == "" {
		return OutputID{}, 0, errors.New("GOCACHEPROG didn't return DiskPath in put response")
	}
	c.noteOutputFile(out, res.DiskPath)
	return out, size, err
}

func (c *ProgCache) Close() error {
	c.closing.Store(true)
	var err error

	// First write a "close" message to the child so it can exit nicely
	// and clean up if it wants. Only after that exchange do we cancel
	// the context that kills the process.
	if c.can[cmdClose] {
		_, err = c.send(c.ctx, &ProgRequest{Command: cmdClose})
	}
	c.ctxCancel()
	<-c.readLoopDone
	return err
}

func (c *ProgCache) FuzzDir() string {
	// TODO(bradfitz): figure out what to do here. For now just use the
	// disk-based default.
	return c.fuzzDirCache.FuzzDir()
}
```