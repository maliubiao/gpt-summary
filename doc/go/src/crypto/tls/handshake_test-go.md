Response:
我的目标是对给定的 Go 语言代码片段进行功能解释，并尽可能推断其目的和使用方法。以下是我的思考过程：

1. **代码初步浏览和结构理解：**
   - 代码开头有版权声明，表明是 Go 官方 `crypto/tls` 包的一部分。
   - 导入了很多标准库和第三方库，如 `bufio`, `bytes`, `crypto/...`, `encoding/hex`, `errors`, `flag`, `fmt`, `io`, `net`, `os`, `os/exec`, `runtime`, `strconv`, `strings`, `sync`, `testing`, `time`。这些导入暗示了代码可能涉及 TLS 握手测试、文件操作、命令行参数处理、并发控制等。
   - 定义了一些全局变量，如 `update`, `keyFile`, `bogoMode`, `bogoFilter`, `bogoLocalDir`，并且使用了 `flag` 包进行命令行参数解析，这表明该文件很可能是一个可执行的测试文件。
   - 定义了多个函数，如 `runTestAndUpdateIfNeeded`, `checkOpenSSLVersion`, `recordingConn` 相关方法, `parseTestData`, `replayingConn` 相关方法, `tempFile`, `localListener`/`localServer`/`localPipe`, `zeroSource`, `allCipherSuites`, `TestMain`, `runMain`, `testHandshake`, `fromHex`, 以及一些以 `test...Certificate` 和 `test...PrivateKey` 开头的变量。

2. **核心功能推断：**
   - **`runTestAndUpdateIfNeeded` 和 `update` flag：** 函数名和 `update` flag 变量名暗示了该文件具有更新测试数据的能力。当测试失败且设置了 `-update` 标志时，会重新运行测试并生成新的“黄金文件”。
   - **`checkOpenSSLVersion`：**  这个函数检查 OpenSSL 的版本，并且特别提到了需要 OpenSSL 1.1.1 来更新测试数据。这强烈暗示该测试依赖于 OpenSSL 作为 TLS 的参考实现。
   - **`recordingConn` 和 `parseTestData` / `replayingConn`：** `recordingConn` 记录 TLS 连接的流量，`WriteTo` 方法可以将记录的流量写入 Go 代码。`parseTestData` 从文本文件中解析这些记录的流量。`replayingConn` 则模拟一个连接，根据解析出的流量进行回放。这三个结构体和函数构成了一个“录制-回放”的测试框架，用于对比 Go 的 TLS 实现和参考实现（OpenSSL）的行为。
   - **`localListener`, `localServer`, `localPipe`：** 这些结构体和函数创建了一个本地 TCP 连接对，用于测试 TLS 握手。这避免了依赖外部网络环境。
   - **`TestMain` 和 `runMain`：**  这是 Go 语言测试的标准入口点。`TestMain` 处理命令行参数和一些初始化工作，`runMain` 实际运行测试。
   - **`testHandshake`：**  这个函数执行 TLS 握手测试，创建客户端和服务器，进行握手，并交换少量数据。
   - **`fromHex`：** 这是一个辅助函数，将十六进制字符串转换为字节切片。
   - **`test...Certificate` 和 `test...PrivateKey`：** 这些变量存储了用于测试的证书和私钥。

3. **具体 Go 语言功能实现推断：**
   - 该文件主要测试 Go 语言 `crypto/tls` 包中的 TLS 握手功能。
   - 它通过与 OpenSSL 的交互来验证 Go 的 TLS 实现的正确性。
   - 使用“录制-回放”机制，将 OpenSSL 生成的 TLS 握手过程保存下来，然后在后续测试中与 Go 的实现进行对比。
   - 使用 `testing` 包进行单元测试。
   - 使用 `flag` 包处理命令行参数，特别是 `-update` 标志用于更新测试数据。

4. **代码示例 (recordingConn 和 replayingConn)：**
   - **假设输入（`recordingConn`）：** 一个通过 TLS 连接发送和接收数据的 `net.Conn`。
   - **输出（`recordingConn`）：** 通过 `WriteTo` 方法将流量写入到 `io.Writer` 中，例如一个文件。
   - **代码示例（写入文件）:**
     ```go
     conn, _ := net.Dial("tcp", "example.com:443")
     tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
     recConn := &recordingConn{Conn: tlsConn}
     recConn.Handshake()
     recConn.Write([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
     buffer := make([]byte, 1024)
     recConn.Read(buffer)

     file, _ := os.Create("testdata/my_recording.txt")
     recConn.WriteTo(file)
     file.Close()
     ```
   - **假设输入（`replayingConn`）：** 一个包含之前录制流量的 `io.Reader`，例如一个文件。
   - **输出（`replayingConn`）：** 模拟一个 TLS 连接，根据录制的流量进行读写。
   - **代码示例（从文件回放）:**
     ```go
     file, _ := os.Open("testdata/my_recording.txt")
     flows, _ := parseTestData(file)
     replayConn := &replayingConn{t: &testing.T{}, flows: flows, reading: true} // 假设第一个操作是读取
     // 使用 replayConn 进行测试，例如与一个模拟的 TLS 服务器进行交互
     ```

5. **命令行参数处理：**
   - **`-update`:**  如果设置，当测试失败时，会触发更新“黄金文件”的操作。需要配合安装了正确版本的 OpenSSL 使用。
   - **`-keylog`:** 指定一个文件路径，用于记录 TLS 会话密钥。这对于调试 TLS 连接很有用。
   - **`-bogo-mode`:** 启用“bogo shim”模式，可能会忽略其他参数，执行特定的测试。
   - **`-bogo-filter`:** 用于过滤 “bogo” 测试。
   - **`-bogo-local-dir`:** 指定本地 “bogo” 目录，而不是从源代码获取。

6. **易犯错的点：**
   - **更新测试数据时 OpenSSL 版本不正确：**  需要安装并配置 OpenSSL 1.1.1，并且 `openssl` 命令需要在 PATH 环境变量中可访问。错误的版本会导致生成的“黄金文件”与预期不符。
   - **不理解录制-回放机制：**  开发者可能会错误地修改或生成测试数据，导致回放测试失败。测试数据的格式需要严格遵循 `parseTestData` 的解析规则。
   - **忽略 `-update` 标志的作用：** 在修改了 TLS 相关代码后，如果没有使用 `-update` 标志重新生成测试数据，测试将始终失败。

通过以上分析，我对该 Go 语言代码片段的功能有了比较清晰的理解。它主要是一个用于测试 `crypto/tls` 包的工具，通过与 OpenSSL 的交互和录制-回放机制来保证 Go 语言 TLS 实现的正确性。

这段Go语言代码是 `go/src/crypto/tls/handshake_test.go` 文件的一部分，主要用于测试 Go 语言 `crypto/tls` 包中的 TLS 握手过程。它的核心功能是**通过与一个参考实现（通常是 OpenSSL）的交互，录制 TLS 连接的字节流，然后在后续的测试中，使用这些录制的字节流来验证 Go 语言的 TLS 实现是否正确**。

以下是它的具体功能：

1. **参考测试 (Reference Tests):**
   - 它能够运行一个与外部 TLS 参考实现（如 OpenSSL）的连接，并记录连接过程中传输的所有字节。
   - Go 的 TLS 代码在测试时被配置为使用确定性的随机数，这样参考测试的结果就可以在将来完全重现。
   - 这些参考连接的数据被保存在 `testdata` 目录下的文件中。

2. **更新测试数据 (Updating Test Data):**
   - 代码提供了通过运行带有 `-update` 标志的测试来更新这些参考连接数据的功能。
   - 当测试失败且设置了 `-update` 标志时，代码会重新运行失败的测试，并使用参考实现生成新的测试数据文件。
   - 代码会检查 OpenSSL 的版本，确保用于更新测试数据的 OpenSSL 版本是 1.1.1。

3. **录制连接 (Recording Connection):**
   - `recordingConn` 结构体实现了一个 `net.Conn` 接口，它可以记录通过它的所有网络流量。
   - `WriteTo` 方法可以将记录的流量以 Go 源代码的形式写入到一个 `io.Writer` 中，方便存储到测试数据文件中。

4. **解析测试数据 (Parsing Test Data):**
   - `parseTestData` 函数用于读取测试数据文件，并将其中记录的十六进制字节流解析为 `[][]byte` 类型的流量数据。

5. **回放连接 (Replaying Connection):**
   - `replayingConn` 结构体实现了 `net.Conn` 接口，它可以模拟一个预先录制好的 TLS 连接。
   - 在测试中，它会根据预先录制的流量进行读取和写入，用于验证 Go 的 TLS 实现的行为是否与参考实现一致。

6. **本地网络连接 (Local Network Connection):**
   - 代码提供了 `localListener`, `localServer`, `localPipe` 等机制，用于在本地创建 TCP 连接对，用于测试 TLS 握手，避免依赖外部网络。

7. **测试框架集成 (Testing Framework Integration):**
   - 使用 `testing` 包进行单元测试。
   - `runTestAndUpdateIfNeeded` 函数用于管理测试的运行和测试数据的更新。

8. **命令行参数处理 (Command-line Arguments):**
   - `-update`: 布尔标志，用于指示是否在测试失败时更新“黄金文件”（测试数据）。
   - `-keylog`: 字符串，指定用于记录 TLS 会话密钥的文件路径，使用 `KeyLogWriter`。
   - `-bogo-mode`: 布尔标志，启用 “bogo shim” 模式，用于特定的测试目的。
   - `-bogo-filter`: 字符串，用于过滤 “bogo” 测试。
   - `-bogo-local-dir`: 字符串，指定本地 BoGo 目录，而不是从源代码获取。

9. **辅助功能 (Utility Functions):**
   - `tempFile`: 创建包含指定内容的临时文件。
   - `zeroSource`: 提供无限零字节的 `io.Reader`，用于测试中的确定性随机数。
   - `allCipherSuites`: 返回所有支持的密码套件的 ID。
   - `testHandshake`: 执行 TLS 握手测试。
   - `fromHex`: 将十六进制字符串转换为字节切片。

**Go 语言功能实现举例 (recordingConn 和 replayingConn):**

```go
// 假设我们有一个正常的 TLS 连接 conn
conn, err := tls.Dial("tcp", "example.com:443", &tls.Config{InsecureSkipVerify: true})
if err != nil {
    panic(err)
}
defer conn.Close()

// 创建一个 recordingConn 来记录流量
recConn := &recordingConn{Conn: conn}

// 执行一些 TLS 通信
recConn.Write([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
buf := make([]byte, 1024)
recConn.Read(buf)

// 将记录的流量写入到文件
file, err := os.Create("testdata/my_test_data.txt")
if err != nil {
    panic(err)
}
defer file.Close()
recConn.WriteTo(file)

fmt.Println("流量已记录到 testdata/my_test_data.txt")

// ------------------- 分割线 -------------------

// 从文件中解析测试数据
file2, err := os.Open("testdata/my_test_data.txt")
if err != nil {
    panic(err)
}
defer file2.Close()
flows, err := parseTestData(file2)
if err != nil {
    panic(err)
}

// 创建一个 replayingConn 来模拟连接
replayConn := &replayingConn{t: &testing.T{}, flows: flows, reading: true} // 假设第一个操作是读取

// 在测试中使用 replayConn
// ... 例如，将其传递给一个需要 net.Conn 的 TLS 代码进行测试
receivedBuf := make([]byte, 1024)
n, err := replayConn.Read(receivedBuf)
if err != nil && err != io.EOF {
    panic(err)
}
fmt.Printf("回放连接读取了 %d 字节: %s\n", n, string(receivedBuf[:n]))

written := []byte("HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello, World!")
m, err := replayConn.Write(written)
if err != nil {
    panic(err)
}
fmt.Printf("回放连接写入了 %d 字节\n", m)
```

**假设的输入与输出：**

* **`recordingConn` 的输入：** 一个活跃的 TLS 连接。
* **`recordingConn` 的输出：** 通过 `WriteTo` 方法，将记录的 TLS 连接字节流以特定格式写入到一个 `io.Writer` (例如文件)。输出格式如代码中所示，以 `>>> Flow ...` 开头，后跟十六进制表示的字节流。
* **`parseTestData` 的输入：** 一个包含 `recordingConn` 输出的 `io.Reader` (例如文件)。
* **`parseTestData` 的输出：** `[][]byte` 类型的切片，每个元素代表一个 TLS 流量片段。
* **`replayingConn` 的输入：**  通过 `parseTestData` 解析得到的 `[][]byte` 类型的流量数据。
* **`replayingConn` 的输出：**  模拟一个 `net.Conn`，其 `Read` 和 `Write` 操作会根据输入的流量数据进行。

**命令行参数的具体处理：**

* **`-update`:** 当在运行测试时指定 `-update` 标志 (例如 `go test -update`)，并且有测试失败时，`runTestAndUpdateIfNeeded` 函数会检测到这个标志，并重新运行失败的测试，这次会将与参考实现的交互结果保存下来，用于更新 `testdata` 目录下的“黄金文件”。这通常用于更新测试基线，例如在 Go 的 TLS 实现进行了修改之后。
* **`-keylog`:** 当指定 `-keylog` 标志并提供一个文件路径 (例如 `go test -keylog=keylog.txt`) 时，`TestMain` 函数会打开指定的文件，并将其设置为 `testConfig.KeyLogWriter`。这会导致在 TLS 握手过程中生成的会话密钥被写入到指定的文件中。这对于调试 TLS 连接和协议分析非常有用。
* **`-bogo-mode`，`-bogo-filter`，`-bogo-local-dir`:** 这些参数与一个名为 "bogo shim" 的特殊测试模式相关。启用 `-bogo-mode` 后，可能会忽略其他的测试，只运行 "bogo" 相关的测试。`-bogo-filter` 用于筛选要运行的 "bogo" 测试，而 `-bogo-local-dir` 则指定了本地 "bogo" 相关的资源目录。具体 "bogo shim" 的实现细节需要查看代码中 `bogoShim()` 函数的定义。

**使用者易犯错的点：**

* **更新测试数据时 OpenSSL 版本不匹配：**  如果要更新测试数据（使用 `-update` 标志），必须确保系统安装了正确版本的 OpenSSL (通常是 1.1.1) 并且 `openssl` 命令在 PATH 环境变量中可用。如果版本不匹配，生成的测试数据可能不正确，导致后续测试失败。
* **手动修改测试数据文件：**  测试数据文件是由程序自动生成的，手动修改这些文件可能会导致 `parseTestData` 解析失败或 `replayingConn` 的行为不符合预期，从而导致测试失败。
* **不理解 `-update` 标志的作用：**  在修改了 TLS 相关代码后，如果测试失败，应该使用 `-update` 标志重新生成测试数据。如果不这样做，测试会一直因为与旧的测试数据不匹配而失败。

总而言之，这段代码是 Go 语言 `crypto/tls` 包进行详细 TLS 握手测试的关键组成部分，它通过与参考实现的交互和录制-回放机制，确保 Go 语言的 TLS 实现的正确性和健壮性。

### 提示词
```
这是路径为go/src/crypto/tls/handshake_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// TLS reference tests run a connection against a reference implementation
// (OpenSSL) of TLS and record the bytes of the resulting connection. The Go
// code, during a test, is configured with deterministic randomness and so the
// reference test can be reproduced exactly in the future.
//
// In order to save everyone who wishes to run the tests from needing the
// reference implementation installed, the reference connections are saved in
// files in the testdata directory. Thus running the tests involves nothing
// external, but creating and updating them requires the reference
// implementation.
//
// Tests can be updated by running them with the -update flag. This will cause
// the test files for failing tests to be regenerated. Since the reference
// implementation will always generate fresh random numbers, large parts of the
// reference connection will always change.

var (
	update       = flag.Bool("update", false, "update golden files on failure")
	keyFile      = flag.String("keylog", "", "destination file for KeyLogWriter")
	bogoMode     = flag.Bool("bogo-mode", false, "Enabled bogo shim mode, ignore everything else")
	bogoFilter   = flag.String("bogo-filter", "", "BoGo test filter")
	bogoLocalDir = flag.String("bogo-local-dir", "", "Local BoGo to use, instead of fetching from source")
)

func runTestAndUpdateIfNeeded(t *testing.T, name string, run func(t *testing.T, update bool), wait bool) {
	// FIPS mode is non-deterministic and so isn't suited for testing against static test transcripts.
	skipFIPS(t)

	success := t.Run(name, func(t *testing.T) {
		if !*update && !wait {
			t.Parallel()
		}
		run(t, false)
	})

	if !success && *update {
		t.Run(name+"#update", func(t *testing.T) {
			run(t, true)
		})
	}
}

// checkOpenSSLVersion ensures that the version of OpenSSL looks reasonable
// before updating the test data.
func checkOpenSSLVersion() error {
	if !*update {
		return nil
	}

	openssl := exec.Command("openssl", "version")
	output, err := openssl.CombinedOutput()
	if err != nil {
		return err
	}

	version := string(output)
	if strings.HasPrefix(version, "OpenSSL 1.1.1") {
		return nil
	}

	println("***********************************************")
	println("")
	println("You need to build OpenSSL 1.1.1 from source in order")
	println("to update the test data.")
	println("")
	println("Configure it with:")
	println("./Configure enable-weak-ssl-ciphers no-shared")
	println("and then add the apps/ directory at the front of your PATH.")
	println("***********************************************")

	return errors.New("version of OpenSSL does not appear to be suitable for updating test data")
}

// recordingConn is a net.Conn that records the traffic that passes through it.
// WriteTo can be used to produce output that can be later be loaded with
// ParseTestData.
type recordingConn struct {
	net.Conn
	sync.Mutex
	flows   [][]byte
	reading bool
}

func (r *recordingConn) Read(b []byte) (n int, err error) {
	if n, err = r.Conn.Read(b); n == 0 {
		return
	}
	b = b[:n]

	r.Lock()
	defer r.Unlock()

	if l := len(r.flows); l == 0 || !r.reading {
		buf := make([]byte, len(b))
		copy(buf, b)
		r.flows = append(r.flows, buf)
	} else {
		r.flows[l-1] = append(r.flows[l-1], b[:n]...)
	}
	r.reading = true
	return
}

func (r *recordingConn) Write(b []byte) (n int, err error) {
	if n, err = r.Conn.Write(b); n == 0 {
		return
	}
	b = b[:n]

	r.Lock()
	defer r.Unlock()

	if l := len(r.flows); l == 0 || r.reading {
		buf := make([]byte, len(b))
		copy(buf, b)
		r.flows = append(r.flows, buf)
	} else {
		r.flows[l-1] = append(r.flows[l-1], b[:n]...)
	}
	r.reading = false
	return
}

// WriteTo writes Go source code to w that contains the recorded traffic.
func (r *recordingConn) WriteTo(w io.Writer) (int64, error) {
	// TLS always starts with a client to server flow.
	clientToServer := true
	var written int64
	for i, flow := range r.flows {
		source, dest := "client", "server"
		if !clientToServer {
			source, dest = dest, source
		}
		n, err := fmt.Fprintf(w, ">>> Flow %d (%s to %s)\n", i+1, source, dest)
		written += int64(n)
		if err != nil {
			return written, err
		}
		dumper := hex.Dumper(w)
		n, err = dumper.Write(flow)
		written += int64(n)
		if err != nil {
			return written, err
		}
		err = dumper.Close()
		if err != nil {
			return written, err
		}
		clientToServer = !clientToServer
	}
	return written, nil
}

func parseTestData(r io.Reader) (flows [][]byte, err error) {
	var currentFlow []byte

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		// If the line starts with ">>> " then it marks the beginning
		// of a new flow.
		if strings.HasPrefix(line, ">>> ") {
			if len(currentFlow) > 0 || len(flows) > 0 {
				flows = append(flows, currentFlow)
				currentFlow = nil
			}
			continue
		}

		// Otherwise the line is a line of hex dump that looks like:
		// 00000170  fc f5 06 bf (...)  |.....X{&?......!|
		// (Some bytes have been omitted from the middle section.)
		_, after, ok := strings.Cut(line, " ")
		if !ok {
			return nil, errors.New("invalid test data")
		}
		line = after

		before, _, ok := strings.Cut(line, "|")
		if !ok {
			return nil, errors.New("invalid test data")
		}
		line = before

		hexBytes := strings.Fields(line)
		for _, hexByte := range hexBytes {
			val, err := strconv.ParseUint(hexByte, 16, 8)
			if err != nil {
				return nil, errors.New("invalid hex byte in test data: " + err.Error())
			}
			currentFlow = append(currentFlow, byte(val))
		}
	}

	if len(currentFlow) > 0 {
		flows = append(flows, currentFlow)
	}

	return flows, nil
}

// replayingConn is a net.Conn that replays flows recorded by recordingConn.
type replayingConn struct {
	t testing.TB
	sync.Mutex
	flows   [][]byte
	reading bool
}

var _ net.Conn = (*replayingConn)(nil)

func (r *replayingConn) Read(b []byte) (n int, err error) {
	r.Lock()
	defer r.Unlock()

	if !r.reading {
		r.t.Errorf("expected write, got read")
		return 0, fmt.Errorf("recording expected write, got read")
	}

	n = copy(b, r.flows[0])
	r.flows[0] = r.flows[0][n:]
	if len(r.flows[0]) == 0 {
		r.flows = r.flows[1:]
		if len(r.flows) == 0 {
			return n, io.EOF
		} else {
			r.reading = false
		}
	}
	return n, nil
}

func (r *replayingConn) Write(b []byte) (n int, err error) {
	r.Lock()
	defer r.Unlock()

	if r.reading {
		r.t.Errorf("expected read, got write")
		return 0, fmt.Errorf("recording expected read, got write")
	}

	if !bytes.HasPrefix(r.flows[0], b) {
		r.t.Errorf("write mismatch: expected %x, got %x", r.flows[0], b)
		return 0, fmt.Errorf("write mismatch")
	}
	r.flows[0] = r.flows[0][len(b):]
	if len(r.flows[0]) == 0 {
		r.flows = r.flows[1:]
		r.reading = true
	}
	return len(b), nil
}

func (r *replayingConn) Close() error {
	r.Lock()
	defer r.Unlock()

	if len(r.flows) > 0 {
		r.t.Errorf("closed with unfinished flows")
		return fmt.Errorf("unexpected close")
	}
	return nil
}

func (r *replayingConn) LocalAddr() net.Addr                { return nil }
func (r *replayingConn) RemoteAddr() net.Addr               { return nil }
func (r *replayingConn) SetDeadline(t time.Time) error      { return nil }
func (r *replayingConn) SetReadDeadline(t time.Time) error  { return nil }
func (r *replayingConn) SetWriteDeadline(t time.Time) error { return nil }

// tempFile creates a temp file containing contents and returns its path.
func tempFile(contents string) string {
	file, err := os.CreateTemp("", "go-tls-test")
	if err != nil {
		panic("failed to create temp file: " + err.Error())
	}
	path := file.Name()
	file.WriteString(contents)
	file.Close()
	return path
}

// localListener is set up by TestMain and used by localPipe to create Conn
// pairs like net.Pipe, but connected by an actual buffered TCP connection.
var localListener struct {
	mu   sync.Mutex
	addr net.Addr
	ch   chan net.Conn
}

const localFlakes = 0 // change to 1 or 2 to exercise localServer/localPipe handling of mismatches

func localServer(l net.Listener) {
	for n := 0; ; n++ {
		c, err := l.Accept()
		if err != nil {
			return
		}
		if localFlakes == 1 && n%2 == 0 {
			c.Close()
			continue
		}
		localListener.ch <- c
	}
}

var isConnRefused = func(err error) bool { return false }

func localPipe(t testing.TB) (net.Conn, net.Conn) {
	localListener.mu.Lock()
	defer localListener.mu.Unlock()

	addr := localListener.addr

	var err error
Dialing:
	// We expect a rare mismatch, but probably not 5 in a row.
	for i := 0; i < 5; i++ {
		tooSlow := time.NewTimer(1 * time.Second)
		defer tooSlow.Stop()
		var c1 net.Conn
		c1, err = net.Dial(addr.Network(), addr.String())
		if err != nil {
			if runtime.GOOS == "dragonfly" && (isConnRefused(err) || os.IsTimeout(err)) {
				// golang.org/issue/29583: Dragonfly sometimes returns a spurious
				// ECONNREFUSED or ETIMEDOUT.
				<-tooSlow.C
				continue
			}
			t.Fatalf("localPipe: %v", err)
		}
		if localFlakes == 2 && i == 0 {
			c1.Close()
			continue
		}
		for {
			select {
			case <-tooSlow.C:
				t.Logf("localPipe: timeout waiting for %v", c1.LocalAddr())
				c1.Close()
				continue Dialing

			case c2 := <-localListener.ch:
				if c2.RemoteAddr().String() == c1.LocalAddr().String() {
					t.Cleanup(func() { c1.Close() })
					t.Cleanup(func() { c2.Close() })
					return c1, c2
				}
				t.Logf("localPipe: unexpected connection: %v != %v", c2.RemoteAddr(), c1.LocalAddr())
				c2.Close()
			}
		}
	}

	t.Fatalf("localPipe: failed to connect: %v", err)
	panic("unreachable")
}

// zeroSource is an io.Reader that returns an unlimited number of zero bytes.
type zeroSource struct{}

func (zeroSource) Read(b []byte) (n int, err error) {
	clear(b)
	return len(b), nil
}

func allCipherSuites() []uint16 {
	ids := make([]uint16, len(cipherSuites))
	for i, suite := range cipherSuites {
		ids[i] = suite.id
	}

	return ids
}

var testConfig *Config

func TestMain(m *testing.M) {
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage of %s:\n", os.Args)
		flag.PrintDefaults()
		if *bogoMode {
			os.Exit(89)
		}
	}

	flag.Parse()

	if *bogoMode {
		bogoShim()
		os.Exit(0)
	}

	os.Exit(runMain(m))
}

func runMain(m *testing.M) int {
	// Cipher suites preferences change based on the architecture. Force them to
	// the version without AES acceleration for test consistency.
	hasAESGCMHardwareSupport = false

	// Set up localPipe.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		l, err = net.Listen("tcp6", "[::1]:0")
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open local listener: %v", err)
		os.Exit(1)
	}
	localListener.ch = make(chan net.Conn)
	localListener.addr = l.Addr()
	defer l.Close()
	go localServer(l)

	if err := checkOpenSSLVersion(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v", err)
		os.Exit(1)
	}

	testConfig = &Config{
		Time:               func() time.Time { return time.Unix(0, 0) },
		Rand:               zeroSource{},
		Certificates:       make([]Certificate, 2),
		InsecureSkipVerify: true,
		CipherSuites:       allCipherSuites(),
		CurvePreferences:   []CurveID{X25519, CurveP256, CurveP384, CurveP521},
		MinVersion:         VersionTLS10,
		MaxVersion:         VersionTLS13,
	}
	testConfig.Certificates[0].Certificate = [][]byte{testRSACertificate}
	testConfig.Certificates[0].PrivateKey = testRSAPrivateKey
	testConfig.Certificates[1].Certificate = [][]byte{testSNICertificate}
	testConfig.Certificates[1].PrivateKey = testRSAPrivateKey
	testConfig.BuildNameToCertificate()
	if *keyFile != "" {
		f, err := os.OpenFile(*keyFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			panic("failed to open -keylog file: " + err.Error())
		}
		testConfig.KeyLogWriter = f
		defer f.Close()
	}

	return m.Run()
}

func testHandshake(t *testing.T, clientConfig, serverConfig *Config) (serverState, clientState ConnectionState, err error) {
	const sentinel = "SENTINEL\n"
	c, s := localPipe(t)
	errChan := make(chan error, 1)
	go func() {
		cli := Client(c, clientConfig)
		err := cli.Handshake()
		if err != nil {
			errChan <- fmt.Errorf("client: %v", err)
			c.Close()
			return
		}
		defer func() { errChan <- nil }()
		clientState = cli.ConnectionState()
		buf, err := io.ReadAll(cli)
		if err != nil {
			t.Errorf("failed to call cli.Read: %v", err)
		}
		if got := string(buf); got != sentinel {
			t.Errorf("read %q from TLS connection, but expected %q", got, sentinel)
		}
		// We discard the error because after ReadAll returns the server must
		// have already closed the connection. Sending data (the closeNotify
		// alert) can cause a reset, that will make Close return an error.
		cli.Close()
	}()
	server := Server(s, serverConfig)
	err = server.Handshake()
	if err == nil {
		serverState = server.ConnectionState()
		if _, err := io.WriteString(server, sentinel); err != nil {
			t.Errorf("failed to call server.Write: %v", err)
		}
		if err := server.Close(); err != nil {
			t.Errorf("failed to call server.Close: %v", err)
		}
	} else {
		err = fmt.Errorf("server: %v", err)
		s.Close()
	}
	err = errors.Join(err, <-errChan)
	return
}

func fromHex(s string) []byte {
	b, _ := hex.DecodeString(s)
	return b
}

var testRSACertificate = fromHex("3082024b308201b4a003020102020900e8f09d3fe25beaa6300d06092a864886f70d01010b0500301f310b3009060355040a1302476f3110300e06035504031307476f20526f6f74301e170d3136303130313030303030305a170d3235303130313030303030305a301a310b3009060355040a1302476f310b300906035504031302476f30819f300d06092a864886f70d010101050003818d0030818902818100db467d932e12270648bc062821ab7ec4b6a25dfe1e5245887a3647a5080d92425bc281c0be97799840fb4f6d14fd2b138bc2a52e67d8d4099ed62238b74a0b74732bc234f1d193e596d9747bf3589f6c613cc0b041d4d92b2b2423775b1c3bbd755dce2054cfa163871d1e24c4f31d1a508baab61443ed97a77562f414c852d70203010001a38193308190300e0603551d0f0101ff0404030205a0301d0603551d250416301406082b0601050507030106082b06010505070302300c0603551d130101ff0402300030190603551d0e041204109f91161f43433e49a6de6db680d79f60301b0603551d230414301280104813494d137e1631bba301d5acab6e7b30190603551d1104123010820e6578616d706c652e676f6c616e67300d06092a864886f70d01010b0500038181009d30cc402b5b50a061cbbae55358e1ed8328a9581aa938a495a1ac315a1a84663d43d32dd90bf297dfd320643892243a00bccf9c7db74020015faad3166109a276fd13c3cce10c5ceeb18782f16c04ed73bbb343778d0c1cf10fa1d8408361c94c722b9daedb4606064df4c1b33ec0d1bd42d4dbfe3d1360845c21d33be9fae7")

var testRSACertificateIssuer = fromHex("3082021930820182a003020102020900ca5e4e811a965964300d06092a864886f70d01010b0500301f310b3009060355040a1302476f3110300e06035504031307476f20526f6f74301e170d3136303130313030303030305a170d3235303130313030303030305a301f310b3009060355040a1302476f3110300e06035504031307476f20526f6f7430819f300d06092a864886f70d010101050003818d0030818902818100d667b378bb22f34143b6cd2008236abefaf2852adf3ab05e01329e2c14834f5105df3f3073f99dab5442d45ee5f8f57b0111c8cb682fbb719a86944eebfffef3406206d898b8c1b1887797c9c5006547bb8f00e694b7a063f10839f269f2c34fff7a1f4b21fbcd6bfdfb13ac792d1d11f277b5c5b48600992203059f2a8f8cc50203010001a35d305b300e0603551d0f0101ff040403020204301d0603551d250416301406082b0601050507030106082b06010505070302300f0603551d130101ff040530030101ff30190603551d0e041204104813494d137e1631bba301d5acab6e7b300d06092a864886f70d01010b050003818100c1154b4bab5266221f293766ae4138899bd4c5e36b13cee670ceeaa4cbdf4f6679017e2fe649765af545749fe4249418a56bd38a04b81e261f5ce86b8d5c65413156a50d12449554748c59a30c515bc36a59d38bddf51173e899820b282e40aa78c806526fd184fb6b4cf186ec728edffa585440d2b3225325f7ab580e87dd76")

var testRSA2048Certificate = fromHex("30820316308201fea003020102020900e8f09d3fe25beaa6300d06092a864886f70d01010b0500301f310b3009060355040a1302476f3110300e06035504031307476f20526f6f74301e170d3136303130313030303030305a170d3338303130313030303030305a301a310b3009060355040a1302476f310b300906035504031302476f30820122300d06092a864886f70d01010105000382010f003082010a0282010100e0ac47db9ba1b7f98a996c62dc1d248d4ee570544136fe4e911e22fccc0fe2b20982f3c4cdd8f4065c5068c873ca0a768b80dc915edc66541a5f26cdea44e56e411221e2f9927bf4e009fee76dbe0e118dcc13392efd6f42d8eb2fd5bc8f63ac77800c84d3be90c20c321273254b9137ef61f825dad1ec2c5e75aa4be6d3104899bd5ac400da7ab942b4227a3870ae5bb97870aa09a1082fb8e78b944cd7fd1b0c6fb1cce03b5430b12ef9ce2d95e01821766e998df0cc99202a57cf030577bd2dc0ec85a49f203511bb6f0e9f43398ead0958f8d7534c61e81daf4501faaa68d9cbc725b58401900fa48a3e2333b15c88cf0c5cc8f33fb9464f9d5f5768b8f10203010001a35a3058300e0603551d0f0101ff0404030205a0301d0603551d250416301406082b0601050507030106082b06010505070302300c0603551d130101ff0402300030190603551d1104123010820e6578616d706c652e676f6c616e67300d06092a864886f70d01010b050003820101009e83f835e2da08204ee6f8bdca793cf83c7aec175349c1642dfbe9f4d0dcfb1aedb4d0122e16c2ad92e63dd31cce10ca5dd04be48cded0fdc8fea49e891d9d93e778a67d54b619ac167ce7bb0f6000ca00c5677d09df3eb10080134ba32bfe4132d33954dc479cb266288d53d3f43af9c78c0ca59d396498bdc56d4966dc6b7e49081f7f2ae1d704bb9f9effed93c57d3b738da02edff3999e3f1a5dce2b093951947d233d9c6b6a12b4b1611826aa02544980089eebbcf22a1a96bd35a3ddf638578989334a93d5081fab442b4383ba6213b7cdd74110582244a2abd937828b311d8dd69178756db7874293b9810c5c2e833f91d49d283a62caaf359141997f")

var testRSA2048CertificateIssuer = fromHex("308203223082020aa003020102020900ca5e4e811a965964300d06092a864886f70d01010b0500301f310b3009060355040a1302476f3110300e06035504031307476f20526f6f74301e170d3136303130313030303030305a170d3235303130313030303030305a301f310b3009060355040a1302476f3110300e06035504031307476f20526f6f7430820122300d06092a864886f70d01010105000382010f003082010a0282010100b308c1720c7054abe66e1be6f8a11246808215a810e8936e47601f7ec1afeb02ad69a5000959d4e08ebc4455ef90b39616f380b8ff2e76f29942d7e009cf010824fe56f69140ac39b761595255ec2aa35155ca2eea884f57b25f8a52f41f56f65b0197cb6c637f9adfa97d8ac27565449f64e67f8b918646ffd630601b0badd8d38aea421fe413ee94f10ea5874c2fd6d8c1b9febaa5ca0ce759993a232c9c48e52230bbf58777b0c30e07e9e0914133730d844b9887b950d5a17c779ac69de2d9c65d26f1ea46c7dd7ac636af6d77df7c9218f78c7b5f08b025867f343ac66cd43a657ac44bfd7e9d07e95a22ff9a0babf72dcffc66eba0a1d90731f67e3bbd0203010001a361305f300e0603551d0f0101ff040403020204301d0603551d250416301406082b0601050507030106082b06010505070302300f0603551d130101ff040530030101ff301d0603551d0e0416041460145a6ce2e8a15b1b68db9a4752ce8684d6ba2d300d06092a864886f70d01010b050003820101001d342fe0b50a25d57a8b13bc14d0abb1eea7431ee752aa423e1306654183e44e9d48bbf592cd32ce77310fdc4e8bbcd724fc43d2723f454bfe605ff90d38d8c6fe60b36c6f4d2d7e4e79bceeb2484f0565274b0d0c4a8562370677624a4c133e332a9e63d4b47544c14e4908ee8685dd0760ae6f4ab089ede2b0cdc595ecefbee7d8be80d57b2d4e4510b6ceda54d1a5980540214191d81cc89a983da43d4043f8efe97a2e231c5153bded520acce87ec8c64a3408f0eb4c742c4a877e8b5b7b7f72497734a41a95994a7a103262ea6d598d03fd5cb0579ed4702424da8893334c58215bc655d49656aedcd02d18676f45d6b9469ae04b89abe9b358391cce99")

var testRSA2048PrivateKey, _ = x509.ParsePKCS1PrivateKey(fromHex("308204a40201000282010100e0ac47db9ba1b7f98a996c62dc1d248d4ee570544136fe4e911e22fccc0fe2b20982f3c4cdd8f4065c5068c873ca0a768b80dc915edc66541a5f26cdea44e56e411221e2f9927bf4e009fee76dbe0e118dcc13392efd6f42d8eb2fd5bc8f63ac77800c84d3be90c20c321273254b9137ef61f825dad1ec2c5e75aa4be6d3104899bd5ac400da7ab942b4227a3870ae5bb97870aa09a1082fb8e78b944cd7fd1b0c6fb1cce03b5430b12ef9ce2d95e01821766e998df0cc99202a57cf030577bd2dc0ec85a49f203511bb6f0e9f43398ead0958f8d7534c61e81daf4501faaa68d9cbc725b58401900fa48a3e2333b15c88cf0c5cc8f33fb9464f9d5f5768b8f10203010001028201007aac96efca229b199e1bf79a63256677e1c455792bc2a348b2e409a68ea57dda486740430d4290bb885c3f5a741eb567d4f41f7b2098a726f4df4f88cf899edc7c9b31f584dffedece15a7212642c7dbbdd8d806392a183e1fc30af36169c9bab9e528f0bdcd27ad4c8b6a97849da6452c6809de61848db80c3ba3289e785042cdfd46fbfee5f78adcba2927fcd8cbe9dcaa97190457eaa45d77adbe0db820aff0c8511d837ab5b307bad5f85afd2cc70d9659ec58045d97ced1eb7950670ac559449c0305fddefda1bac88d36629a177f65abad182c6470830b39e7f6dbdef4df813ccaef01d5a42d37213b2b9647e2ff56a63e6b6a4b6e8a1567bbfd77042102818100eb66f205e8507c78f7167dbef3ddf02fde6a67bd15152609e9296576e28c79678177145ae98e0a2fee58fdb3d626fb6beae3e0ae0b76bc47d16fcdeb16f0caca8a0902779979382609705ae84514de480c2fb2ddda3049347cc1bde9f1a359747079ef3dce020a3c186c90e63bc20b5489a40d768b1c1c35c679edc5662e18c702818100f454ffff95b126b55cb13b68a3841600fc0bc69ff4064f7ceb122495fa972fdb05ca2fa1c6e2e84432f81c96875ab12226e8ce92ba808c4f6325f27ce058791f05db96e623687d3cfc198e748a07521a8c7ee9e7e8faf95b0985be82b867a49f7d5d50fac3881d2c39dedfdbca3ebe847b859c9864cf7a543e4688f5a60118870281806cee737ac65950704daeebbb8c701c709a54d4f28baa00b33f6137a1bf0e5033d4963d2620c3e8f4eb2fe51eee2f95d3079c31e1784e96ac093fdaa33a376d3032961ebd27990fa192669abab715041385082196461c6813d0d37ac5a25afbcf452937cb7ae438c63c6b28d651bae6b1550c446aa1cefd42e9388d0df6cdc80b02818100cac172c33504923bb494fad8e5c0a9c5dd63244bfe63f238969632b82700a95cd71c2694d887d9f92656d0da75ae640a1441e392cda3f94bb3da7cb4f6335527d2639c809467946e34423cfe26c0d6786398ba20922d1b1a59f79bd5bc937d8040b75c890c13fb298548977a3c05ff71cf535c54f66b5a77684a7e4363a3cb2702818100a4d782f35d5a07f9c1f8f9c378564b220387d1e481cc856b631de7637d8bb77c851db070122050ac230dc6e45edf4523471c717c1cb86a36b2fd3358fae349d51be54d71d7dbeaa6af668323e2b51933f0b8488aa12723e0f32207068b4aa64ed54bcef4acbbbe35b92802faba7ed45ae52bef8313d9ef4393ccc5cf868ddbf8"))

// testRSAPSSCertificate has signatureAlgorithm rsassaPss, but subjectPublicKeyInfo
// algorithm rsaEncryption, for use with the rsa_pss_rsae_* SignatureSchemes.
// See also TestRSAPSSKeyError. testRSAPSSCertificate is self-signed.
var testRSAPSSCertificate = fromHex("308202583082018da003020102021100f29926eb87ea8a0db9fcc247347c11b0304106092a864886f70d01010a3034a00f300d06096086480165030402010500a11c301a06092a864886f70d010108300d06096086480165030402010500a20302012030123110300e060355040a130741636d6520436f301e170d3137313132333136313631305a170d3138313132333136313631305a30123110300e060355040a130741636d6520436f30819f300d06092a864886f70d010101050003818d0030818902818100db467d932e12270648bc062821ab7ec4b6a25dfe1e5245887a3647a5080d92425bc281c0be97799840fb4f6d14fd2b138bc2a52e67d8d4099ed62238b74a0b74732bc234f1d193e596d9747bf3589f6c613cc0b041d4d92b2b2423775b1c3bbd755dce2054cfa163871d1e24c4f31d1a508baab61443ed97a77562f414c852d70203010001a3463044300e0603551d0f0101ff0404030205a030130603551d25040c300a06082b06010505070301300c0603551d130101ff04023000300f0603551d110408300687047f000001304106092a864886f70d01010a3034a00f300d06096086480165030402010500a11c301a06092a864886f70d010108300d06096086480165030402010500a20302012003818100cdac4ef2ce5f8d79881042707f7cbf1b5a8a00ef19154b40151771006cd41626e5496d56da0c1a139fd84695593cb67f87765e18aa03ea067522dd78d2a589b8c92364e12838ce346c6e067b51f1a7e6f4b37ffab13f1411896679d18e880e0ba09e302ac067efca460288e9538122692297ad8093d4f7dd701424d7700a46a1")

var testECDSACertificate = fromHex("3082020030820162020900b8bf2d47a0d2ebf4300906072a8648ce3d04013045310b3009060355040613024155311330110603550408130a536f6d652d53746174653121301f060355040a1318496e7465726e6574205769646769747320507479204c7464301e170d3132313132323135303633325a170d3232313132303135303633325a3045310b3009060355040613024155311330110603550408130a536f6d652d53746174653121301f060355040a1318496e7465726e6574205769646769747320507479204c746430819b301006072a8648ce3d020106052b81040023038186000400c4a1edbe98f90b4873367ec316561122f23d53c33b4d213dcd6b75e6f6b0dc9adf26c1bcb287f072327cb3642f1c90bcea6823107efee325c0483a69e0286dd33700ef0462dd0da09c706283d881d36431aa9e9731bd96b068c09b23de76643f1a5c7fe9120e5858b65f70dd9bd8ead5d7f5d5ccb9b69f30665b669a20e227e5bffe3b300906072a8648ce3d040103818c0030818802420188a24febe245c5487d1bacf5ed989dae4770c05e1bb62fbdf1b64db76140d311a2ceee0b7e927eff769dc33b7ea53fcefa10e259ec472d7cacda4e970e15a06fd00242014dfcbe67139c2d050ebd3fa38c25c13313830d9406bbd4377af6ec7ac9862eddd711697f857c56defb31782be4c7780daecbbe9e4e3624317b6a0f399512078f2a")

var testEd25519Certificate = fromHex("3082012e3081e1a00302010202100f431c425793941de987e4f1ad15005d300506032b657030123110300e060355040a130741636d6520436f301e170d3139303531363231333830315a170d3230303531353231333830315a30123110300e060355040a130741636d6520436f302a300506032b65700321003fe2152ee6e3ef3f4e854a7577a3649eede0bf842ccc92268ffa6f3483aaec8fa34d304b300e0603551d0f0101ff0404030205a030130603551d25040c300a06082b06010505070301300c0603551d130101ff0402300030160603551d11040f300d820b6578616d706c652e636f6d300506032b65700341006344ed9cc4be5324539fd2108d9fe82108909539e50dc155ff2c16b71dfcab7d4dd4e09313d0a942e0b66bfe5d6748d79f50bc6ccd4b03837cf20858cdaccf0c")

var testSNICertificate = fromHex("0441883421114c81480804c430820237308201a0a003020102020900e8f09d3fe25beaa6300d06092a864886f70d01010b0500301f310b3009060355040a1302476f3110300e06035504031307476f20526f6f74301e170d3136303130313030303030305a170d3235303130313030303030305a3023310b3009060355040a1302476f311430120603550403130b736e69746573742e636f6d30819f300d06092a864886f70d010101050003818d0030818902818100db467d932e12270648bc062821ab7ec4b6a25dfe1e5245887a3647a5080d92425bc281c0be97799840fb4f6d14fd2b138bc2a52e67d8d4099ed62238b74a0b74732bc234f1d193e596d9747bf3589f6c613cc0b041d4d92b2b2423775b1c3bbd755dce2054cfa163871d1e24c4f31d1a508baab61443ed97a77562f414c852d70203010001a3773075300e0603551d0f0101ff0404030205a0301d0603551d250416301406082b0601050507030106082b06010505070302300c0603551d130101ff0402300030190603551d0e041204109f91161f43433e49a6de6db680d79f60301b0603551d230414301280104813494d137e1631bba301d5acab6e7b300d06092a864886f70d01010b0500038181007beeecff0230dbb2e7a334af65430b7116e09f327c3bbf918107fc9c66cb497493207ae9b4dbb045cb63d605ec1b5dd485bb69124d68fa298dc776699b47632fd6d73cab57042acb26f083c4087459bc5a3bb3ca4d878d7fe31016b7bc9a627438666566e3389bfaeebe6becc9a0093ceed18d0f9ac79d56f3a73f18188988ed")

var testP256Certificate = fromHex("308201693082010ea00302010202105012dc24e1124ade4f3e153326ff27bf300a06082a8648ce3d04030230123110300e060355040a130741636d6520436f301e170d3137303533313232343934375a170d3138303533313232343934375a30123110300e060355040a130741636d6520436f3059301306072a8648ce3d020106082a8648ce3d03010703420004c02c61c9b16283bbcc14956d886d79b358aa614596975f78cece787146abf74c2d5dc578c0992b4f3c631373479ebf3892efe53d21c4f4f1cc9a11c3536b7f75a3463044300e0603551d0f0101ff0404030205a030130603551d25040c300a06082b06010505070301300c0603551d130101ff04023000300f0603551d1104083006820474657374300a06082a8648ce3d0403020349003046022100963712d6226c7b2bef41512d47e1434131aaca3ba585d666c924df71ac0448b3022100f4d05c725064741aef125f243cdbccaa2a5d485927831f221c43023bd5ae471a")

var testRSAPrivateKey, _ = x509.ParsePKCS1PrivateKey(fromHex("3082025b02010002818100db467d932e12270648bc062821ab7ec4b6a25dfe1e5245887a3647a5080d92425bc281c0be97799840fb4f6d14fd2b138bc2a52e67d8d4099ed62238b74a0b74732bc234f1d193e596d9747bf3589f6c613cc0b041d4d92b2b2423775b1c3bbd755dce2054cfa163871d1e24c4f31d1a508baab61443ed97a77562f414c852d702030100010281800b07fbcf48b50f1388db34b016298b8217f2092a7c9a04f77db6775a3d1279b62ee9951f7e371e9de33f015aea80660760b3951dc589a9f925ed7de13e8f520e1ccbc7498ce78e7fab6d59582c2386cc07ed688212a576ff37833bd5943483b5554d15a0b9b4010ed9bf09f207e7e9805f649240ed6c1256ed75ab7cd56d9671024100fded810da442775f5923debae4ac758390a032a16598d62f059bb2e781a9c2f41bfa015c209f966513fe3bf5a58717cbdb385100de914f88d649b7d15309fa49024100dd10978c623463a1802c52f012cfa72ff5d901f25a2292446552c2568b1840e49a312e127217c2186615aae4fb6602a4f6ebf3f3d160f3b3ad04c592f65ae41f02400c69062ca781841a09de41ed7a6d9f54adc5d693a2c6847949d9e1358555c9ac6a8d9e71653ac77beb2d3abaf7bb1183aa14278956575dbebf525d0482fd72d90240560fe1900ba36dae3022115fd952f2399fb28e2975a1c3e3d0b679660bdcb356cc189d611cfdd6d87cd5aea45aa30a2082e8b51e94c2f3dd5d5c6036a8a615ed0240143993d80ece56f877cb80048335701eb0e608cc0c1ca8c2227b52edf8f1ac99c562f2541b5ce81f0515af1c5b4770dba53383964b4b725ff46fdec3d08907df"))

var testECDSAPrivateKey, _ = x509.ParseECPrivateKey(fromHex("3081dc0201010442019883e909ad0ac9ea3d33f9eae661f1785206970f8ca9a91672f1eedca7a8ef12bd6561bb246dda5df4b4d5e7e3a92649bc5d83a0bf92972e00e62067d0c7bd99d7a00706052b81040023a18189038186000400c4a1edbe98f90b4873367ec316561122f23d53c33b4d213dcd6b75e6f6b0dc9adf26c1bcb287f072327cb3642f1c90bcea6823107efee325c0483a69e0286dd33700ef0462dd0da09c706283d881d36431aa9e9731bd96b068c09b23de76643f1a5c7fe9120e5858b65f70dd9bd8ead5d7f5d5ccb9b69f30665b669a20e227e5bffe3b"))

var testP256PrivateKey, _ = x509.ParseECPrivateKey(fromHex("30770201010420012f3b52bc54c36ba3577ad45034e2e8efe1e6999851284cb848725cfe029991a00a06082a8648ce3d030107a14403420004c02c61c9b16283bbcc14956d886d79b358aa614596975f78cece787146abf74c2d5dc578c0992b4f3c631373479ebf3892efe53d21c4f4f1cc9a11c3536b7f75"))

var testEd25519PrivateKey = ed25519.PrivateKey(fromHex("3a884965e76b3f55e5faf9615458a92354894234de3ec9f684d46d55cebf3dc63fe2152ee6e3ef3f4e854a7577a3649eede0bf842ccc92268ffa6f3483aaec8f"))

const clientCertificatePEM = `
-----BEGIN CERTIFICATE-----
MIIB7zCCAVigAwIBAgIQXBnBiWWDVW/cC8m5k5/pvDANBgkqhkiG9w0BAQsFADAS
MRAwDgYDVQQKEwdBY21lIENvMB4XDTE2MDgxNzIxNTIzMVoXDTE3MDgxNzIxNTIz
MVowEjEQMA4GA1UEChMHQWNtZSBDbzCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkC
gYEAum+qhr3Pv5/y71yUYHhv6BPy0ZZvzdkybiI3zkH5yl0prOEn2mGi7oHLEMff
NFiVhuk9GeZcJ3NgyI14AvQdpJgJoxlwaTwlYmYqqyIjxXuFOE8uCXMyp70+m63K
hAfmDzr/d8WdQYUAirab7rCkPy1MTOZCPrtRyN1IVPQMjkcCAwEAAaNGMEQwDgYD
VR0PAQH/BAQDAgWgMBMGA1UdJQQMMAoGCCsGAQUFBwMBMAwGA1UdEwEB/wQCMAAw
DwYDVR0RBAgwBocEfwAAATANBgkqhkiG9w0BAQsFAAOBgQBGq0Si+yhU+Fpn+GKU
8ZqyGJ7ysd4dfm92lam6512oFmyc9wnTN+RLKzZ8Aa1B0jLYw9KT+RBrjpW5LBeK
o0RIvFkTgxYEiKSBXCUNmAysEbEoVr4dzWFihAm/1oDGRY2CLLTYg5vbySK3KhIR
e/oCO8HJ/+rJnahJ05XX1Q7lNQ==
-----END CERTIFICATE-----`

var clientKeyPEM = testingKey(`
-----BEGIN RSA TESTING KEY-----
MIICXQIBAAKBgQC6b6qGvc+/n/LvXJRgeG/oE/LRlm/N2TJuIjfOQfnKXSms4Sfa
YaLugcsQx980WJWG6T0Z5lwnc2DIjXgC9B2kmAmjGXBpPCViZiqrIiPFe4U4Ty4J
czKnvT6brcqEB+YPOv93xZ1BhQCKtpvusKQ/LUxM5kI+u1HI3UhU9AyORwIDAQAB
AoGAEJZ03q4uuMb7b26WSQsOMeDsftdatT747LGgs3pNRkMJvTb/O7/qJjxoG+Mc
qeSj0TAZXp+PXXc3ikCECAc+R8rVMfWdmp903XgO/qYtmZGCorxAHEmR80SrfMXv
PJnznLQWc8U9nphQErR+tTESg7xWEzmFcPKwnZd1xg8ERYkCQQDTGtrFczlB2b/Z
9TjNMqUlMnTLIk/a/rPE2fLLmAYhK5sHnJdvDURaH2mF4nso0EGtENnTsh6LATnY
dkrxXGm9AkEA4hXHG2q3MnhgK1Z5hjv+Fnqd+8bcbII9WW4flFs15EKoMgS1w/PJ
zbsySaSy5IVS8XeShmT9+3lrleed4sy+UwJBAJOOAbxhfXP5r4+5R6ql66jES75w
jUCVJzJA5ORJrn8g64u2eGK28z/LFQbv9wXgCwfc72R468BdawFSLa/m2EECQGbZ
rWiFla26IVXV0xcD98VWJsTBZMlgPnSOqoMdM1kSEd4fUmlAYI/dFzV1XYSkOmVr
FhdZnklmpVDeu27P4c0CQQCuCOup0FlJSBpWY1TTfun/KMBkBatMz0VMA3d7FKIU
csPezl677Yjo8u1r/KzeI6zLg87Z8E6r6ZWNc9wBSZK6
-----END RSA TESTING KEY-----`)

const clientECDSACertificatePEM = `
-----BEGIN CERTIFICATE-----
MIIB/DCCAV4CCQCaMIRsJjXZFzAJBgcqhkjOPQQBMEUxCzAJBgNVBAYTAkFVMRMw
EQYDVQQIEwpTb21lLVN0YXRlMSEwHwYDVQQKExhJbnRlcm5ldCBXaWRnaXRzIFB0
eSBMdGQwHhcNMTIxMTE0MTMyNTUzWhcNMjIxMTEyMTMyNTUzWjBBMQswCQYDVQQG
EwJBVTEMMAoGA1UECBMDTlNXMRAwDgYDVQQHEwdQeXJtb250MRIwEAYDVQQDEwlK
b2VsIFNpbmcwgZswEAYHKoZIzj0CAQYFK4EEACMDgYYABACVjJF1FMBexFe01MNv
ja5oHt1vzobhfm6ySD6B5U7ixohLZNz1MLvT/2XMW/TdtWo+PtAd3kfDdq0Z9kUs
jLzYHQFMH3CQRnZIi4+DzEpcj0B22uCJ7B0rxE4wdihBsmKo+1vx+U56jb0JuK7q
ixgnTy5w/hOWusPTQBbNZU6sER7m8TAJBgcqhkjOPQQBA4GMADCBiAJCAOAUxGBg
C3JosDJdYUoCdFzCgbkWqD8pyDbHgf9stlvZcPE4O1BIKJTLCRpS8V3ujfK58PDa
2RU6+b0DeoeiIzXsAkIBo9SKeDUcSpoj0gq+KxAxnZxfvuiRs9oa9V2jI/Umi0Vw
jWVim34BmT0Y9hCaOGGbLlfk+syxis7iI6CH8OFnUes=
-----END CERTIFICATE-----`

var clientECDSAKeyPEM = testingKey(`
-----BEGIN EC PARAMETERS-----
BgUrgQQAIw==
-----END EC PARAMETERS-----
-----BEGIN EC TESTING KEY-----
MIHcAgEBBEIBkJN9X4IqZIguiEVKMqeBUP5xtRsEv4HJEtOpOGLELwO53SD78Ew8
k+wLWoqizS3NpQyMtrU8JFdWfj+C57UNkOugBwYFK4EEACOhgYkDgYYABACVjJF1
FMBexFe01MNvja5oHt1vzobhfm6ySD6B5U7ixohLZNz1MLvT/2XMW/TdtWo+PtAd
3kfDdq0Z9kUsjLzYHQFMH3CQRnZIi4+DzEpcj0B22uCJ7B0rxE4wdihBsmKo+1vx
+U56jb0JuK7qixgnTy5w/hOWusPTQBbNZU6sER7m8Q==
-----END EC TESTING KEY-----`)

const clientEd25519CertificatePEM = `
-----BEGIN CERTIFICATE-----
MIIBLjCB4aADAgECAhAX0YGTviqMISAQJRXoNCNPMAUGAytlcDASMRAwDgYDVQQK
EwdBY21lIENvMB4XDTE5MDUxNjIxNTQyNloXDTIwMDUxNTIxNTQyNlowEjEQMA4G
A1UEChMHQWNtZSBDbzAqMAUGAytlcAMhAAvgtWC14nkwPb7jHuBQsQTIbcd4bGkv
xRStmmNveRKRo00wSzAOBgNVHQ8BAf8EBAMCBaAwEwYDVR0lBAwwCgYIKwYBBQUH
AwIwDAYDVR0TAQH/BAIwADAWBgNVHREEDzANggtleGFtcGxlLmNvbTAFBgMrZXAD
QQD8GRcqlKUx+inILn9boF2KTjRAOdazENwZ/qAicbP1j6FYDc308YUkv+Y9FN/f
7Q7hF9gRomDQijcjKsJGqjoI
-----END CERTIFICATE-----`

var clientEd25519KeyPEM = testingKey(`
-----BEGIN TESTING KEY-----
MC4CAQAwBQYDK2VwBCIEINifzf07d9qx3d44e0FSbV4mC/xQxT644RRbpgNpin7I
-----END TESTING KEY-----`)
```