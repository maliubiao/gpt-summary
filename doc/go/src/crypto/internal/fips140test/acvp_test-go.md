Response:
Let's break down the thought process for analyzing the provided Go code.

1. **Understand the Goal:** The first step is to grasp the overall purpose of the code. The initial comment block is crucial here. It clearly states that this code acts as a "module wrapper" for the Go FIPS module, enabling it to communicate with the `acvptool` from the BoringSSL project. The key takeaway is the interaction with `acvptool` and the role of translating between `acvptool`'s stdin/stdout protocol and the Go FIPS module's functionalities.

2. **Identify Key Components:**  Next, scan the code for the major building blocks. Keywords like `func`, `type`, `var`, `import`, and the `main` function are good starting points.

    * **`TestMain` and `wrapperMain`:** These immediately highlight the dual nature of the program: running as a standard Go test or as the ACVP wrapper. The environment variable `ACVP_WRAPPER` is a key control point.

    * **`processingLoop`:** This function is the heart of the wrapper. It reads requests, processes them, and writes responses. This suggests a request-response interaction.

    * **`request` and `command` types:** These structures define the format of requests and the association of commands with their handlers.

    * **`commands` map:** This map is central to dispatching requests to the correct handler function based on the command name. The keys are command strings (e.g., "SHA2-256"), and the values are `command` structs.

    * **`cmdGetConfig`, `cmdHashAft`, `cmdHashMct`, `cmdSha3Mct`, `cmdHmacAft`, `cmdPbkdf`:** These functions are the command handlers themselves. They implement the logic for different cryptographic operations. Notice the naming convention: `cmd` prefix followed by the operation.

    * **`readRequest`, `readArgs`, `writeResponse`:** These functions handle the low-level details of parsing the `acvptool`'s binary protocol. The comments mentioning "32-bit little-endian" confirm this.

    * **`lookupHash`:** This utility function helps map string representations of hash algorithms to the corresponding Go FIPS hash functions.

    * **`TestACVP`:** This is the integration test that orchestrates the interaction with the actual `acvptool`. It fetches necessary modules, builds the tool, and runs the `check_expected.go` test driver.

    * **`TestTooFewArgs`, `TestTooManyArgs`, `TestGetConfig`, `TestSha2256`:** These are unit tests for specific aspects of the wrapper's functionality.

3. **Trace the Execution Flow:**  Imagine how the program runs when `ACVP_WRAPPER` is set.

    * `TestMain` calls `wrapperMain`.
    * `wrapperMain` calls `processingLoop`.
    * `processingLoop` repeatedly reads requests from stdin using `readRequest`.
    * `readRequest` parses the binary data to get the command name and arguments.
    * `processingLoop` looks up the command in the `commands` map.
    * The corresponding handler function is called.
    * The handler performs the cryptographic operation.
    * The result is formatted into a response using `writeResponse` and sent to stdout.

4. **Analyze Individual Components in Detail:** Now, delve deeper into the purpose of each function and data structure.

    * **`commands` map:**  Pay attention to the keys and the associated handlers. Notice the different suffixes like `/MCT` which indicate different test modes (Monte Carlo Test). The embedded `acvp_capabilities.json` file is also important as it dictates which algorithms are considered supported.

    * **Command handlers:**  Understand the arguments they expect and the return values. For example, `cmdHashAft` takes a message, hashes it, and returns the digest. `cmdPbkdf` takes multiple arguments for the PBKDF2 parameters.

    * **Protocol functions (`readRequest`, `writeResponse`):**  The comments about the binary format are key. The little-endian encoding and the structure of the request/response are important details.

5. **Infer Functionality and Provide Examples:** Based on the analysis, start explaining what each part does and provide illustrative examples.

    * **GetConfig:** It's clear this retrieves the supported algorithms from the `capabilitiesJson`.

    * **Hashing:**  The `cmdHashAft` and `cmdHashMct` functions demonstrate the standard hash and Monte Carlo test flows. Provide simple input and expected output examples.

    * **HMAC:**  `cmdHmacAft` shows how HMAC is handled, requiring both a message and a key.

    * **PBKDF2:** `cmdPbkdf` illustrates the more complex PBKDF2 operation with its various parameters.

6. **Identify Command-Line Arguments and Environment Variables:** The `TestMain` function uses `os.Getenv("ACVP_WRAPPER")`. This is a crucial piece of information about how the program behaves in different contexts. The `TestACVP` function doesn't directly take command-line arguments for *this* specific wrapper program. However, it builds and executes `acvptool`, which likely has its own command-line arguments (though these aren't directly handled *by this Go code*). The `acvp_test.config.json` is also a form of configuration input.

7. **Consider Potential Errors:** Think about common mistakes users might make. The strict argument requirements for each command are a potential source of errors. The unit tests `TestTooFewArgs` and `TestTooManyArgs` confirm this. Also, mismatches between the `commands` map and the `acvp_capabilities.json` could lead to unexpected behavior.

8. **Structure the Answer:** Organize the information logically using the prompts as a guide. Start with the overall functionality, then detail specific aspects like the Go function implementation with examples, command-line arguments (specifically the environment variable), and potential pitfalls. Use clear and concise language.

By following these steps, one can systematically analyze the code and provide a comprehensive and accurate explanation of its functionality. The key is to understand the high-level goal and then gradually drill down into the details of each component and their interactions.
这个Go语言文件 `acvp_test.go` 的主要功能是**实现一个适配器（wrapper）**，使得Go语言的FIPS 140模块能够与BoringSSL项目的 `acvptool` 工具进行交互。 `acvptool` 用于自动化测试密码学模块是否符合NIST的ACVP（Algorithm Validation Program）标准。

更具体地说，它的功能包括：

1. **实现与 `acvptool` 的通信协议:**  `acvptool` 通过标准输入 (stdin) 发送测试用例，并期望在标准输出 (stdout) 上接收测试结果。这个文件实现了读取 `acvptool` 发送的请求，并按照 `acvptool` 期望的格式返回响应。这种通信协议是基于二进制格式的，包括参数的数量、每个参数的长度和内容。

2. **支持 `acvptool` 定义的命令:**  文件中定义了一系列命令（例如 "getConfig", "SHA2-256", "HMAC-SHA2-256", "PBKDF" 等），这些命令对应着 `acvptool` 发起的针对不同密码学算法的测试。

3. **调用 Go FIPS 140 模块的实现:**  对于每个支持的命令，文件中都有相应的处理函数（例如 `cmdHashAft`, `cmdHmacAft`, `cmdPbkdf`）。这些函数会调用 `crypto/internal/fips140` 包中实现的密码学算法（例如 SHA256, HMAC, PBKDF2）。

4. **处理不同类型的测试:**  支持算法功能测试 (AFT) 和 Monte Carlo 测试 (MCT)。例如，对于 SHA2-256，既有 `SHA2-256` 命令用于 AFT，也有 `SHA2-256/MCT` 命令用于 MCT。

5. **提供模块配置信息:**  实现了 `getConfig` 命令，用于向 `acvptool` 提供当前模块支持的算法和配置信息。这些信息通常以 JSON 格式存储在 `acvp_capabilities.json` 文件中。

**Go语言功能实现示例：**

以下以 SHA2-256 的算法功能测试 (AFT) 为例，说明代码是如何使用 Go 语言的 `crypto/internal/fips140/sha256` 包来实现哈希计算的。

```go
import (
	"bytes"
	"crypto/internal/fips140"
	"crypto/internal/fips140/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
)

// 假设 acvptool 发送一个 SHA2-256 的 AFT 请求，包含要哈希的消息 "hello world"。
// 请求的二进制数据（简化表示，实际包含长度等信息）可以被 `readRequest` 函数解析出来。
// 假设解析后的请求如下：
// req := &request{name: "SHA2-256", args: [][]byte{[]byte("hello world")}}

func cmdHashAftExample(t *testing.T) {
	// 模拟 acvptool 发送的请求
	testMessage := []byte("hello world")
	req := mockRequest(t, "SHA2-256", [][]byte{testMessage})

	// 创建一个用于捕获输出的 buffer
	var output bytes.Buffer

	// 调用 processingLoop 处理请求
	err := processingLoop(req, &output)
	if err != nil {
		t.Fatalf("processingLoop error: %v", err)
	}

	// 从输出中读取响应
	respArgs := readResponse(t, &output)
	if len(respArgs) != 1 {
		t.Fatalf("expected 1 response arg, got %d", len(respArgs))
	}

	// 期望的 SHA256 哈希值
	expectedDigest := []byte{
		0xb9, 0x4d, 0x27, 0xb9, 0x93, 0x4d, 0x3e, 0x08, 0xa5, 0x2e, 0x52, 0xd7, 0xda, 0x7d, 0xac, 0xb4,
		0x84, 0xef, 0xea, 0xbd, 0xe9, 0xdb, 0x01, 0xf7, 0xe2, 0xea, 0x71, 0xd3, 0x6b, 0x3d, 0xa8, 0xdd,
	}

	// 验证计算出的哈希值是否与期望值一致
	if !bytes.Equal(respArgs[0], expectedDigest) {
		t.Errorf("expected digest %x, got %x", expectedDigest, respArgs[0])
	}
}

// 辅助函数，用于模拟 acvptool 的请求
func mockRequest(t *testing.T, cmd string, args [][]byte) io.Reader {
	t.Helper()

	msgData := append([][]byte{[]byte(cmd)}, args...)

	var buf bytes.Buffer
	if err := writeResponse(&buf, msgData); err != nil {
		t.Fatalf("writeResponse error: %v", err)
	}

	return &buf
}

// 辅助函数，用于读取 wrapper 的响应
func readResponse(t *testing.T, reader io.Reader) [][]byte {
	var numArgs uint32
	if err := binary.Read(reader, binary.LittleEndian, &numArgs); err != nil {
		t.Fatalf("failed to read response args count: %v", err)
	}

	argLengths := make([]uint32, numArgs)
	respArgs := make([][]byte, numArgs)

	for i := range argLengths {
		if err := binary.Read(reader, binary.LittleEndian, &argLengths[i]); err != nil {
			t.Fatalf("failed to read %d-th response arg len: %v", i, err)
		}
	}

	for i, length := range argLengths {
		buf := make([]byte, length)
		if _, err := io.ReadFull(reader, buf); err != nil {
			t.Fatalf("failed to read %d-th response arg data: %v", i, err)
		}
		respArgs[i] = buf
	}

	return respArgs
}

// ... (文件中的其他代码)
```

在这个例子中，`cmdHashAft` 函数负责处理 "SHA2-256" 命令。它接收 `acvptool` 发送的消息（`args[0]`），创建一个 `sha256.New()` 的哈希对象，将消息写入哈希对象，然后计算并返回哈希值。

**命令行参数的具体处理：**

这个文件本身**不直接处理命令行参数**。它的运行方式是由 `acvptool` 工具驱动的。当 `acvptool` 需要测试 Go FIPS 模块时，它会 fork 这个 Go 程序，并通过标准输入发送命令和参数。

然而，代码中有一个关键的环境变量的处理：

* **`ACVP_WRAPPER`:**  在 `TestMain` 函数中，会检查环境变量 `ACVP_WRAPPER` 是否设置为 "1"。
    * 如果设置了，程序会进入 `wrapperMain` 函数，这意味着它作为 `acvptool` 的一个子进程运行，负责处理 `acvptool` 发送的测试请求。
    * 如果没有设置，程序会像普通的 Go 测试一样运行测试用例（通过 `m.Run()`）。

实际上，`TestACVP` 函数会构建并运行 `acvptool` 工具，并将当前测试二进制文件作为模块包装器传递给 `acvptool`。在运行 `acvptool` 时，会设置 `ACVP_WRAPPER=1` 环境变量，从而触发包装器模式。

**使用者易犯错的点：**

1. **手动运行 wrapper 程序而不设置 `ACVP_WRAPPER`:** 如果直接运行 `go run acvp_test.go`，程序会执行测试用例，而不会进入与 `acvptool` 交互的模式。使用者可能会错误地认为程序没有正常工作。

2. **修改 `commands` 映射但未更新 `acvp_capabilities.json`:**  `acvptool` 首先会调用 `getConfig` 命令来获取模块支持的算法。如果 `commands` 映射中添加或删除了命令，但 `acvp_capabilities.json` 文件没有相应更新，`acvptool` 可能会发送模块不支持的命令，导致错误。

   例如，如果在 `commands` 中添加了一个新的哈希算法 "SM3"，但 `acvp_capabilities.json` 中没有声明支持 "SM3"，那么 `acvptool` 可能会因为配置不匹配而报错。

3. **假设 `processingLoop` 可以独立运行进行测试:** `processingLoop` 依赖于 `acvptool` 发送符合特定二进制格式的请求。如果手动构造输入数据，需要严格遵循该格式，包括参数数量和长度的 32 位小端表示。构造错误的输入会导致 `readRequest` 或后续处理出错。

**总结:**

`go/src/crypto/internal/fips140test/acvp_test.go` 文件的核心作用是充当一个桥梁，让 Go 语言的 FIPS 140 模块能够被外部的 `acvptool` 工具验证其符合性。它实现了与 `acvptool` 的通信协议，并根据 `acvptool` 发送的命令调用 Go 语言的密码学算法实现。 理解其与 `acvptool` 的协作方式以及依赖的环境变量是正确使用和理解这段代码的关键。

Prompt: 
```
这是路径为go/src/crypto/internal/fips140test/acvp_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package fipstest

// A module wrapper adapting the Go FIPS module to the protocol used by the
// BoringSSL project's `acvptool`.
//
// The `acvptool` "lowers" the NIST ACVP server JSON test vectors into a simpler
// stdin/stdout protocol that can be implemented by a module shim. The tool
// will fork this binary, request the supported configuration, and then provide
// test cases over stdin, expecting results to be returned on stdout.
//
// See "Testing other FIPS modules"[0] from the BoringSSL ACVP.md documentation
// for a more detailed description of the protocol used between the acvptool
// and module wrappers.
//
// [0]: https://boringssl.googlesource.com/boringssl/+/refs/heads/master/util/fipstools/acvp/ACVP.md#testing-other-fips-modules

import (
	"bufio"
	"bytes"
	"crypto/internal/cryptotest"
	"crypto/internal/fips140"
	"crypto/internal/fips140/hmac"
	"crypto/internal/fips140/pbkdf2"
	"crypto/internal/fips140/sha256"
	"crypto/internal/fips140/sha3"
	"crypto/internal/fips140/sha512"
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"
	"internal/testenv"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMain(m *testing.M) {
	if os.Getenv("ACVP_WRAPPER") == "1" {
		wrapperMain()
	} else {
		os.Exit(m.Run())
	}
}

func wrapperMain() {
	if err := processingLoop(bufio.NewReader(os.Stdin), os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "processing error: %v\n", err)
		os.Exit(1)
	}
}

type request struct {
	name string
	args [][]byte
}

type commandHandler func([][]byte) ([][]byte, error)

type command struct {
	// requiredArgs enforces that an exact number of arguments are provided to the handler.
	requiredArgs int
	handler      commandHandler
}

var (
	// SHA2 algorithm capabilities:
	//   https://pages.nist.gov/ACVP/draft-celi-acvp-sha.html#section-7.2
	// HMAC algorithm capabilities:
	//   https://pages.nist.gov/ACVP/draft-fussell-acvp-mac.html#section-7
	// PBKDF2 algorithm capabilities:
	//   https://pages.nist.gov/ACVP/draft-celi-acvp-pbkdf.html#section-7.3
	//go:embed acvp_capabilities.json
	capabilitiesJson []byte

	// commands should reflect what config says we support. E.g. adding a command here will be a NOP
	// unless the configuration/acvp_capabilities.json indicates the command's associated algorithm
	// is supported.
	commands = map[string]command{
		"getConfig": cmdGetConfig(),

		"SHA2-224":         cmdHashAft(sha256.New224()),
		"SHA2-224/MCT":     cmdHashMct(sha256.New224()),
		"SHA2-256":         cmdHashAft(sha256.New()),
		"SHA2-256/MCT":     cmdHashMct(sha256.New()),
		"SHA2-384":         cmdHashAft(sha512.New384()),
		"SHA2-384/MCT":     cmdHashMct(sha512.New384()),
		"SHA2-512":         cmdHashAft(sha512.New()),
		"SHA2-512/MCT":     cmdHashMct(sha512.New()),
		"SHA2-512/224":     cmdHashAft(sha512.New512_224()),
		"SHA2-512/224/MCT": cmdHashMct(sha512.New512_224()),
		"SHA2-512/256":     cmdHashAft(sha512.New512_256()),
		"SHA2-512/256/MCT": cmdHashMct(sha512.New512_256()),

		"SHA3-256":     cmdHashAft(sha3.New256()),
		"SHA3-256/MCT": cmdSha3Mct(sha3.New256()),
		"SHA3-224":     cmdHashAft(sha3.New224()),
		"SHA3-224/MCT": cmdSha3Mct(sha3.New224()),
		"SHA3-384":     cmdHashAft(sha3.New384()),
		"SHA3-384/MCT": cmdSha3Mct(sha3.New384()),
		"SHA3-512":     cmdHashAft(sha3.New512()),
		"SHA3-512/MCT": cmdSha3Mct(sha3.New512()),

		"HMAC-SHA2-224":     cmdHmacAft(func() fips140.Hash { return sha256.New224() }),
		"HMAC-SHA2-256":     cmdHmacAft(func() fips140.Hash { return sha256.New() }),
		"HMAC-SHA2-384":     cmdHmacAft(func() fips140.Hash { return sha512.New384() }),
		"HMAC-SHA2-512":     cmdHmacAft(func() fips140.Hash { return sha512.New() }),
		"HMAC-SHA2-512/224": cmdHmacAft(func() fips140.Hash { return sha512.New512_224() }),
		"HMAC-SHA2-512/256": cmdHmacAft(func() fips140.Hash { return sha512.New512_256() }),
		"HMAC-SHA3-224":     cmdHmacAft(func() fips140.Hash { return sha3.New224() }),
		"HMAC-SHA3-256":     cmdHmacAft(func() fips140.Hash { return sha3.New256() }),
		"HMAC-SHA3-384":     cmdHmacAft(func() fips140.Hash { return sha3.New384() }),
		"HMAC-SHA3-512":     cmdHmacAft(func() fips140.Hash { return sha3.New512() }),

		"PBKDF": cmdPbkdf(),
	}
)

func processingLoop(reader io.Reader, writer io.Writer) error {
	// Per ACVP.md:
	//   The protocol is request–response: the subprocess only speaks in response to a request
	//   and there is exactly one response for every request.
	for {
		req, err := readRequest(reader)
		if errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return fmt.Errorf("reading request: %w", err)
		}

		cmd, exists := commands[req.name]
		if !exists {
			return fmt.Errorf("unknown command: %q", req.name)
		}

		if gotArgs := len(req.args); gotArgs != cmd.requiredArgs {
			return fmt.Errorf("command %q expected %d args, got %d", req.name, cmd.requiredArgs, gotArgs)
		}

		response, err := cmd.handler(req.args)
		if err != nil {
			return fmt.Errorf("command %q failed: %w", req.name, err)
		}

		if err = writeResponse(writer, response); err != nil {
			return fmt.Errorf("command %q response failed: %w", req.name, err)
		}
	}

	return nil
}

func readRequest(reader io.Reader) (*request, error) {
	// Per ACVP.md:
	//   Requests consist of one or more byte strings and responses consist
	//   of zero or more byte strings. A request contains: the number of byte
	//   strings, the length of each byte string, and the contents of each byte
	//   string. All numbers are 32-bit little-endian and values are
	//   concatenated in the order specified.
	var numArgs uint32
	if err := binary.Read(reader, binary.LittleEndian, &numArgs); err != nil {
		return nil, err
	}
	if numArgs == 0 {
		return nil, errors.New("invalid request: zero args")
	}

	args, err := readArgs(reader, numArgs)
	if err != nil {
		return nil, err
	}

	return &request{
		name: string(args[0]),
		args: args[1:],
	}, nil
}

func readArgs(reader io.Reader, requiredArgs uint32) ([][]byte, error) {
	argLengths := make([]uint32, requiredArgs)
	args := make([][]byte, requiredArgs)

	for i := range argLengths {
		if err := binary.Read(reader, binary.LittleEndian, &argLengths[i]); err != nil {
			return nil, fmt.Errorf("invalid request: failed to read %d-th arg len: %w", i, err)
		}
	}

	for i, length := range argLengths {
		buf := make([]byte, length)
		if _, err := io.ReadFull(reader, buf); err != nil {
			return nil, fmt.Errorf("invalid request: failed to read %d-th arg data: %w", i, err)
		}
		args[i] = buf
	}

	return args, nil
}

func writeResponse(writer io.Writer, args [][]byte) error {
	// See `readRequest` for details on the base format. Per ACVP.md:
	//   A response has the same format except that there may be zero byte strings
	//   and the first byte string has no special meaning.
	numArgs := uint32(len(args))
	if err := binary.Write(writer, binary.LittleEndian, numArgs); err != nil {
		return fmt.Errorf("writing arg count: %w", err)
	}

	for i, arg := range args {
		if err := binary.Write(writer, binary.LittleEndian, uint32(len(arg))); err != nil {
			return fmt.Errorf("writing %d-th arg length: %w", i, err)
		}
	}

	for i, b := range args {
		if _, err := writer.Write(b); err != nil {
			return fmt.Errorf("writing %d-th arg data: %w", i, err)
		}
	}

	return nil
}

// "All implementations must support the getConfig command
// which takes no arguments and returns a single byte string
// which is a JSON blob of ACVP algorithm configuration."
func cmdGetConfig() command {
	return command{
		handler: func(args [][]byte) ([][]byte, error) {
			return [][]byte{capabilitiesJson}, nil
		},
	}
}

// cmdHashAft returns a command handler for the specified hash
// algorithm for algorithm functional test (AFT) test cases.
//
// This shape of command expects a message as the sole argument,
// and writes the resulting digest as a response.
//
// See https://pages.nist.gov/ACVP/draft-celi-acvp-sha.html
func cmdHashAft(h fips140.Hash) command {
	return command{
		requiredArgs: 1, // Message to hash.
		handler: func(args [][]byte) ([][]byte, error) {
			h.Reset()
			h.Write(args[0])
			digest := make([]byte, 0, h.Size())
			digest = h.Sum(digest)

			return [][]byte{digest}, nil
		},
	}
}

// cmdHashMct returns a command handler for the specified hash
// algorithm for monte carlo test (MCT) test cases.
//
// This shape of command expects a seed as the sole argument,
// and writes the resulting digest as a response. It implements
// the "standard" flavour of the MCT, not the "alternative".
//
// This algorithm was ported from `HashMCT` in BSSL's `modulewrapper.cc`
// Note that it differs slightly from the upstream NIST MCT[0] algorithm
// in that it does not perform the outer 100 iterations itself. See
// footnote #1 in the ACVP.md docs[1], the acvptool handles this.
//
// [0]: https://pages.nist.gov/ACVP/draft-celi-acvp-sha.html#section-6.2
// [1]: https://boringssl.googlesource.com/boringssl/+/refs/heads/master/util/fipstools/acvp/ACVP.md#testing-other-fips-modules
func cmdHashMct(h fips140.Hash) command {
	return command{
		requiredArgs: 1, // Seed message.
		handler: func(args [][]byte) ([][]byte, error) {
			hSize := h.Size()
			seed := args[0]

			if seedLen := len(seed); seedLen != hSize {
				return nil, fmt.Errorf("invalid seed size: expected %d got %d", hSize, seedLen)
			}

			digest := make([]byte, 0, hSize)
			buf := make([]byte, 0, 3*hSize)
			buf = append(buf, seed...)
			buf = append(buf, seed...)
			buf = append(buf, seed...)

			for i := 0; i < 1000; i++ {
				h.Reset()
				h.Write(buf)
				digest = h.Sum(digest[:0])

				copy(buf, buf[hSize:])
				copy(buf[2*hSize:], digest)
			}

			return [][]byte{buf[hSize*2:]}, nil
		},
	}
}

// cmdSha3Mct returns a command handler for the specified hash
// algorithm for SHA-3 monte carlo test (MCT) test cases.
//
// This shape of command expects a seed as the sole argument,
// and writes the resulting digest as a response. It implements
// the "standard" flavour of the MCT, not the "alternative".
//
// This algorithm was ported from the "standard" MCT algorithm
// specified in  draft-celi-acvp-sha3[0]. Note this differs from
// the SHA2-* family of MCT tests handled by cmdHashMct. However,
// like that handler it does not perform the outer 100 iterations.
//
// [0]: https://pages.nist.gov/ACVP/draft-celi-acvp-sha3.html#section-6.2.1
func cmdSha3Mct(h fips140.Hash) command {
	return command{
		requiredArgs: 1, // Seed message.
		handler: func(args [][]byte) ([][]byte, error) {
			seed := args[0]
			md := make([][]byte, 1001)
			md[0] = seed

			for i := 1; i <= 1000; i++ {
				h.Reset()
				h.Write(md[i-1])
				md[i] = h.Sum(nil)
			}

			return [][]byte{md[1000]}, nil
		},
	}
}

func cmdHmacAft(h func() fips140.Hash) command {
	return command{
		requiredArgs: 2, // Message and key
		handler: func(args [][]byte) ([][]byte, error) {
			msg := args[0]
			key := args[1]
			mac := hmac.New(h, key)
			mac.Write(msg)
			return [][]byte{mac.Sum(nil)}, nil
		},
	}
}

func cmdPbkdf() command {
	return command{
		// Hash name, key length, salt, password, iteration count
		requiredArgs: 5,
		handler: func(args [][]byte) ([][]byte, error) {
			h, err := lookupHash(string(args[0]))
			if err != nil {
				return nil, fmt.Errorf("PBKDF2 failed: %w", err)
			}

			keyLen := binary.LittleEndian.Uint32(args[1]) / 8
			salt := args[2]
			password := args[3]
			iterationCount := binary.LittleEndian.Uint32(args[4])

			derivedKey, err := pbkdf2.Key(h, string(password), salt, int(iterationCount), int(keyLen))
			if err != nil {
				return nil, fmt.Errorf("PBKDF2 failed: %w", err)
			}

			return [][]byte{derivedKey}, nil
		},
	}
}

func lookupHash(name string) (func() fips140.Hash, error) {
	var h func() fips140.Hash

	switch name {
	case "SHA2-224":
		h = func() fips140.Hash { return sha256.New224() }
	case "SHA2-256":
		h = func() fips140.Hash { return sha256.New() }
	case "SHA2-384":
		h = func() fips140.Hash { return sha512.New384() }
	case "SHA2-512":
		h = func() fips140.Hash { return sha512.New() }
	case "SHA2-512/224":
		h = func() fips140.Hash { return sha512.New512_224() }
	case "SHA2-512/256":
		h = func() fips140.Hash { return sha512.New512_256() }
	case "SHA3-224":
		h = func() fips140.Hash { return sha3.New224() }
	case "SHA3-256":
		h = func() fips140.Hash { return sha3.New256() }
	case "SHA3-384":
		h = func() fips140.Hash { return sha3.New384() }
	case "SHA3-512":
		h = func() fips140.Hash { return sha3.New512() }
	default:
		return nil, fmt.Errorf("unknown hash name: %q", name)
	}

	return h, nil
}

func TestACVP(t *testing.T) {
	testenv.SkipIfShortAndSlow(t)

	const (
		bsslModule    = "boringssl.googlesource.com/boringssl.git"
		bsslVersion   = "v0.0.0-20241015160643-2587c4974dbe"
		goAcvpModule  = "github.com/cpu/go-acvp"
		goAcvpVersion = "v0.0.0-20241011151719-6e0509dcb7ce"
	)

	// In crypto/tls/bogo_shim_test.go the test is skipped if run on a builder with runtime.GOOS == "windows"
	// due to flaky networking. It may be necessary to do the same here.

	// Stat the acvp test config file so the test will be re-run if it changes, invalidating cached results
	// from the old config.
	if _, err := os.Stat("acvp_test.config.json"); err != nil {
		t.Fatalf("failed to stat config file: %s", err)
	}

	// Fetch the BSSL module and use the JSON output to find the absolute path to the dir.
	bsslDir := cryptotest.FetchModule(t, bsslModule, bsslVersion)

	t.Log("building acvptool")

	// Build the acvptool binary.
	toolPath := filepath.Join(t.TempDir(), "acvptool.exe")
	goTool := testenv.GoToolPath(t)
	cmd := testenv.Command(t, goTool,
		"build",
		"-o", toolPath,
		"./util/fipstools/acvp/acvptool")
	cmd.Dir = bsslDir
	out := &strings.Builder{}
	cmd.Stderr = out
	if err := cmd.Run(); err != nil {
		t.Fatalf("failed to build acvptool: %s\n%s", err, out.String())
	}

	// Similarly, fetch the ACVP data module that has vectors/expected answers.
	dataDir := cryptotest.FetchModule(t, goAcvpModule, goAcvpVersion)

	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to fetch cwd: %s", err)
	}
	configPath := filepath.Join(cwd, "acvp_test.config.json")
	t.Logf("running check_expected.go\ncwd: %q\ndata_dir: %q\nconfig: %q\ntool: %q\nmodule-wrapper: %q\n",
		cwd, dataDir, configPath, toolPath, os.Args[0])

	// Run the check_expected test driver using the acvptool we built, and this test binary as the
	// module wrapper. The file paths in the config file are specified relative to the dataDir root
	// so we run the command from that dir.
	args := []string{
		"run",
		filepath.Join(bsslDir, "util/fipstools/acvp/acvptool/test/check_expected.go"),
		"-tool",
		toolPath,
		// Note: module prefix must match Wrapper value in acvp_test.config.json.
		"-module-wrappers", "go:" + os.Args[0],
		"-tests", configPath,
	}
	cmd = testenv.Command(t, goTool, args...)
	cmd.Dir = dataDir
	cmd.Env = append(os.Environ(), "ACVP_WRAPPER=1")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("failed to run acvp tests: %s\n%s", err, string(output))
	}
	t.Log(string(output))
}

func TestTooFewArgs(t *testing.T) {
	commands["test"] = command{
		requiredArgs: 1,
		handler: func(args [][]byte) ([][]byte, error) {
			if gotArgs := len(args); gotArgs != 1 {
				return nil, fmt.Errorf("expected 1 args, got %d", gotArgs)
			}
			return nil, nil
		},
	}

	var output bytes.Buffer
	err := processingLoop(mockRequest(t, "test", nil), &output)
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	expectedErr := "expected 1 args, got 0"
	if !strings.Contains(err.Error(), expectedErr) {
		t.Errorf("expected error to contain %q, got %v", expectedErr, err)
	}
}

func TestTooManyArgs(t *testing.T) {
	commands["test"] = command{
		requiredArgs: 1,
		handler: func(args [][]byte) ([][]byte, error) {
			if gotArgs := len(args); gotArgs != 1 {
				return nil, fmt.Errorf("expected 1 args, got %d", gotArgs)
			}
			return nil, nil
		},
	}

	var output bytes.Buffer
	err := processingLoop(mockRequest(
		t, "test", [][]byte{[]byte("one"), []byte("two")}), &output)
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	expectedErr := "expected 1 args, got 2"
	if !strings.Contains(err.Error(), expectedErr) {
		t.Errorf("expected error to contain %q, got %v", expectedErr, err)
	}
}

func TestGetConfig(t *testing.T) {
	var output bytes.Buffer
	err := processingLoop(mockRequest(t, "getConfig", nil), &output)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	respArgs := readResponse(t, &output)
	if len(respArgs) != 1 {
		t.Fatalf("expected 1 response arg, got %d", len(respArgs))
	}

	if !bytes.Equal(respArgs[0], capabilitiesJson) {
		t.Errorf("expected config %q, got %q", string(capabilitiesJson), string(respArgs[0]))
	}
}

func TestSha2256(t *testing.T) {
	testMessage := []byte("gophers eat grass")
	expectedDigest := []byte{
		188, 142, 10, 214, 48, 236, 72, 143, 70, 216, 223, 205, 219, 69, 53, 29,
		205, 207, 162, 6, 14, 70, 113, 60, 251, 170, 201, 236, 119, 39, 141, 172,
	}

	var output bytes.Buffer
	err := processingLoop(mockRequest(t, "SHA2-256", [][]byte{testMessage}), &output)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	respArgs := readResponse(t, &output)
	if len(respArgs) != 1 {
		t.Fatalf("expected 1 response arg, got %d", len(respArgs))
	}

	if !bytes.Equal(respArgs[0], expectedDigest) {
		t.Errorf("expected digest %v, got %v", expectedDigest, respArgs[0])
	}
}

func mockRequest(t *testing.T, cmd string, args [][]byte) io.Reader {
	t.Helper()

	msgData := append([][]byte{[]byte(cmd)}, args...)

	var buf bytes.Buffer
	if err := writeResponse(&buf, msgData); err != nil {
		t.Fatalf("writeResponse error: %v", err)
	}

	return &buf
}

func readResponse(t *testing.T, reader io.Reader) [][]byte {
	var numArgs uint32
	if err := binary.Read(reader, binary.LittleEndian, &numArgs); err != nil {
		t.Fatalf("failed to read response args count: %v", err)
	}

	args, err := readArgs(reader, numArgs)
	if err != nil {
		t.Fatalf("failed to read %d response args: %v", numArgs, err)
	}

	return args
}

"""



```