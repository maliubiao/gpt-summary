Response:
Let's break down the thought process for analyzing the provided Go code.

1. **Identify the Core Purpose:**  The first thing to do is scan the import statements and top-level function names. We see `net`, `syscall`, `os/exec`, `testing`, and names like `TestAcceptIgnoreSomeErrors`, `TestInterfacesWithNetsh`, `TestInterfaceAddrsWithNetsh`, `TestInterfaceHardwareAddrWithGetmac`. This immediately suggests that the code is testing the `net` package's functionality on Windows. Specifically, it looks like it's verifying how the `net` package interacts with the underlying Windows network stack.

2. **Deconstruct by Test Function:** The code is organized into test functions. This is a good way to approach the analysis.

   * **`TestAcceptIgnoreSomeErrors`:** The name is quite descriptive. It suggests testing the `Accept` method of a `TCPListener` and how it handles errors, particularly broken connections, on Windows. The code spawns a child process to simulate a broken connection, writes to the connection, and then checks if subsequent `Accept` calls work correctly. The `toErrno` helper function confirms the focus on specific Windows error codes.

   * **`runCmd`:** This function is clearly a utility for executing Windows commands (using `powershell`). The `-Command` flag indicates it's running PowerShell commands directly. The `Out-File` part suggests it's capturing the output of those commands to a temporary file. The UTF8 encoding handling is also notable.

   * **`checkNetsh`:** This function uses `runCmd` to execute `netsh help`. It's likely a pre-condition check to ensure the `netsh` command-line tool is available and working correctly on the test environment. The ARM64 skip is a clue about potential platform-specific issues.

   * **`netshInterfaceIPShowInterface`:**  This function uses `netsh` to retrieve interface information (status - up/down) for both IPv4 and IPv6. The parsing of the `netsh` output is evident in the byte-by-byte analysis of the lines. The comparison between IPv4 and IPv6 states hints at a consistency check.

   * **`TestInterfacesWithNetsh`:** This test uses the `netshInterfaceIPShowInterface` function and the Go `net.Interfaces()` function to compare the list of network interfaces and their up/down status. The sorting of the lists before comparison is standard practice for ensuring order doesn't cause false negatives.

   * **`netshInterfaceIPv4ShowAddress` and `netshInterfaceIPv6ShowAddress`:** These functions are similar to the previous `netsh` function, but they focus on retrieving IP addresses and subnet prefixes for a specific interface. The parsing logic is tailored to the specific output format of `netsh interface ipv4/ipv6 show address`. The IPv6 function notes the lack of netmask output from `netsh`.

   * **`TestInterfaceAddrsWithNetsh`:** This test uses the previous two `netsh` address functions and Go's `ifi.Addrs()` to compare the reported IP addresses. The handling of both `*IPNet` and `*IPAddr` is important. The IPv6 address comparison again highlights the missing netmask in `netsh` output.

   * **`checkGetmac`:** Similar to `checkNetsh`, this verifies the availability and basic functionality (English output) of the `getmac` command.

   * **`TestInterfaceHardwareAddrWithGetmac`:** This test retrieves the MAC addresses of network interfaces using both Go's `ifi.HardwareAddr` and the `getmac` command. The parsing of `getmac` output is complex due to its format. The handling of duplicate MAC addresses and the logic for matching Go interfaces to `getmac` output indicate the challenges in reliably mapping interface names to MAC addresses.

3. **Identify Key Go Features Illustrated:** Based on the analysis, several Go features are prominently used:

   * **`net` package:**  Core networking functionalities like listening (`Listen`), accepting connections (`Accept`), dialing (`Dial`), and retrieving interface information (`Interfaces`, `ifi.Addrs`, `ifi.HardwareAddr`).
   * **`os/exec` package:** Executing external commands (`netsh`, `getmac`, and the child process in `TestAcceptIgnoreSomeErrors`).
   * **`testing` package:** Writing unit tests with `t.Fatal`, `t.Errorf`, `t.Skipf`.
   * **Error handling:** Checking for errors and using `fmt.Errorf` to create informative error messages (including Windows error codes).
   * **Concurrency:** Using goroutines and channels for the delayed connection in `TestAcceptIgnoreSomeErrors`.
   * **String and byte manipulation:**  Extensive use of `strings` and `bytes` packages for parsing command output.
   * **Slices:**  Using `slices.Sort` for comparing lists of interfaces and addresses.
   * **Type assertions:** Used in `toErrno` to get the underlying `syscall.Errno`.

4. **Infer Functionality and Provide Examples:**  Now that we understand what each test does, we can describe the overall functionality and create illustrative Go code examples. The examples should directly relate to the tested `net` package functionalities.

5. **Consider Command-Line Arguments:**  The `TestAcceptIgnoreSomeErrors` test uses environment variables (`GOTEST_DIAL_ADDR`) to communicate with the child process. This is the key command-line aspect to explain.

6. **Identify Potential Pitfalls:** Based on the code and its purpose, potential user errors might include:

   * **Incorrect error handling:** Not checking for errors when working with network operations.
   * **Platform dependence:**  Assuming network behavior is consistent across operating systems. The tests themselves highlight Windows-specific behaviors.
   * **Misinterpreting command output:** Incorrectly parsing the output of `netsh` or `getmac`.
   * **Ignoring interface status:**  Not checking if an interface is up before attempting network operations.

7. **Structure the Output:** Finally, organize the findings into clear sections with headings, bullet points, and code blocks to make the information easy to understand. Use clear and concise language in Chinese as requested.
这段代码是 Go 语言标准库 `net` 包的一部分，专门用于在 Windows 操作系统上测试网络相关的功能。它主要关注以下几个方面：

**1. 测试 `TCPListener.Accept` 的错误处理机制 (TestAcceptIgnoreSomeErrors):**

* **功能:**  测试当 TCP 监听器 (`TCPListener`) 接受连接时，如何处理一些特定的、表示连接中断的错误，例如 `syscall.ERROR_NETNAME_DELETED` 和 `syscall.WSAECONNRESET`。
* **实现原理:**  这个测试会启动一个子进程，该子进程会连接到测试创建的 TCP 监听器。然后，主进程会强制杀死子进程，从而人为地制造连接中断的错误。测试验证在这种情况下，`Accept` 方法是否能正确处理这些错误，而不会影响后续的连接。
* **Go 代码示例:**

```go
package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"time"
)

func main() {
	if os.Getenv("GOTEST_DIAL_ADDR") != "" {
		// 子进程代码
		conn, err := net.Dial("tcp", os.Getenv("GOTEST_DIAL_ADDR"))
		if err != nil {
			fmt.Println("子进程连接失败:", err)
			return
		}
		defer conn.Close()
		fmt.Println("子进程已连接，等待被杀死...")
		time.Sleep(time.Minute) // 子进程会在这里被杀死
		return
	}

	// 主进程代码
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fmt.Println("监听失败:", err)
		return
	}
	defer ln.Close()

	addr := ln.Addr().String()
	fmt.Println("监听地址:", addr)

	// 启动子进程
	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(), "GOTEST_DIAL_ADDR="+addr)
	err = cmd.Start()
	if err != nil {
		fmt.Println("启动子进程失败:", err)
		return
	}
	defer cmd.Wait()

	time.Sleep(time.Second) // 等待子进程连接

	// 杀死子进程
	err = cmd.Process.Kill()
	if err != nil {
		fmt.Println("杀死子进程失败:", err)
		return
	}
	fmt.Println("子进程已杀死")

	// 尝试接受连接，应该会遇到连接中断的错误
	_, err = ln.Accept()
	if err != nil {
		fmt.Println("Accept 遇到错误:", err)
	} else {
		fmt.Println("Accept 没有遇到错误，这不符合预期")
	}

	// 再次尝试接受连接，验证是否能正常工作
	conn, err := ln.Accept()
	if err != nil {
		fmt.Println("第二次 Accept 遇到错误:", err)
	} else {
		fmt.Println("第二次 Accept 成功:", conn.RemoteAddr())
		conn.Close()
	}
}
```

* **假设的输入与输出:** 无特定的输入，输出会根据测试结果而定。正常情况下，会输出 "Accept 遇到错误" 和 "第二次 Accept 成功"。

**2. 使用 `netsh` 命令测试网络接口信息 (TestInterfacesWithNetsh, netshInterfaceIPShowInterface):**

* **功能:**  使用 Windows 自带的 `netsh` 命令行工具来获取网络接口的信息 (例如，接口是否启用)，并与 Go 语言 `net.Interfaces()` 获取的信息进行对比，验证 `net` 包在 Windows 上获取网络接口信息的准确性。
* **实现原理:**  `netshInterfaceIPShowInterface` 函数会执行 `netsh interface ipv4 show interface level=verbose` 和 `netsh interface ipv6 show interface level=verbose` 命令，解析命令输出，提取接口名称和状态。`TestInterfacesWithNetsh` 函数则调用 Go 的 `net.Interfaces()` 获取接口信息，并与 `netsh` 获取的信息进行比对。
* **Go 代码示例:**  由于这部分功能主要依赖于执行外部命令并解析其输出，所以用 Go 代码示例演示 `netsh` 的使用更有意义：

```powershell
# 获取所有 IPv4 接口的详细信息
netsh interface ipv4 show interface level=verbose

# 获取所有 IPv6 接口的详细信息
netsh interface ipv6 show interface level=verbose
```

* **命令行参数处理:** `netsh` 命令本身有很多参数。这里使用了 `interface ipv4 show interface level=verbose` 和 `interface ipv6 show interface level=verbose`。
    * `interface`:  指定要操作的上下文为接口。
    * `ipv4` 或 `ipv6`:  指定 IP 协议版本。
    * `show interface`:  显示接口信息。
    * `level=verbose`:  指定输出详细信息。
* **假设的输入与输出:**  无特定的输入，输出是 `netsh` 命令的执行结果，包含了网络接口的详细配置信息，例如接口名称、状态（已连接/已断开）等。

**3. 使用 `netsh` 命令测试网络接口的 IP 地址信息 (TestInterfaceAddrsWithNetsh, netshInterfaceIPv4ShowAddress, netshInterfaceIPv6ShowAddress):**

* **功能:** 使用 `netsh` 命令获取网络接口的 IPv4 和 IPv6 地址信息 (包括 IP 地址和子网掩码)，并与 Go 语言 `ifi.Addrs()` 获取的信息进行对比，验证 `net` 包在 Windows 上获取 IP 地址信息的准确性。
* **实现原理:**  `netshInterfaceIPv4ShowAddress` 和 `netshInterfaceIPv6ShowAddress` 函数分别执行 `netsh interface ipv4 show address` 和 `netsh interface ipv6 show address level=verbose` 命令，解析命令输出，提取接口的 IP 地址和子网掩码。`TestInterfaceAddrsWithNetsh` 函数则调用 Go 的 `ifi.Addrs()` 获取接口地址信息，并与 `netsh` 获取的信息进行比对。
* **Go 代码示例:**

```powershell
# 获取所有 IPv4 接口的地址信息
netsh interface ipv4 show address

# 获取所有 IPv6 接口的地址信息 (详细模式)
netsh interface ipv6 show address level=verbose
```

* **命令行参数处理:**
    * `interface ipv4 show address`: 显示 IPv4 地址信息。
    * `interface ipv6 show address level=verbose`: 显示详细的 IPv6 地址信息。
* **假设的输入与输出:**  无特定的输入，输出是 `netsh` 命令的执行结果，包含了网络接口的 IP 地址、子网掩码、网关等信息。

**4. 使用 `getmac` 命令测试网络接口的 MAC 地址信息 (TestInterfaceHardwareAddrWithGetmac, checkGetmac):**

* **功能:** 使用 Windows 的 `getmac` 命令行工具来获取网络接口的 MAC 地址，并与 Go 语言 `ifi.HardwareAddr` 获取的信息进行对比，验证 `net` 包在 Windows 上获取 MAC 地址的准确性。
* **实现原理:** `TestInterfaceHardwareAddrWithGetmac` 函数执行 `getmac /fo list /v` 命令，解析其输出，提取接口名称和对应的 MAC 地址。然后，它遍历 Go 的 `net.Interfaces()` 获取的接口信息，并比较 MAC 地址。
* **Go 代码示例:**

```powershell
# 获取所有网络适配器的 MAC 地址 (列表格式，详细输出)
getmac /fo list /v
```

* **命令行参数处理:**
    * `getmac`:  执行 getmac 命令。
    * `/fo list`:  指定输出格式为列表。
    * `/v`:  显示详细输出。
* **假设的输入与输出:**  无特定的输入，输出是 `getmac` 命令的执行结果，包含了网络适配器的连接名称、网络适配器名称和物理地址（MAC 地址）等信息。

**辅助函数:**

* **`toErrno(err error) (syscall.Errno, bool)`:**  用于将 `error` 类型转换为 Windows 的 `syscall.Errno` 类型，方便检查具体的 Windows 错误代码。
* **`runCmd(args ...string) ([]byte, error)`:**  用于执行 Windows 的命令行命令，并将输出作为 `[]byte` 返回。它使用 `powershell` 来执行命令，并将输出重定向到文件，以处理可能的编码问题。
* **`checkNetsh(t *testing.T)` 和 `checkGetmac(t *testing.T)`:**  用于检查 `netsh` 和 `getmac` 命令是否可用，以及输出是否为英文，避免在非英文环境下测试失败。

**可以推理出它是什么 Go 语言功能的实现:**

这段代码主要测试了 Go 语言 `net` 包在 Windows 平台上的以下功能实现：

* **TCP 监听和连接处理:**  特别是 `TCPListener` 的 `Accept` 方法如何处理连接中断的错误。
* **网络接口信息获取:**  通过 `net.Interfaces()` 函数获取网络接口的列表和基本信息 (例如，接口名称和状态)。
* **网络接口地址信息获取:**  通过 `ifi.Addrs()` 方法获取网络接口的 IP 地址和子网掩码。
* **网络接口 MAC 地址获取:**  通过 `ifi.HardwareAddr` 字段获取网络接口的 MAC 地址。

**使用者易犯错的点:**

* **错误处理不当:**  在进行网络编程时，忽略错误检查是很常见的错误。例如，在 `Accept` 方法返回错误时没有进行处理，可能会导致程序行为异常。这段测试强调了 `Accept` 在特定错误下的处理，可以帮助开发者理解需要关注的错误类型。
    * **例子:**

    ```go
    ln, err := net.Listen("tcp", "127.0.0.1:8080")
    if err != nil {
        // 应该处理错误，例如打印日志并退出
        panic(err)
    }
    defer ln.Close()

    for {
        conn, err := ln.Accept()
        // 易错点：没有检查 err
        if err != nil {
            // 正确的做法是处理错误，例如记录日志，然后继续尝试接受连接
            fmt.Println("接受连接失败:", err)
            continue
        }
        go handleConnection(conn)
    }
    ```

* **平台依赖性:**  这段代码是针对 Windows 平台的测试，一些网络行为和错误码在不同的操作系统上可能有所不同。开发者在编写跨平台网络程序时，需要注意这些差异。例如，连接中断的错误码在 Linux 和 Windows 上可能不同。

* **对 `netsh` 或 `getmac` 命令输出的解析错误:**  在需要与外部命令交互时，解析命令的输出是容易出错的环节。输出格式可能因系统版本或语言设置而异。这段代码中 `runCmd` 函数尝试通过重定向到文件并读取来处理编码问题，但仍然需要小心解析逻辑的健壮性。

总而言之，这段代码是 `net` 包在 Windows 平台上的功能测试，它覆盖了 TCP 连接处理、网络接口信息、IP 地址和 MAC 地址的获取等方面，并使用了 Windows 特有的命令行工具进行辅助验证。理解这段代码可以帮助开发者更好地理解 Go 语言在 Windows 平台上的网络编程特性。

### 提示词
```
这是路径为go/src/net/net_windows_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package net

import (
	"bufio"
	"bytes"
	"fmt"
	"internal/testenv"
	"io"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
)

func toErrno(err error) (syscall.Errno, bool) {
	operr, ok := err.(*OpError)
	if !ok {
		return 0, false
	}
	syserr, ok := operr.Err.(*os.SyscallError)
	if !ok {
		return 0, false
	}
	errno, ok := syserr.Err.(syscall.Errno)
	if !ok {
		return 0, false
	}
	return errno, true
}

// TestAcceptIgnoreSomeErrors tests that windows TCPListener.AcceptTCP
// handles broken connections. It verifies that broken connections do
// not affect future connections.
func TestAcceptIgnoreSomeErrors(t *testing.T) {
	recv := func(ln Listener, ignoreSomeReadErrors bool) (string, error) {
		c, err := ln.Accept()
		if err != nil {
			// Display windows errno in error message.
			errno, ok := toErrno(err)
			if !ok {
				return "", err
			}
			return "", fmt.Errorf("%v (windows errno=%d)", err, errno)
		}
		defer c.Close()

		b := make([]byte, 100)
		n, err := c.Read(b)
		if err == nil || err == io.EOF {
			return string(b[:n]), nil
		}
		errno, ok := toErrno(err)
		if ok && ignoreSomeReadErrors && (errno == syscall.ERROR_NETNAME_DELETED || errno == syscall.WSAECONNRESET) {
			return "", nil
		}
		return "", err
	}

	send := func(addr string, data string) error {
		c, err := Dial("tcp", addr)
		if err != nil {
			return err
		}
		defer c.Close()

		b := []byte(data)
		n, err := c.Write(b)
		if err != nil {
			return err
		}
		if n != len(b) {
			return fmt.Errorf(`Only %d chars of string "%s" sent`, n, data)
		}
		return nil
	}

	if envaddr := os.Getenv("GOTEST_DIAL_ADDR"); envaddr != "" {
		// In child process.
		c, err := Dial("tcp", envaddr)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Printf("sleeping\n")
		time.Sleep(time.Minute) // process will be killed here
		c.Close()
	}

	ln, err := Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	// Start child process that connects to our listener.
	cmd := exec.Command(os.Args[0], "-test.run=TestAcceptIgnoreSomeErrors")
	cmd.Env = append(os.Environ(), "GOTEST_DIAL_ADDR="+ln.Addr().String())
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("cmd.StdoutPipe failed: %v", err)
	}
	err = cmd.Start()
	if err != nil {
		t.Fatalf("cmd.Start failed: %v\n", err)
	}
	outReader := bufio.NewReader(stdout)
	for {
		s, err := outReader.ReadString('\n')
		if err != nil {
			t.Fatalf("reading stdout failed: %v", err)
		}
		if s == "sleeping\n" {
			break
		}
	}
	defer cmd.Wait() // ignore error - we know it is getting killed

	const alittle = 100 * time.Millisecond
	time.Sleep(alittle)
	cmd.Process.Kill() // the only way to trigger the errors
	time.Sleep(alittle)

	// Send second connection data (with delay in a separate goroutine).
	result := make(chan error)
	go func() {
		time.Sleep(alittle)
		err := send(ln.Addr().String(), "abc")
		if err != nil {
			result <- err
		}
		result <- nil
	}()
	defer func() {
		err := <-result
		if err != nil {
			t.Fatalf("send failed: %v", err)
		}
	}()

	// Receive first or second connection.
	s, err := recv(ln, true)
	if err != nil {
		t.Fatalf("recv failed: %v", err)
	}
	switch s {
	case "":
		// First connection data is received, let's get second connection data.
	case "abc":
		// First connection is lost forever, but that is ok.
		return
	default:
		t.Fatalf(`"%s" received from recv, but "" or "abc" expected`, s)
	}

	// Get second connection data.
	s, err = recv(ln, false)
	if err != nil {
		t.Fatalf("recv failed: %v", err)
	}
	if s != "abc" {
		t.Fatalf(`"%s" received from recv, but "abc" expected`, s)
	}
}

func runCmd(args ...string) ([]byte, error) {
	removeUTF8BOM := func(b []byte) []byte {
		if len(b) >= 3 && b[0] == 0xEF && b[1] == 0xBB && b[2] == 0xBF {
			return b[3:]
		}
		return b
	}
	f, err := os.CreateTemp("", "netcmd")
	if err != nil {
		return nil, err
	}
	f.Close()
	defer os.Remove(f.Name())
	cmd := fmt.Sprintf(`%s | Out-File "%s" -encoding UTF8`, strings.Join(args, " "), f.Name())
	out, err := exec.Command("powershell", "-Command", cmd).CombinedOutput()
	if err != nil {
		if len(out) != 0 {
			return nil, fmt.Errorf("%s failed: %v: %q", args[0], err, string(removeUTF8BOM(out)))
		}
		var err2 error
		out, err2 = os.ReadFile(f.Name())
		if err2 != nil {
			return nil, err2
		}
		if len(out) != 0 {
			return nil, fmt.Errorf("%s failed: %v: %q", args[0], err, string(removeUTF8BOM(out)))
		}
		return nil, fmt.Errorf("%s failed: %v", args[0], err)
	}
	out, err = os.ReadFile(f.Name())
	if err != nil {
		return nil, err
	}
	return removeUTF8BOM(out), nil
}

func checkNetsh(t *testing.T) {
	if testenv.Builder() == "windows-arm64-10" {
		// netsh was observed to sometimes hang on this builder.
		// We have not observed failures on windows-arm64-11, so for the
		// moment we are leaving the test enabled elsewhere on the theory
		// that it may have been a platform bug fixed in Windows 11.
		testenv.SkipFlaky(t, 52082)
	}
	out, err := runCmd("netsh", "help")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(out, []byte("The following helper DLL cannot be loaded")) {
		t.Skipf("powershell failure:\n%s", err)
	}
	if !bytes.Contains(out, []byte("The following commands are available:")) {
		t.Skipf("powershell does not speak English:\n%s", out)
	}
}

func netshInterfaceIPShowInterface(ipver string, ifaces map[string]bool) error {
	out, err := runCmd("netsh", "interface", ipver, "show", "interface", "level=verbose")
	if err != nil {
		return err
	}
	// interface information is listed like:
	//
	//Interface Local Area Connection Parameters
	//----------------------------------------------
	//IfLuid                             : ethernet_6
	//IfIndex                            : 11
	//State                              : connected
	//Metric                             : 10
	//...
	var name string
	lines := bytes.Split(out, []byte{'\r', '\n'})
	for _, line := range lines {
		if bytes.HasPrefix(line, []byte("Interface ")) && bytes.HasSuffix(line, []byte(" Parameters")) {
			f := line[len("Interface "):]
			f = f[:len(f)-len(" Parameters")]
			name = string(f)
			continue
		}
		var isup bool
		switch string(line) {
		case "State                              : connected":
			isup = true
		case "State                              : disconnected":
			isup = false
		default:
			continue
		}
		if name != "" {
			if v, ok := ifaces[name]; ok && v != isup {
				return fmt.Errorf("%s:%s isup=%v: ipv4 and ipv6 report different interface state", ipver, name, isup)
			}
			ifaces[name] = isup
			name = ""
		}
	}
	return nil
}

func TestInterfacesWithNetsh(t *testing.T) {
	checkNetsh(t)

	toString := func(name string, isup bool) string {
		if isup {
			return name + ":up"
		}
		return name + ":down"
	}

	ift, err := Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	have := make([]string, 0)
	for _, ifi := range ift {
		have = append(have, toString(ifi.Name, ifi.Flags&FlagUp != 0))
	}
	slices.Sort(have)

	ifaces := make(map[string]bool)
	err = netshInterfaceIPShowInterface("ipv6", ifaces)
	if err != nil {
		t.Fatal(err)
	}
	err = netshInterfaceIPShowInterface("ipv4", ifaces)
	if err != nil {
		t.Fatal(err)
	}
	want := make([]string, 0)
	for name, isup := range ifaces {
		want = append(want, toString(name, isup))
	}
	slices.Sort(want)

	if strings.Join(want, "/") != strings.Join(have, "/") {
		t.Fatalf("unexpected interface list %q, want %q", have, want)
	}
}

func netshInterfaceIPv4ShowAddress(name string, netshOutput []byte) []string {
	// Address information is listed like:
	//
	//Configuration for interface "Local Area Connection"
	//    DHCP enabled:                         Yes
	//    IP Address:                           10.0.0.2
	//    Subnet Prefix:                        10.0.0.0/24 (mask 255.255.255.0)
	//    IP Address:                           10.0.0.3
	//    Subnet Prefix:                        10.0.0.0/24 (mask 255.255.255.0)
	//    Default Gateway:                      10.0.0.254
	//    Gateway Metric:                       0
	//    InterfaceMetric:                      10
	//
	//Configuration for interface "Loopback Pseudo-Interface 1"
	//    DHCP enabled:                         No
	//    IP Address:                           127.0.0.1
	//    Subnet Prefix:                        127.0.0.0/8 (mask 255.0.0.0)
	//    InterfaceMetric:                      50
	//
	addrs := make([]string, 0)
	var addr, subnetprefix string
	var processingOurInterface bool
	lines := bytes.Split(netshOutput, []byte{'\r', '\n'})
	for _, line := range lines {
		if !processingOurInterface {
			if !bytes.HasPrefix(line, []byte("Configuration for interface")) {
				continue
			}
			if !bytes.Contains(line, []byte(`"`+name+`"`)) {
				continue
			}
			processingOurInterface = true
			continue
		}
		if len(line) == 0 {
			break
		}
		if bytes.Contains(line, []byte("Subnet Prefix:")) {
			f := bytes.Split(line, []byte{':'})
			if len(f) == 2 {
				f = bytes.Split(f[1], []byte{'('})
				if len(f) == 2 {
					f = bytes.Split(f[0], []byte{'/'})
					if len(f) == 2 {
						subnetprefix = string(bytes.TrimSpace(f[1]))
						if addr != "" && subnetprefix != "" {
							addrs = append(addrs, addr+"/"+subnetprefix)
						}
					}
				}
			}
		}
		addr = ""
		if bytes.Contains(line, []byte("IP Address:")) {
			f := bytes.Split(line, []byte{':'})
			if len(f) == 2 {
				addr = string(bytes.TrimSpace(f[1]))
			}
		}
	}
	return addrs
}

func netshInterfaceIPv6ShowAddress(name string, netshOutput []byte) []string {
	// Address information is listed like:
	//
	//Address ::1 Parameters
	//---------------------------------------------------------
	//Interface Luid     : Loopback Pseudo-Interface 1
	//Scope Id           : 0.0
	//Valid Lifetime     : infinite
	//Preferred Lifetime : infinite
	//DAD State          : Preferred
	//Address Type       : Other
	//Skip as Source     : false
	//
	//Address XXXX::XXXX:XXXX:XXXX:XXXX%11 Parameters
	//---------------------------------------------------------
	//Interface Luid     : Local Area Connection
	//Scope Id           : 0.11
	//Valid Lifetime     : infinite
	//Preferred Lifetime : infinite
	//DAD State          : Preferred
	//Address Type       : Other
	//Skip as Source     : false
	//

	// TODO: need to test ipv6 netmask too, but netsh does not outputs it
	var addr string
	addrs := make([]string, 0)
	lines := bytes.Split(netshOutput, []byte{'\r', '\n'})
	for _, line := range lines {
		if addr != "" {
			if len(line) == 0 {
				addr = ""
				continue
			}
			if string(line) != "Interface Luid     : "+name {
				continue
			}
			addrs = append(addrs, addr)
			addr = ""
			continue
		}
		if !bytes.HasPrefix(line, []byte("Address")) {
			continue
		}
		if !bytes.HasSuffix(line, []byte("Parameters")) {
			continue
		}
		f := bytes.Split(line, []byte{' '})
		if len(f) != 3 {
			continue
		}
		// remove scope ID if present
		f = bytes.Split(f[1], []byte{'%'})

		// netsh can create IPv4-embedded IPv6 addresses, like fe80::5efe:192.168.140.1.
		// Convert these to all hexadecimal fe80::5efe:c0a8:8c01 for later string comparisons.
		ipv4Tail := regexp.MustCompile(`:\d+\.\d+\.\d+\.\d+$`)
		if ipv4Tail.Match(f[0]) {
			f[0] = []byte(ParseIP(string(f[0])).String())
		}

		addr = string(bytes.ToLower(bytes.TrimSpace(f[0])))
	}
	return addrs
}

func TestInterfaceAddrsWithNetsh(t *testing.T) {
	checkNetsh(t)

	outIPV4, err := runCmd("netsh", "interface", "ipv4", "show", "address")
	if err != nil {
		t.Fatal(err)
	}
	outIPV6, err := runCmd("netsh", "interface", "ipv6", "show", "address", "level=verbose")
	if err != nil {
		t.Fatal(err)
	}

	ift, err := Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, ifi := range ift {
		// Skip the interface if it's down.
		if (ifi.Flags & FlagUp) == 0 {
			continue
		}
		have := make([]string, 0)
		addrs, err := ifi.Addrs()
		if err != nil {
			t.Fatal(err)
		}
		for _, addr := range addrs {
			switch addr := addr.(type) {
			case *IPNet:
				if addr.IP.To4() != nil {
					have = append(have, addr.String())
				}
				if addr.IP.To16() != nil && addr.IP.To4() == nil {
					// netsh does not output netmask for ipv6, so ignore ipv6 mask
					have = append(have, addr.IP.String())
				}
			case *IPAddr:
				if addr.IP.To4() != nil {
					have = append(have, addr.String())
				}
				if addr.IP.To16() != nil && addr.IP.To4() == nil {
					// netsh does not output netmask for ipv6, so ignore ipv6 mask
					have = append(have, addr.IP.String())
				}
			}
		}
		slices.Sort(have)

		want := netshInterfaceIPv4ShowAddress(ifi.Name, outIPV4)
		wantIPv6 := netshInterfaceIPv6ShowAddress(ifi.Name, outIPV6)
		want = append(want, wantIPv6...)
		slices.Sort(want)

		if strings.Join(want, "/") != strings.Join(have, "/") {
			t.Errorf("%s: unexpected addresses list %q, want %q", ifi.Name, have, want)
		}
	}
}

// check that getmac exists as a powershell command, and that it
// speaks English.
func checkGetmac(t *testing.T) {
	out, err := runCmd("getmac", "/?")
	if err != nil {
		if strings.Contains(err.Error(), "term 'getmac' is not recognized as the name of a cmdlet") {
			t.Skipf("getmac not available")
		}
		t.Fatal(err)
	}
	if !bytes.Contains(out, []byte("network adapters on a system")) {
		t.Skipf("skipping test on non-English system")
	}
}

func TestInterfaceHardwareAddrWithGetmac(t *testing.T) {
	checkGetmac(t)

	ift, err := Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	have := make(map[string]string)
	for _, ifi := range ift {
		if ifi.Flags&FlagLoopback != 0 {
			// no MAC address for loopback interfaces
			continue
		}
		have[ifi.Name] = ifi.HardwareAddr.String()
	}

	out, err := runCmd("getmac", "/fo", "list", "/v")
	if err != nil {
		t.Fatal(err)
	}
	// getmac output looks like:
	//
	//Connection Name:  Local Area Connection
	//Network Adapter:  Intel Gigabit Network Connection
	//Physical Address: XX-XX-XX-XX-XX-XX
	//Transport Name:   \Device\Tcpip_{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}
	//
	//Connection Name:  Wireless Network Connection
	//Network Adapter:  Wireles WLAN Card
	//Physical Address: XX-XX-XX-XX-XX-XX
	//Transport Name:   Media disconnected
	//
	//Connection Name:  Bluetooth Network Connection
	//Network Adapter:  Bluetooth Device (Personal Area Network)
	//Physical Address: N/A
	//Transport Name:   Hardware not present
	//
	//Connection Name:  VMware Network Adapter VMnet8
	//Network Adapter:  VMware Virtual Ethernet Adapter for VMnet8
	//Physical Address: Disabled
	//Transport Name:   Disconnected
	//
	want := make(map[string]string)
	group := make(map[string]string) // name / values for single adapter
	getValue := func(name string) string {
		value, found := group[name]
		if !found {
			t.Fatalf("%q has no %q line in it", group, name)
		}
		if value == "" {
			t.Fatalf("%q has empty %q value", group, name)
		}
		return value
	}
	processGroup := func() {
		if len(group) == 0 {
			return
		}
		tname := strings.ToLower(getValue("Transport Name"))
		if tname == "n/a" {
			// skip these
			return
		}
		addr := strings.ToLower(getValue("Physical Address"))
		if addr == "disabled" || addr == "n/a" {
			// skip these
			return
		}
		addr = strings.ReplaceAll(addr, "-", ":")
		cname := getValue("Connection Name")
		want[cname] = addr
		group = make(map[string]string)
	}
	lines := bytes.Split(out, []byte{'\r', '\n'})
	for _, line := range lines {
		if len(line) == 0 {
			processGroup()
			continue
		}
		i := bytes.IndexByte(line, ':')
		if i == -1 {
			t.Fatalf("line %q has no : in it", line)
		}
		group[string(line[:i])] = string(bytes.TrimSpace(line[i+1:]))
	}
	processGroup()

	dups := make(map[string][]string)
	for name, addr := range want {
		if _, ok := dups[addr]; !ok {
			dups[addr] = make([]string, 0)
		}
		dups[addr] = append(dups[addr], name)
	}

nextWant:
	for name, wantAddr := range want {
		if haveAddr, ok := have[name]; ok {
			if haveAddr != wantAddr {
				t.Errorf("unexpected MAC address for %q - %v, want %v", name, haveAddr, wantAddr)
			}
			continue
		}
		// We could not find the interface in getmac output by name.
		// But sometimes getmac lists many interface names
		// for the same MAC address. If that is the case here,
		// and we can match at least one of those names,
		// let's ignore the other names.
		if dupNames, ok := dups[wantAddr]; ok && len(dupNames) > 1 {
			for _, dupName := range dupNames {
				if haveAddr, ok := have[dupName]; ok && haveAddr == wantAddr {
					continue nextWant
				}
			}
		}
		t.Errorf("getmac lists %q, but it could not be found among Go interfaces %v", name, have)
	}
}
```