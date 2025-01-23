Response:
Let's break down the thought process for analyzing the provided Go code snippet for `net/smtp`.

**1. Understanding the Goal:**

The primary goal is to understand the functionality of the given Go code and explain it clearly in Chinese. This includes:

* Listing the functions and their purposes.
* Identifying the overall Go functionality implemented.
* Providing illustrative Go code examples.
* Explaining command-line argument handling (if any).
* Pointing out potential user errors.

**2. Initial Code Scan and Keyword Recognition:**

First, a quick scan of the code reveals keywords and patterns related to networking and email protocols:

* `package smtp`:  Clearly indicates this is the SMTP package.
* `Client`: Suggests a client-side implementation for interacting with an SMTP server.
* `Dial`, `NewClient`:  Methods for establishing a connection.
* `Hello`, `EHLO`:  SMTP greeting commands.
* `StartTLS`:  Indicates support for secure connections.
* `Auth`:  Authentication mechanisms.
* `Mail`, `Rcpt`, `Data`: Core SMTP commands for sending emails.
* `SendMail`: A higher-level helper function.
* `Extension`:  Checking server capabilities.
* `Quit`: Closing the connection.
* `textproto.Conn`:  Indicates the use of a text-based protocol.
* `net.Conn`, `tls.Conn`: Network connection types.

**3. Function-by-Function Analysis:**

Next, I go through each exported function and method, understanding its purpose and how it interacts with other parts of the code. I make mental notes (or actual notes) about the key actions of each function.

* **`Client` struct:**  This is the central data structure, holding the connection, server information, and supported extensions.
* **`Dial(addr string)`:**  Creates a new `Client` by establishing a TCP connection to the given address. I note that it requires the port in the address.
* **`NewClient(conn net.Conn, host string)`:** Creates a `Client` using an existing connection. This is useful for scenarios where the connection is already established (e.g., for testing or custom connection handling). Crucially, it performs the initial server greeting read.
* **`Close()`:**  Closes the underlying connection.
* **`hello()`:** Handles sending the initial `EHLO` or `HELO` command if not already done. It prioritizes `EHLO`.
* **`Hello(localName string)`:** Allows the user to specify the hostname for the `HELO`/`EHLO` command. It has a constraint: it must be called before other methods that trigger the hello sequence.
* **`cmd(expectCode int, format string, args ...any)`:** A helper function for sending commands and checking the expected response code. This streamlines command execution.
* **`helo()`:** Sends the `HELO` command.
* **`ehlo()`:** Sends the `EHLO` command and parses the server's response to identify supported extensions and authentication mechanisms.
* **`StartTLS(config *tls.Config)`:** Upgrades the connection to TLS. It first performs the handshake and then renegotiates extensions with `EHLO`.
* **`TLSConnectionState()`:** Returns the TLS connection state if TLS is active.
* **`Verify(addr string)`:** Sends the `VRFY` command to check the validity of an email address (note the caveat about server behavior).
* **`Auth(a Auth)`:** Handles authentication using a provided `Auth` interface. This involves a back-and-forth exchange with the server.
* **`Mail(from string)`:** Sends the `MAIL FROM` command, potentially adding `BODY=8BITMIME` and `SMTPUTF8` extensions if supported.
* **`Rcpt(to string)`:** Sends the `RCPT TO` command.
* **`Data()`:** Sends the `DATA` command and returns a writer for the email content. The closing of this writer signals the end of the data.
* **`SendMail(addr string, a Auth, from string, to []string, msg []byte)`:** A high-level function that encapsulates the entire email sending process. It handles connection, TLS, authentication, and sending the email content.
* **`Extension(ext string)`:** Checks if a specific extension is supported.
* **`Reset()`:** Sends the `RSET` command to abort the current transaction.
* **`Noop()`:** Sends the `NOOP` command to check the connection.
* **`Quit()`:** Sends the `QUIT` command and closes the connection.
* **`validateLine(line string)`:** A utility function to ensure lines don't contain CR or LF.

**4. Identifying the Core Functionality:**

Based on the function analysis, it's clear that this code implements the **SMTP client** functionality in Go. It provides the necessary tools to connect to an SMTP server, authenticate, and send emails.

**5. Crafting Go Code Examples:**

For the most important functions (`Dial`, `SendMail`), I create simple, runnable examples to demonstrate their usage. This involves:

* **`Dial` Example:** Showing how to connect to a server.
* **`SendMail` Example:** Demonstrating a basic email sending scenario, including the message format. I recognize the need for an authentication mechanism example. Since the code mentions `Auth`, I create a placeholder example using `PlainAuth`.

**6. Considering Command-Line Arguments:**

I review the code for any direct handling of command-line arguments. In this case, the `net/smtp` package itself doesn't directly handle command-line arguments. The arguments are passed programmatically to the functions. I make a note of this.

**7. Identifying Potential User Errors:**

I think about common mistakes developers might make when using this package:

* **Incorrect address format for `Dial`:** Forgetting the port.
* **Calling `Hello` at the wrong time:** After other SMTP commands.
* **Not closing the `Data` writer:** Leading to incomplete email sending.
* **Incorrect email message format:**  Missing headers or the blank line separator.

**8. Structuring the Answer in Chinese:**

Finally, I organize the information in a clear and structured manner, using Chinese, and addressing all the points requested in the prompt. This involves:

* **功能列表:**  Listing each function and its purpose concisely.
* **Go语言功能实现:** Clearly stating that it's an SMTP client.
* **Go代码举例:** Providing the `Dial` and `SendMail` examples with clear explanations of the inputs and expected outputs.
* **命令行参数处理:** Explaining that the package doesn't handle command-line arguments directly.
* **使用者易犯错的点:**  Listing the potential pitfalls with illustrative examples.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe I should explain every single function in detail.
* **Correction:** Focus on the most important and commonly used functions for the examples to keep it concise and relevant.
* **Initial thought:**  Just show the basic `SendMail` example.
* **Correction:**  Realize that authentication is a key part of SMTP, so include an example using `PlainAuth`.
* **Initial thought:**  Simply say "incorrect usage."
* **Correction:** Provide specific examples of common mistakes and how they manifest to make the explanation more helpful.

By following these steps, I can effectively analyze the Go code and provide a comprehensive and understandable explanation in Chinese.
好的，让我们来分析一下 `go/src/net/smtp/smtp.go` 文件中的代码片段。

**功能列表:**

这段代码定义了一个用于与 SMTP (Simple Mail Transfer Protocol) 服务器进行通信的客户端。其主要功能包括：

1. **建立连接:**
   - `Dial(addr string)`:  根据给定的地址（包含主机名和端口）连接到 SMTP 服务器。
   - `NewClient(conn net.Conn, host string)`: 使用已存在的网络连接创建一个新的 SMTP 客户端，并进行初步的服务器问候语读取。

2. **关闭连接:**
   - `Close()`: 关闭与 SMTP 服务器的连接。

3. **发送问候语:**
   - `hello()`:  自动发送 `EHLO` (Extended Hello) 或 `HELO` (Hello) 命令与服务器进行问候。`EHLO` 是首选的问候方式，如果失败则尝试 `HELO`。
   - `Hello(localName string)`: 允许客户端指定 `HELO`/`EHLO` 命令中使用的主机名。

4. **执行 SMTP 命令:**
   - `cmd(expectCode int, format string, args ...any)`:  一个便捷的内部函数，用于发送格式化的 SMTP 命令并接收服务器的响应，并检查响应码是否符合预期。
   - `helo()`: 发送 `HELO` 命令。
   - `ehlo()`: 发送 `EHLO` 命令，并解析服务器返回的扩展功能列表和支持的认证机制。

5. **启用 TLS 加密:**
   - `StartTLS(config *tls.Config)`: 发送 `STARTTLS` 命令，将连接升级为 TLS 加密连接。

6. **获取 TLS 连接状态:**
   - `TLSConnectionState()`: 返回客户端当前的 TLS 连接状态。

7. **验证邮箱地址 (VRFY):**
   - `Verify(addr string)`: 发送 `VRFY` 命令来尝试验证服务器上邮箱地址的有效性。请注意，许多服务器出于安全考虑可能不会执行此操作。

8. **身份验证 (AUTH):**
   - `Auth(a Auth)`: 使用提供的身份验证机制与服务器进行身份验证。

9. **发送邮件:**
   - `Mail(from string)`: 发送 `MAIL FROM` 命令，指定发件人地址。如果服务器支持，还会添加 `BODY=8BITMIME` 和 `SMTPUTF8` 参数。
   - `Rcpt(to string)`: 发送 `RCPT TO` 命令，指定收件人地址。
   - `Data()`: 发送 `DATA` 命令，表示邮件内容即将发送，并返回一个 `io.WriteCloser` 用于写入邮件头和正文。

10. **发送完整邮件 (高级功能):**
    - `SendMail(addr string, a Auth, from string, to []string, msg []byte)`: 一个更高级别的函数，封装了连接、TLS 升级（如果支持）、身份验证（如果提供）以及发送邮件的整个过程。

11. **检查服务器扩展功能:**
    - `Extension(ext string)`:  检查服务器是否支持特定的扩展功能。

12. **重置会话:**
    - `Reset()`: 发送 `RSET` 命令，中止当前的邮件事务。

13. **空操作:**
    - `Noop()`: 发送 `NOOP` 命令，用于检查与服务器的连接是否正常。

14. **退出:**
    - `Quit()`: 发送 `QUIT` 命令并关闭与服务器的连接。

15. **内部校验:**
    - `validateLine(line string)`:  一个内部函数，用于检查字符串是否包含 `CR` 或 `LF`，以符合 RFC 5321 的规定。

**实现的 Go 语言功能:**

这段代码实现了 **SMTP 客户端** 的核心功能。它允许 Go 程序连接到 SMTP 服务器，执行各种 SMTP 命令，例如发送邮件、进行身份验证、启用加密等。 这属于 Go 语言中 **网络编程** 的一部分，具体来说是应用层协议的实现。

**Go 代码举例说明:**

假设我们要连接到 `mail.example.com:25` 这个 SMTP 服务器并发送一封简单的邮件。

```go
package main

import (
	"fmt"
	"net/smtp"
)

func main() {
	// 连接到 SMTP 服务器
	client, err := smtp.Dial("mail.example.com:25")
	if err != nil {
		fmt.Println("连接错误:", err)
		return
	}
	defer client.Close()

	// 设置发件人和收件人
	from := "sender@example.com"
	to := []string{"recipient@example.com"}

	// 邮件消息内容
	msg := []byte("Subject: 简单邮件\r\n" +
		"From: sender@example.com\r\n" +
		"To: recipient@example.com\r\n" +
		"\r\n" +
		"这是一封简单的邮件。\r\n")

	// 发送邮件
	err = smtp.SendMail("mail.example.com:25", nil, from, to, msg)
	if err != nil {
		fmt.Println("发送邮件错误:", err)
		return
	}

	fmt.Println("邮件发送成功!")
}
```

**假设的输入与输出:**

* **输入:**  程序执行，尝试连接到 `mail.example.com:25`。
* **输出 (成功情况):**  `邮件发送成功!`
* **输出 (连接错误):** 如果 `mail.example.com:25` 无法访问，则输出类似于 `连接错误: dial tcp 192.0.2.1:25: connection refused` (具体的 IP 地址会不同)。
* **输出 (发送邮件错误):** 如果 SMTP 服务器返回错误，例如收件人地址不存在，则输出相应的错误信息。

**命令行参数的具体处理:**

这段代码本身 **没有直接处理命令行参数**。`net/smtp` 包提供的功能是作为库被其他 Go 程序使用的，具体的 SMTP 服务器地址、发件人、收件人等信息通常会在调用 `smtp.Dial` 或 `smtp.SendMail` 等函数时作为参数传递。

如果需要从命令行获取这些信息，需要在调用 `net/smtp` 包的程序中处理命令行参数，例如使用 `flag` 包。

**使用者易犯错的点:**

1. **`Dial` 函数的地址格式不正确:**  忘记包含端口号。
   ```go
   // 错误示例：忘记添加端口
   client, err := smtp.Dial("mail.example.com")
   if err != nil {
       fmt.Println("错误:", err) // 输出类似 "missing port in address" 的错误
   }
   ```

2. **在调用 `Hello` 之后调用其他可能触发 hello 流程的方法:** `Hello` 方法应该在任何其他可能触发 `hello` 方法（例如 `Mail`, `Auth`, `StartTLS` 等）的方法之前调用。
   ```go
   client, _ := smtp.Dial("mail.example.com:25")
   // 错误示例：在 Hello 之前调用 Mail
   err := client.Mail("sender@example.com")
   if err != nil {
       fmt.Println("错误:", err)
   }
   err = client.Hello("myhostname") // 此时会报错，因为已经发送过 EHLO/HELO
   if err != nil {
       fmt.Println("错误:", err) // 可能输出 "smtp: Hello called after other methods"
   }
   ```

3. **忘记关闭 `Data()` 返回的 `io.WriteCloser`:**  在调用 `Data()` 发送邮件内容后，必须调用返回的 `io.WriteCloser` 的 `Close()` 方法来告知服务器邮件内容发送完毕。
   ```go
   client, _ := smtp.Dial("mail.example.com:25")
   client.Mail("sender@example.com")
   client.Rcpt("recipient@example.com")
   wc, err := client.Data()
   if err != nil {
       // ... 错误处理
   }
   fmt.Fprintln(wc, "Subject: Test")
   fmt.Fprintln(wc, "")
   fmt.Fprintln(wc, "This is the message body.")
   // 正确的做法是调用 wc.Close()
   err = wc.Close()
   if err != nil {
       // ... 错误处理
   }
   client.Quit()
   ```

4. **邮件消息格式不正确:**  邮件消息需要遵循 RFC 822 格式，包含头部（例如 `Subject`, `From`, `To`）和一个空行分隔头部和正文，每行以 `\r\n` 结尾。
   ```go
   msg := []byte("Subject: 测试邮件\n" + // 错误：应该使用 \r\n
       "From: sender@example.com\n" +   // 错误：应该使用 \r\n
       "\n" +                            // 错误：应该使用 \r\n
       "邮件正文")                       // 错误：应该使用 \r\n

   // 正确的做法：
   msg := []byte("Subject: 测试邮件\r\n" +
       "From: sender@example.com\r\n" +
       "\r\n" +
       "邮件正文\r\n")
   ```

希望这个详细的分析能够帮助你理解 `go/src/net/smtp/smtp.go` 的功能！

### 提示词
```
这是路径为go/src/net/smtp/smtp.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package smtp implements the Simple Mail Transfer Protocol as defined in RFC 5321.
// It also implements the following extensions:
//
//	8BITMIME  RFC 1652
//	AUTH      RFC 2554
//	STARTTLS  RFC 3207
//
// Additional extensions may be handled by clients.
//
// The smtp package is frozen and is not accepting new features.
// Some external packages provide more functionality. See:
//
//	https://godoc.org/?q=smtp
package smtp

import (
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/textproto"
	"strings"
)

// A Client represents a client connection to an SMTP server.
type Client struct {
	// Text is the textproto.Conn used by the Client. It is exported to allow for
	// clients to add extensions.
	Text *textproto.Conn
	// keep a reference to the connection so it can be used to create a TLS
	// connection later
	conn net.Conn
	// whether the Client is using TLS
	tls        bool
	serverName string
	// map of supported extensions
	ext map[string]string
	// supported auth mechanisms
	auth       []string
	localName  string // the name to use in HELO/EHLO
	didHello   bool   // whether we've said HELO/EHLO
	helloError error  // the error from the hello
}

// Dial returns a new [Client] connected to an SMTP server at addr.
// The addr must include a port, as in "mail.example.com:smtp".
func Dial(addr string) (*Client, error) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	host, _, _ := net.SplitHostPort(addr)
	return NewClient(conn, host)
}

// NewClient returns a new [Client] using an existing connection and host as a
// server name to be used when authenticating.
func NewClient(conn net.Conn, host string) (*Client, error) {
	text := textproto.NewConn(conn)
	_, _, err := text.ReadResponse(220)
	if err != nil {
		text.Close()
		return nil, err
	}
	c := &Client{Text: text, conn: conn, serverName: host, localName: "localhost"}
	_, c.tls = conn.(*tls.Conn)
	return c, nil
}

// Close closes the connection.
func (c *Client) Close() error {
	return c.Text.Close()
}

// hello runs a hello exchange if needed.
func (c *Client) hello() error {
	if !c.didHello {
		c.didHello = true
		err := c.ehlo()
		if err != nil {
			c.helloError = c.helo()
		}
	}
	return c.helloError
}

// Hello sends a HELO or EHLO to the server as the given host name.
// Calling this method is only necessary if the client needs control
// over the host name used. The client will introduce itself as "localhost"
// automatically otherwise. If Hello is called, it must be called before
// any of the other methods.
func (c *Client) Hello(localName string) error {
	if err := validateLine(localName); err != nil {
		return err
	}
	if c.didHello {
		return errors.New("smtp: Hello called after other methods")
	}
	c.localName = localName
	return c.hello()
}

// cmd is a convenience function that sends a command and returns the response
func (c *Client) cmd(expectCode int, format string, args ...any) (int, string, error) {
	id, err := c.Text.Cmd(format, args...)
	if err != nil {
		return 0, "", err
	}
	c.Text.StartResponse(id)
	defer c.Text.EndResponse(id)
	code, msg, err := c.Text.ReadResponse(expectCode)
	return code, msg, err
}

// helo sends the HELO greeting to the server. It should be used only when the
// server does not support ehlo.
func (c *Client) helo() error {
	c.ext = nil
	_, _, err := c.cmd(250, "HELO %s", c.localName)
	return err
}

// ehlo sends the EHLO (extended hello) greeting to the server. It
// should be the preferred greeting for servers that support it.
func (c *Client) ehlo() error {
	_, msg, err := c.cmd(250, "EHLO %s", c.localName)
	if err != nil {
		return err
	}
	ext := make(map[string]string)
	extList := strings.Split(msg, "\n")
	if len(extList) > 1 {
		extList = extList[1:]
		for _, line := range extList {
			k, v, _ := strings.Cut(line, " ")
			ext[k] = v
		}
	}
	if mechs, ok := ext["AUTH"]; ok {
		c.auth = strings.Split(mechs, " ")
	}
	c.ext = ext
	return err
}

// StartTLS sends the STARTTLS command and encrypts all further communication.
// Only servers that advertise the STARTTLS extension support this function.
func (c *Client) StartTLS(config *tls.Config) error {
	if err := c.hello(); err != nil {
		return err
	}
	_, _, err := c.cmd(220, "STARTTLS")
	if err != nil {
		return err
	}
	c.conn = tls.Client(c.conn, config)
	c.Text = textproto.NewConn(c.conn)
	c.tls = true
	return c.ehlo()
}

// TLSConnectionState returns the client's TLS connection state.
// The return values are their zero values if [Client.StartTLS] did
// not succeed.
func (c *Client) TLSConnectionState() (state tls.ConnectionState, ok bool) {
	tc, ok := c.conn.(*tls.Conn)
	if !ok {
		return
	}
	return tc.ConnectionState(), true
}

// Verify checks the validity of an email address on the server.
// If Verify returns nil, the address is valid. A non-nil return
// does not necessarily indicate an invalid address. Many servers
// will not verify addresses for security reasons.
func (c *Client) Verify(addr string) error {
	if err := validateLine(addr); err != nil {
		return err
	}
	if err := c.hello(); err != nil {
		return err
	}
	_, _, err := c.cmd(250, "VRFY %s", addr)
	return err
}

// Auth authenticates a client using the provided authentication mechanism.
// A failed authentication closes the connection.
// Only servers that advertise the AUTH extension support this function.
func (c *Client) Auth(a Auth) error {
	if err := c.hello(); err != nil {
		return err
	}
	encoding := base64.StdEncoding
	mech, resp, err := a.Start(&ServerInfo{c.serverName, c.tls, c.auth})
	if err != nil {
		c.Quit()
		return err
	}
	resp64 := make([]byte, encoding.EncodedLen(len(resp)))
	encoding.Encode(resp64, resp)
	code, msg64, err := c.cmd(0, "%s", strings.TrimSpace(fmt.Sprintf("AUTH %s %s", mech, resp64)))
	for err == nil {
		var msg []byte
		switch code {
		case 334:
			msg, err = encoding.DecodeString(msg64)
		case 235:
			// the last message isn't base64 because it isn't a challenge
			msg = []byte(msg64)
		default:
			err = &textproto.Error{Code: code, Msg: msg64}
		}
		if err == nil {
			resp, err = a.Next(msg, code == 334)
		}
		if err != nil {
			// abort the AUTH
			c.cmd(501, "*")
			c.Quit()
			break
		}
		if resp == nil {
			break
		}
		resp64 = make([]byte, encoding.EncodedLen(len(resp)))
		encoding.Encode(resp64, resp)
		code, msg64, err = c.cmd(0, "%s", resp64)
	}
	return err
}

// Mail issues a MAIL command to the server using the provided email address.
// If the server supports the 8BITMIME extension, Mail adds the BODY=8BITMIME
// parameter. If the server supports the SMTPUTF8 extension, Mail adds the
// SMTPUTF8 parameter.
// This initiates a mail transaction and is followed by one or more [Client.Rcpt] calls.
func (c *Client) Mail(from string) error {
	if err := validateLine(from); err != nil {
		return err
	}
	if err := c.hello(); err != nil {
		return err
	}
	cmdStr := "MAIL FROM:<%s>"
	if c.ext != nil {
		if _, ok := c.ext["8BITMIME"]; ok {
			cmdStr += " BODY=8BITMIME"
		}
		if _, ok := c.ext["SMTPUTF8"]; ok {
			cmdStr += " SMTPUTF8"
		}
	}
	_, _, err := c.cmd(250, cmdStr, from)
	return err
}

// Rcpt issues a RCPT command to the server using the provided email address.
// A call to Rcpt must be preceded by a call to [Client.Mail] and may be followed by
// a [Client.Data] call or another Rcpt call.
func (c *Client) Rcpt(to string) error {
	if err := validateLine(to); err != nil {
		return err
	}
	_, _, err := c.cmd(25, "RCPT TO:<%s>", to)
	return err
}

type dataCloser struct {
	c *Client
	io.WriteCloser
}

func (d *dataCloser) Close() error {
	d.WriteCloser.Close()
	_, _, err := d.c.Text.ReadResponse(250)
	return err
}

// Data issues a DATA command to the server and returns a writer that
// can be used to write the mail headers and body. The caller should
// close the writer before calling any more methods on c. A call to
// Data must be preceded by one or more calls to [Client.Rcpt].
func (c *Client) Data() (io.WriteCloser, error) {
	_, _, err := c.cmd(354, "DATA")
	if err != nil {
		return nil, err
	}
	return &dataCloser{c, c.Text.DotWriter()}, nil
}

var testHookStartTLS func(*tls.Config) // nil, except for tests

// SendMail connects to the server at addr, switches to TLS if
// possible, authenticates with the optional mechanism a if possible,
// and then sends an email from address from, to addresses to, with
// message msg.
// The addr must include a port, as in "mail.example.com:smtp".
//
// The addresses in the to parameter are the SMTP RCPT addresses.
//
// The msg parameter should be an RFC 822-style email with headers
// first, a blank line, and then the message body. The lines of msg
// should be CRLF terminated. The msg headers should usually include
// fields such as "From", "To", "Subject", and "Cc".  Sending "Bcc"
// messages is accomplished by including an email address in the to
// parameter but not including it in the msg headers.
//
// The SendMail function and the net/smtp package are low-level
// mechanisms and provide no support for DKIM signing, MIME
// attachments (see the mime/multipart package), or other mail
// functionality. Higher-level packages exist outside of the standard
// library.
func SendMail(addr string, a Auth, from string, to []string, msg []byte) error {
	if err := validateLine(from); err != nil {
		return err
	}
	for _, recp := range to {
		if err := validateLine(recp); err != nil {
			return err
		}
	}
	c, err := Dial(addr)
	if err != nil {
		return err
	}
	defer c.Close()
	if err = c.hello(); err != nil {
		return err
	}
	if ok, _ := c.Extension("STARTTLS"); ok {
		config := &tls.Config{ServerName: c.serverName}
		if testHookStartTLS != nil {
			testHookStartTLS(config)
		}
		if err = c.StartTLS(config); err != nil {
			return err
		}
	}
	if a != nil && c.ext != nil {
		if _, ok := c.ext["AUTH"]; !ok {
			return errors.New("smtp: server doesn't support AUTH")
		}
		if err = c.Auth(a); err != nil {
			return err
		}
	}
	if err = c.Mail(from); err != nil {
		return err
	}
	for _, addr := range to {
		if err = c.Rcpt(addr); err != nil {
			return err
		}
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	_, err = w.Write(msg)
	if err != nil {
		return err
	}
	err = w.Close()
	if err != nil {
		return err
	}
	return c.Quit()
}

// Extension reports whether an extension is support by the server.
// The extension name is case-insensitive. If the extension is supported,
// Extension also returns a string that contains any parameters the
// server specifies for the extension.
func (c *Client) Extension(ext string) (bool, string) {
	if err := c.hello(); err != nil {
		return false, ""
	}
	if c.ext == nil {
		return false, ""
	}
	ext = strings.ToUpper(ext)
	param, ok := c.ext[ext]
	return ok, param
}

// Reset sends the RSET command to the server, aborting the current mail
// transaction.
func (c *Client) Reset() error {
	if err := c.hello(); err != nil {
		return err
	}
	_, _, err := c.cmd(250, "RSET")
	return err
}

// Noop sends the NOOP command to the server. It does nothing but check
// that the connection to the server is okay.
func (c *Client) Noop() error {
	if err := c.hello(); err != nil {
		return err
	}
	_, _, err := c.cmd(250, "NOOP")
	return err
}

// Quit sends the QUIT command and closes the connection to the server.
func (c *Client) Quit() error {
	c.hello() // ignore error; we're quitting anyhow
	_, _, err := c.cmd(221, "QUIT")
	if err != nil {
		return err
	}
	return c.Text.Close()
}

// validateLine checks to see if a line has CR or LF as per RFC 5321.
func validateLine(line string) error {
	if strings.ContainsAny(line, "\n\r") {
		return errors.New("smtp: A line must not contain CR or LF")
	}
	return nil
}
```