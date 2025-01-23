Response:
Let's break down the thought process for analyzing the provided Go code snippet.

**1. Understanding the Request:**

The request asks for a breakdown of the provided Go code for `go/src/net/mail/message.go`. The specific requirements include:

* **Functionality Listing:** What does this code do?
* **Go Feature Identification:** What Go language features does it implement?
* **Code Examples:** Demonstrate the identified features with Go code. Include input/output for code reasoning.
* **Command-Line Arguments:**  Describe any command-line argument handling (though, in this case, unlikely for a library).
* **Common Pitfalls:**  Highlight areas where users might make mistakes.
* **Chinese Output:**  All answers must be in Chinese.

**2. Initial Code Scan and High-Level Understanding:**

A quick read-through reveals the following key aspects:

* **Package `mail`:**  This immediately signals that the code is related to email handling.
* **Comments and RFC References:** The initial comments explicitly mention RFC 5322 and RFC 6532, confirming the email focus and hinting at parsing functionalities. The comments also highlight specific deviations from the RFCs.
* **`Message` struct:** This structure likely represents a parsed email message, containing headers and a body.
* **`ReadMessage` function:** This strongly suggests the code can read and parse an email message from an `io.Reader`.
* **`Header` type:** A map to store email headers.
* **Parsing Functions:** Functions like `readHeader`, `ParseDate`, `ParseAddress`, `ParseAddressList`, and the `addrParser` struct indicate the core functionality is parsing different parts of an email message.
* **Helper Functions:**  Functions like `isAtext`, `isQtext`, `quoteString`, etc., are likely utility functions for parsing according to the email standards.

**3. Deeper Dive and Functional Analysis:**

Now, let's examine the code more systematically, focusing on identifying specific functionalities:

* **Reading Email Messages (`ReadMessage`):**  This is a primary function. It uses `bufio.NewReader` and `textproto.NewReader` for efficient reading and header parsing. It separates the headers and the body.
* **Parsing Headers (`readHeader`):**  This function handles the specific rules for parsing email headers, noting its divergence from `net/textproto` for RFC 5322 compliance. It iterates through lines, splitting keys and values.
* **Parsing Dates (`ParseDate`):** This function attempts to parse dates according to various RFC 5322 defined formats. It uses `time.Parse` and pre-defined layouts.
* **Handling Headers (`Header` type and methods):** The `Header` type provides a convenient way to access and manipulate email headers. The `Get`, `Date`, and `AddressList` methods offer specific functionalities.
* **Parsing Email Addresses (`Address`, `ParseAddress`, `ParseAddressList`, `AddressParser`, `addrParser`):** A significant portion of the code is dedicated to parsing email addresses according to RFC 5322. The `addrParser` struct is the core parser, and there are various helper functions to handle different parts of an address (local-part, domain, display name, quoted strings, atoms, etc.). The `AddressParser` allows for custom word decoding (RFC 2047).
* **Formatting Email Addresses (`Address.String()`):**  The code can also format an `Address` struct back into a string representation, handling cases with non-ASCII characters using RFC 2047 encoding.
* **Handling Comments and Quoted Strings:**  The parser includes logic to deal with comments and quoted strings within email addresses and headers.
* **RFC 2047 Decoding:** The code incorporates decoding of RFC 2047 encoded words, which are used to represent non-ASCII characters in headers.

**4. Identifying Go Language Features:**

As the functionality is analyzed, corresponding Go features become apparent:

* **`package`:**  Defines the `mail` package.
* **`import`:** Imports necessary standard library packages (`bufio`, `errors`, `fmt`, `io`, etc.).
* **`struct`:** Defines the `Message` and `Address` data structures.
* **`map`:**  Used for the `Header` type.
* **`interface` (`io.Reader`):** Used for representing the message body and input streams.
* **Functions:**  Numerous functions implement the parsing logic.
* **Methods:** Methods are defined on the `Message`, `Header`, and `Address` types.
* **Error Handling:**  Uses the `error` interface and `errors.New`.
* **Constants and Variables:**  `debug`, `dateLayouts`, `rfc2047Decoder`.
* **`sync.Once`:** Used for lazy initialization of `dateLayouts`.
* **Closures (Anonymous Functions):** Used in `buildDateLayouts` and `decodeRFC2047Word`.
* **String Manipulation:**  Extensive use of the `strings` package.
* **Unicode Support:**  Uses the `unicode/utf8` package for handling UTF-8 encoded characters.
* **Time Parsing:** Uses the `time` package for parsing dates.
* **Networking (`net` package):** Used for parsing IP addresses in domain literals.
* **MIME (`mime` package):** Used for word decoding (RFC 2047).

**5. Constructing Code Examples:**

Based on the identified features, create illustrative code snippets. Crucially, provide clear input and expected output for each example to demonstrate the functionality and aid in reasoning. For example, for `ReadMessage`, provide a sample email string as input and show how to access the parsed header and body.

**6. Identifying Common Pitfalls:**

Think about potential issues users might encounter:

* **Incorrect Date Format:** Providing a date string that doesn't match the expected RFC 5322 formats.
* **Malformed Email Addresses:**  Providing addresses that violate the RFC 5322 syntax rules (missing '@', unclosed angle brackets, etc.).
* **Case Sensitivity of Headers (subtle):**  While `Get` is case-insensitive, direct map access is not. This could lead to confusion.
* **Assuming Strict RFC Compliance (deviations):**  Users might expect the parser to behave exactly according to RFC 5322, but the comments highlight some deviations.

**7. Structuring the Output (Chinese):**

Organize the findings logically according to the request's structure. Use clear and concise Chinese to explain each point. Provide code examples with Chinese comments where necessary.

**Self-Correction/Refinement:**

* **Initial thought:**  "This code just parses emails."  **Refinement:**  Be more specific. It parses *RFC 5322 compliant* email messages (with some noted deviations).
* **Initial thought:** "Just show a simple example of reading a message." **Refinement:** Show how to access both the header and the body. Show examples of parsing dates and addresses as well.
* **Initial thought:** "Don't need to explain every single helper function." **Refinement:** Focus on the main functionalities and only mention helper functions when directly relevant to explaining those functionalities.
* **Initial thought:** "Just translate the code comments." **Refinement:**  Explain the *purpose* of the code, not just what it literally says.

By following this structured approach, iteratively analyzing the code, and refining the explanations, we arrive at the comprehensive and accurate response provided earlier.
这段代码是 Go 语言标准库 `net/mail` 包中 `message.go` 文件的一部分，它主要负责**解析电子邮件消息**。

以下是它的主要功能：

1. **解析邮件消息结构:**
   - `Message` 结构体定义了一个已解析的邮件消息，包含 `Header`（邮件头）和 `Body`（邮件体）。
   - `ReadMessage(r io.Reader)` 函数从一个 `io.Reader` 中读取邮件内容，并将它解析成 `Message` 结构体。它会解析邮件头，并将邮件体部分以 `io.Reader` 的形式保存在 `msg.Body` 中。

2. **解析邮件头 (`Header`):**
   - `Header` 类型是一个 `map[string][]string`，用于存储邮件头部的键值对。键是规范化的 MIME 头部键（例如 "Content-Type"），值是字符串切片，因为一个头部键可能对应多个值。
   - `readHeader(r *textproto.Reader)` 函数负责从 `textproto.Reader` 中读取并解析邮件头。它与 `net/textproto.ReadMIMEHeader` 类似，但更符合 RFC 5322 的宽松规范，允许一些在 HTTP 头部中不允许的格式。
   - `Header.Get(key string)` 方法用于获取指定键的第一个值（不区分大小写）。
   - `Header.Date()` 方法用于解析 "Date" 头部字段，返回一个 `time.Time` 类型的时间。
   - `Header.AddressList(key string)` 方法用于解析包含邮件地址列表的头部字段（例如 "To", "From"），返回一个 `[]*Address` 切片。

3. **解析日期 (`ParseDate`):**
   - `ParseDate(date string)` 函数尝试解析符合 RFC 5322 规范的日期字符串，将其转换为 `time.Time` 类型。它会尝试多种日期格式进行解析。

4. **解析邮件地址 (`Address`, `ParseAddress`, `ParseAddressList`):**
   - `Address` 结构体表示一个邮件地址，包含 `Name`（显示名称）和 `Address`（实际的 email 地址）。
   - `ParseAddress(address string)` 函数解析单个 RFC 5322 格式的邮件地址字符串。
   - `ParseAddressList(list string)` 函数解析一个包含多个邮件地址的字符串，地址之间用逗号分隔。
   - `AddressParser` 结构体提供了一种更灵活的方式来解析邮件地址，它允许自定义 `mime.WordDecoder` 来处理 RFC 2047 编码的词。

5. **格式化邮件地址 (`Address.String()`):**
   - `Address.String()` 方法将 `Address` 结构体格式化成一个符合 RFC 5322 规范的邮件地址字符串。如果 `Name` 包含非 ASCII 字符，它会根据 RFC 2047 进行编码。

6. **内部的地址解析器 (`addrParser`):**
   - `addrParser` 结构体是实现邮件地址解析的核心部分。它包含了一些方法来解析地址的各个组成部分，例如：
     - `parseAddressList()`: 解析地址列表。
     - `parseSingleAddress()`: 解析单个地址。
     - `consumeAddrSpec()`: 解析地址的规范部分 (local-part@domain)。
     - `consumePhrase()`: 解析地址中的短语（例如显示名称）。
     - `consumeQuotedString()`: 解析带引号的字符串。
     - `consumeAtom()`: 解析原子（不包含空格和特殊字符的字符串）。
     - `consumeDomainLiteral()`: 解析域名中的字面量（例如 IP 地址）。
     - `consumeComment()`: 解析注释。
     - `decodeRFC2047Word()`: 解码 RFC 2047 编码的词。

**它是什么 Go 语言功能的实现？**

这个文件主要实现了 Go 语言中处理电子邮件消息的功能，特别是**邮件头的解析和邮件地址的解析**。它并没有直接涉及发送邮件，而是专注于理解和提取邮件内容中的信息。

**Go 代码举例说明:**

假设我们有一个包含邮件内容的字符串：

```go
package main

import (
	"fmt"
	"net/mail"
	"strings"
)

func main() {
	rawMessage := `From: sender@example.com
To: recipient1@example.com, "Recipient Two" <recipient2@example.com>
Date: Mon, 10 Jul 2023 10:00:00 +0000
Subject: Test Email

This is the body of the email.
`

	r := strings.NewReader(rawMessage)
	msg, err := mail.ReadMessage(r)
	if err != nil {
		fmt.Println("Error reading message:", err)
		return
	}

	fmt.Println("Headers:")
	for key, values := range msg.Header {
		fmt.Printf("%s: %v\n", key, values)
	}

	fmt.Println("\nBody:")
	bodyBuf := new(strings.Builder)
	_, err = bodyBuf.ReadFrom(msg.Body)
	if err != nil {
		fmt.Println("Error reading body:", err)
		return
	}
	fmt.Println(bodyBuf.String())

	date, err := msg.Header.Date()
	if err != nil {
		fmt.Println("Error parsing date:", err)
	} else {
		fmt.Println("\nParsed Date:", date)
	}

	fromAddress, err := mail.ParseAddress(msg.Header.Get("From"))
	if err != nil {
		fmt.Println("Error parsing From address:", err)
	} else {
		fmt.Println("\nParsed From Address:", fromAddress)
	}

	toAddresses, err := msg.Header.AddressList("To")
	if err != nil {
		fmt.Println("Error parsing To addresses:", err)
	} else {
		fmt.Println("\nParsed To Addresses:", toAddresses)
	}
}
```

**假设的输入与输出:**

**输入 (rawMessage):**

```
From: sender@example.com
To: recipient1@example.com, "Recipient Two" <recipient2@example.com>
Date: Mon, 10 Jul 2023 10:00:00 +0000
Subject: Test Email

This is the body of the email.
```

**输出:**

```
Headers:
From: [sender@example.com]
To: [recipient1@example.com Recipient Two <recipient2@example.com>]
Date: [Mon, 10 Jul 2023 10:00:00 +0000]
Subject: [Test Email]

Body:
This is the body of the email.

Parsed Date: 2023-07-10 10:00:00 +0000 UTC

Parsed From Address: sender@example.com

Parsed To Addresses: [{ recipient1@example.com} {Recipient Two recipient2@example.com}]
```

**命令行参数的具体处理:**

这个文件本身是一个库，不直接处理命令行参数。它的功能是被其他程序调用来解析邮件内容。 如果你需要处理包含邮件内容的文件，你需要编写一个程序来读取文件内容，然后将其传递给 `mail.ReadMessage` 函数。

例如，你可以创建一个简单的命令行工具来读取并打印邮件头：

```go
package main

import (
	"fmt"
	"net/mail"
	"os"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Println("Usage: go run main.go <email_file>")
		return
	}

	filename := os.Args[1]
	file, err := os.Open(filename)
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer file.Close()

	msg, err := mail.ReadMessage(file)
	if err != nil {
		fmt.Println("Error reading message:", err)
		return
	}

	fmt.Println("Headers:")
	for key, values := range msg.Header {
		fmt.Printf("%s: %v\n", key, values)
	}
}
```

你可以使用如下命令运行：

```bash
go run main.go my_email.txt
```

其中 `my_email.txt` 是包含邮件内容的文件。

**使用者易犯错的点:**

1. **假设邮件头键的大小写敏感性:** 虽然 `Header.Get()` 方法不区分大小写，但直接访问 `Header` map 时是区分大小写的。因此，应该始终使用 `textproto.CanonicalMIMEHeaderKey` 对头部键进行规范化，或者使用 `Get()` 方法。

   ```go
   // 错误的做法：
   subject := msg.Header["subject"][0] // 可能找不到

   // 正确的做法：
   subject := msg.Header.Get("Subject")

   // 或者：
   canonicalKey := textproto.CanonicalMIMEHeaderKey("subject")
   subject := msg.Header[canonicalKey][0]
   ```

2. **错误地处理多个同名头部字段:**  一个邮件头可能包含多个同名的字段（例如 "Received" 头部）。 使用 `Get()` 只能获取第一个值。如果需要获取所有值，必须直接访问 `Header` map。

   ```go
   // 如果邮件有多个 "Received" 头部：
   receivedHeaders := msg.Header["Received"]
   for _, header := range receivedHeaders {
       fmt.Println("Received:", header)
   }
   ```

3. **日期格式不匹配:** `ParseDate` 函数只能解析符合 RFC 5322 规范的日期格式。如果邮件头中的 "Date" 字段使用了其他格式，解析将会失败。

4. **地址解析的复杂性:** 邮件地址的格式非常灵活，解析规则也比较复杂。开发者可能会错误地假设邮件地址总是简单的 `user@domain` 格式，而忽略了显示名称、注释、带引号的部分等。应该使用 `mail.ParseAddress` 或 `mail.ParseAddressList` 来正确解析。

5. **忽略错误处理:**  所有解析函数都可能返回错误，应该始终检查错误并进行适当的处理，例如 `ReadMessage`, `Header.Date`, `Header.AddressList`, `mail.ParseAddress` 等。

总而言之，`go/src/net/mail/message.go` 提供了一套用于解析电子邮件消息的工具，开发者需要理解邮件消息的结构和相关的 RFC 规范，并小心处理可能出现的各种格式和错误情况。

### 提示词
```
这是路径为go/src/net/mail/message.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/*
Package mail implements parsing of mail messages.

For the most part, this package follows the syntax as specified by RFC 5322 and
extended by RFC 6532.
Notable divergences:
  - Obsolete address formats are not parsed, including addresses with
    embedded route information.
  - The full range of spacing (the CFWS syntax element) is not supported,
    such as breaking addresses across lines.
  - No unicode normalization is performed.
  - A leading From line is permitted, as in mbox format (RFC 4155).
*/
package mail

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net"
	"net/textproto"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

var debug = debugT(false)

type debugT bool

func (d debugT) Printf(format string, args ...any) {
	if d {
		log.Printf(format, args...)
	}
}

// A Message represents a parsed mail message.
type Message struct {
	Header Header
	Body   io.Reader
}

// ReadMessage reads a message from r.
// The headers are parsed, and the body of the message will be available
// for reading from msg.Body.
func ReadMessage(r io.Reader) (msg *Message, err error) {
	tp := textproto.NewReader(bufio.NewReader(r))

	hdr, err := readHeader(tp)
	if err != nil && (err != io.EOF || len(hdr) == 0) {
		return nil, err
	}

	return &Message{
		Header: Header(hdr),
		Body:   tp.R,
	}, nil
}

// readHeader reads the message headers from r.
// This is like textproto.ReadMIMEHeader, but doesn't validate.
// The fix for issue #53188 tightened up net/textproto to enforce
// restrictions of RFC 7230.
// This package implements RFC 5322, which does not have those restrictions.
// This function copies the relevant code from net/textproto,
// simplified for RFC 5322.
func readHeader(r *textproto.Reader) (map[string][]string, error) {
	m := make(map[string][]string)

	// The first line cannot start with a leading space.
	if buf, err := r.R.Peek(1); err == nil && (buf[0] == ' ' || buf[0] == '\t') {
		line, err := r.ReadLine()
		if err != nil {
			return m, err
		}
		return m, errors.New("malformed initial line: " + line)
	}

	for {
		kv, err := r.ReadContinuedLine()
		if kv == "" {
			return m, err
		}

		// Key ends at first colon.
		k, v, ok := strings.Cut(kv, ":")
		if !ok {
			return m, errors.New("malformed header line: " + kv)
		}
		key := textproto.CanonicalMIMEHeaderKey(k)

		// Permit empty key, because that is what we did in the past.
		if key == "" {
			continue
		}

		// Skip initial spaces in value.
		value := strings.TrimLeft(v, " \t")

		m[key] = append(m[key], value)

		if err != nil {
			return m, err
		}
	}
}

// Layouts suitable for passing to time.Parse.
// These are tried in order.
var (
	dateLayoutsBuildOnce sync.Once
	dateLayouts          []string
)

func buildDateLayouts() {
	// Generate layouts based on RFC 5322, section 3.3.

	dows := [...]string{"", "Mon, "}   // day-of-week
	days := [...]string{"2", "02"}     // day = 1*2DIGIT
	years := [...]string{"2006", "06"} // year = 4*DIGIT / 2*DIGIT
	seconds := [...]string{":05", ""}  // second
	// "-0700 (MST)" is not in RFC 5322, but is common.
	zones := [...]string{"-0700", "MST", "UT"} // zone = (("+" / "-") 4DIGIT) / "UT" / "GMT" / ...

	for _, dow := range dows {
		for _, day := range days {
			for _, year := range years {
				for _, second := range seconds {
					for _, zone := range zones {
						s := dow + day + " Jan " + year + " 15:04" + second + " " + zone
						dateLayouts = append(dateLayouts, s)
					}
				}
			}
		}
	}
}

// ParseDate parses an RFC 5322 date string.
func ParseDate(date string) (time.Time, error) {
	dateLayoutsBuildOnce.Do(buildDateLayouts)
	// CR and LF must match and are tolerated anywhere in the date field.
	date = strings.ReplaceAll(date, "\r\n", "")
	if strings.Contains(date, "\r") {
		return time.Time{}, errors.New("mail: header has a CR without LF")
	}
	// Re-using some addrParser methods which support obsolete text, i.e. non-printable ASCII
	p := addrParser{date, nil}
	p.skipSpace()

	// RFC 5322: zone = (FWS ( "+" / "-" ) 4DIGIT) / obs-zone
	// zone length is always 5 chars unless obsolete (obs-zone)
	if ind := strings.IndexAny(p.s, "+-"); ind != -1 && len(p.s) >= ind+5 {
		date = p.s[:ind+5]
		p.s = p.s[ind+5:]
	} else {
		ind := strings.Index(p.s, "T")
		if ind == 0 {
			// In this case we have the following date formats:
			// * Thu, 20 Nov 1997 09:55:06 MDT
			// * Thu, 20 Nov 1997 09:55:06 MDT (MDT)
			// * Thu, 20 Nov 1997 09:55:06 MDT (This comment)
			ind = strings.Index(p.s[1:], "T")
			if ind != -1 {
				ind++
			}
		}

		if ind != -1 && len(p.s) >= ind+5 {
			// The last letter T of the obsolete time zone is checked when no standard time zone is found.
			// If T is misplaced, the date to parse is garbage.
			date = p.s[:ind+1]
			p.s = p.s[ind+1:]
		}
	}
	if !p.skipCFWS() {
		return time.Time{}, errors.New("mail: misformatted parenthetical comment")
	}
	for _, layout := range dateLayouts {
		t, err := time.Parse(layout, date)
		if err == nil {
			return t, nil
		}
	}
	return time.Time{}, errors.New("mail: header could not be parsed")
}

// A Header represents the key-value pairs in a mail message header.
type Header map[string][]string

// Get gets the first value associated with the given key.
// It is case insensitive; CanonicalMIMEHeaderKey is used
// to canonicalize the provided key.
// If there are no values associated with the key, Get returns "".
// To access multiple values of a key, or to use non-canonical keys,
// access the map directly.
func (h Header) Get(key string) string {
	return textproto.MIMEHeader(h).Get(key)
}

var ErrHeaderNotPresent = errors.New("mail: header not in message")

// Date parses the Date header field.
func (h Header) Date() (time.Time, error) {
	hdr := h.Get("Date")
	if hdr == "" {
		return time.Time{}, ErrHeaderNotPresent
	}
	return ParseDate(hdr)
}

// AddressList parses the named header field as a list of addresses.
func (h Header) AddressList(key string) ([]*Address, error) {
	hdr := h.Get(key)
	if hdr == "" {
		return nil, ErrHeaderNotPresent
	}
	return ParseAddressList(hdr)
}

// Address represents a single mail address.
// An address such as "Barry Gibbs <bg@example.com>" is represented
// as Address{Name: "Barry Gibbs", Address: "bg@example.com"}.
type Address struct {
	Name    string // Proper name; may be empty.
	Address string // user@domain
}

// ParseAddress parses a single RFC 5322 address, e.g. "Barry Gibbs <bg@example.com>"
func ParseAddress(address string) (*Address, error) {
	return (&addrParser{s: address}).parseSingleAddress()
}

// ParseAddressList parses the given string as a list of addresses.
func ParseAddressList(list string) ([]*Address, error) {
	return (&addrParser{s: list}).parseAddressList()
}

// An AddressParser is an RFC 5322 address parser.
type AddressParser struct {
	// WordDecoder optionally specifies a decoder for RFC 2047 encoded-words.
	WordDecoder *mime.WordDecoder
}

// Parse parses a single RFC 5322 address of the
// form "Gogh Fir <gf@example.com>" or "foo@example.com".
func (p *AddressParser) Parse(address string) (*Address, error) {
	return (&addrParser{s: address, dec: p.WordDecoder}).parseSingleAddress()
}

// ParseList parses the given string as a list of comma-separated addresses
// of the form "Gogh Fir <gf@example.com>" or "foo@example.com".
func (p *AddressParser) ParseList(list string) ([]*Address, error) {
	return (&addrParser{s: list, dec: p.WordDecoder}).parseAddressList()
}

// String formats the address as a valid RFC 5322 address.
// If the address's name contains non-ASCII characters
// the name will be rendered according to RFC 2047.
func (a *Address) String() string {
	// Format address local@domain
	at := strings.LastIndex(a.Address, "@")
	var local, domain string
	if at < 0 {
		// This is a malformed address ("@" is required in addr-spec);
		// treat the whole address as local-part.
		local = a.Address
	} else {
		local, domain = a.Address[:at], a.Address[at+1:]
	}

	// Add quotes if needed
	quoteLocal := false
	for i, r := range local {
		if isAtext(r, false) {
			continue
		}
		if r == '.' {
			// Dots are okay if they are surrounded by atext.
			// We only need to check that the previous byte is
			// not a dot, and this isn't the end of the string.
			if i > 0 && local[i-1] != '.' && i < len(local)-1 {
				continue
			}
		}
		quoteLocal = true
		break
	}
	if quoteLocal {
		local = quoteString(local)

	}

	s := "<" + local + "@" + domain + ">"

	if a.Name == "" {
		return s
	}

	// If every character is printable ASCII, quoting is simple.
	allPrintable := true
	for _, r := range a.Name {
		// isWSP here should actually be isFWS,
		// but we don't support folding yet.
		if !isVchar(r) && !isWSP(r) || isMultibyte(r) {
			allPrintable = false
			break
		}
	}
	if allPrintable {
		return quoteString(a.Name) + " " + s
	}

	// Text in an encoded-word in a display-name must not contain certain
	// characters like quotes or parentheses (see RFC 2047 section 5.3).
	// When this is the case encode the name using base64 encoding.
	if strings.ContainsAny(a.Name, "\"#$%&'(),.:;<>@[]^`{|}~") {
		return mime.BEncoding.Encode("utf-8", a.Name) + " " + s
	}
	return mime.QEncoding.Encode("utf-8", a.Name) + " " + s
}

type addrParser struct {
	s   string
	dec *mime.WordDecoder // may be nil
}

func (p *addrParser) parseAddressList() ([]*Address, error) {
	var list []*Address
	for {
		p.skipSpace()

		// allow skipping empty entries (RFC5322 obs-addr-list)
		if p.consume(',') {
			continue
		}

		addrs, err := p.parseAddress(true)
		if err != nil {
			return nil, err
		}
		list = append(list, addrs...)

		if !p.skipCFWS() {
			return nil, errors.New("mail: misformatted parenthetical comment")
		}
		if p.empty() {
			break
		}
		if p.peek() != ',' {
			return nil, errors.New("mail: expected comma")
		}

		// Skip empty entries for obs-addr-list.
		for p.consume(',') {
			p.skipSpace()
		}
		if p.empty() {
			break
		}
	}
	return list, nil
}

func (p *addrParser) parseSingleAddress() (*Address, error) {
	addrs, err := p.parseAddress(true)
	if err != nil {
		return nil, err
	}
	if !p.skipCFWS() {
		return nil, errors.New("mail: misformatted parenthetical comment")
	}
	if !p.empty() {
		return nil, fmt.Errorf("mail: expected single address, got %q", p.s)
	}
	if len(addrs) == 0 {
		return nil, errors.New("mail: empty group")
	}
	if len(addrs) > 1 {
		return nil, errors.New("mail: group with multiple addresses")
	}
	return addrs[0], nil
}

// parseAddress parses a single RFC 5322 address at the start of p.
func (p *addrParser) parseAddress(handleGroup bool) ([]*Address, error) {
	debug.Printf("parseAddress: %q", p.s)
	p.skipSpace()
	if p.empty() {
		return nil, errors.New("mail: no address")
	}

	// address = mailbox / group
	// mailbox = name-addr / addr-spec
	// group = display-name ":" [group-list] ";" [CFWS]

	// addr-spec has a more restricted grammar than name-addr,
	// so try parsing it first, and fallback to name-addr.
	// TODO(dsymonds): Is this really correct?
	spec, err := p.consumeAddrSpec()
	if err == nil {
		var displayName string
		p.skipSpace()
		if !p.empty() && p.peek() == '(' {
			displayName, err = p.consumeDisplayNameComment()
			if err != nil {
				return nil, err
			}
		}

		return []*Address{{
			Name:    displayName,
			Address: spec,
		}}, err
	}
	debug.Printf("parseAddress: not an addr-spec: %v", err)
	debug.Printf("parseAddress: state is now %q", p.s)

	// display-name
	var displayName string
	if p.peek() != '<' {
		displayName, err = p.consumePhrase()
		if err != nil {
			return nil, err
		}
	}
	debug.Printf("parseAddress: displayName=%q", displayName)

	p.skipSpace()
	if handleGroup {
		if p.consume(':') {
			return p.consumeGroupList()
		}
	}
	// angle-addr = "<" addr-spec ">"
	if !p.consume('<') {
		atext := true
		for _, r := range displayName {
			if !isAtext(r, true) {
				atext = false
				break
			}
		}
		if atext {
			// The input is like "foo.bar"; it's possible the input
			// meant to be "foo.bar@domain", or "foo.bar <...>".
			return nil, errors.New("mail: missing '@' or angle-addr")
		}
		// The input is like "Full Name", which couldn't possibly be a
		// valid email address if followed by "@domain"; the input
		// likely meant to be "Full Name <...>".
		return nil, errors.New("mail: no angle-addr")
	}
	spec, err = p.consumeAddrSpec()
	if err != nil {
		return nil, err
	}
	if !p.consume('>') {
		return nil, errors.New("mail: unclosed angle-addr")
	}
	debug.Printf("parseAddress: spec=%q", spec)

	return []*Address{{
		Name:    displayName,
		Address: spec,
	}}, nil
}

func (p *addrParser) consumeGroupList() ([]*Address, error) {
	var group []*Address
	// handle empty group.
	p.skipSpace()
	if p.consume(';') {
		if !p.skipCFWS() {
			return nil, errors.New("mail: misformatted parenthetical comment")
		}
		return group, nil
	}

	for {
		p.skipSpace()
		// embedded groups not allowed.
		addrs, err := p.parseAddress(false)
		if err != nil {
			return nil, err
		}
		group = append(group, addrs...)

		if !p.skipCFWS() {
			return nil, errors.New("mail: misformatted parenthetical comment")
		}
		if p.consume(';') {
			if !p.skipCFWS() {
				return nil, errors.New("mail: misformatted parenthetical comment")
			}
			break
		}
		if !p.consume(',') {
			return nil, errors.New("mail: expected comma")
		}
	}
	return group, nil
}

// consumeAddrSpec parses a single RFC 5322 addr-spec at the start of p.
func (p *addrParser) consumeAddrSpec() (spec string, err error) {
	debug.Printf("consumeAddrSpec: %q", p.s)

	orig := *p
	defer func() {
		if err != nil {
			*p = orig
		}
	}()

	// local-part = dot-atom / quoted-string
	var localPart string
	p.skipSpace()
	if p.empty() {
		return "", errors.New("mail: no addr-spec")
	}
	if p.peek() == '"' {
		// quoted-string
		debug.Printf("consumeAddrSpec: parsing quoted-string")
		localPart, err = p.consumeQuotedString()
		if localPart == "" {
			err = errors.New("mail: empty quoted string in addr-spec")
		}
	} else {
		// dot-atom
		debug.Printf("consumeAddrSpec: parsing dot-atom")
		localPart, err = p.consumeAtom(true, false)
	}
	if err != nil {
		debug.Printf("consumeAddrSpec: failed: %v", err)
		return "", err
	}

	if !p.consume('@') {
		return "", errors.New("mail: missing @ in addr-spec")
	}

	// domain = dot-atom / domain-literal
	var domain string
	p.skipSpace()
	if p.empty() {
		return "", errors.New("mail: no domain in addr-spec")
	}

	if p.peek() == '[' {
		// domain-literal
		domain, err = p.consumeDomainLiteral()
		if err != nil {
			return "", err
		}
	} else {
		// dot-atom
		domain, err = p.consumeAtom(true, false)
		if err != nil {
			return "", err
		}
	}

	return localPart + "@" + domain, nil
}

// consumePhrase parses the RFC 5322 phrase at the start of p.
func (p *addrParser) consumePhrase() (phrase string, err error) {
	debug.Printf("consumePhrase: [%s]", p.s)
	// phrase = 1*word
	var words []string
	var isPrevEncoded bool
	for {
		// obs-phrase allows CFWS after one word
		if len(words) > 0 {
			if !p.skipCFWS() {
				return "", errors.New("mail: misformatted parenthetical comment")
			}
		}
		// word = atom / quoted-string
		var word string
		p.skipSpace()
		if p.empty() {
			break
		}
		isEncoded := false
		if p.peek() == '"' {
			// quoted-string
			word, err = p.consumeQuotedString()
		} else {
			// atom
			// We actually parse dot-atom here to be more permissive
			// than what RFC 5322 specifies.
			word, err = p.consumeAtom(true, true)
			if err == nil {
				word, isEncoded, err = p.decodeRFC2047Word(word)
			}
		}

		if err != nil {
			break
		}
		debug.Printf("consumePhrase: consumed %q", word)
		if isPrevEncoded && isEncoded {
			words[len(words)-1] += word
		} else {
			words = append(words, word)
		}
		isPrevEncoded = isEncoded
	}
	// Ignore any error if we got at least one word.
	if err != nil && len(words) == 0 {
		debug.Printf("consumePhrase: hit err: %v", err)
		return "", fmt.Errorf("mail: missing word in phrase: %v", err)
	}
	phrase = strings.Join(words, " ")
	return phrase, nil
}

// consumeQuotedString parses the quoted string at the start of p.
func (p *addrParser) consumeQuotedString() (qs string, err error) {
	// Assume first byte is '"'.
	i := 1
	qsb := make([]rune, 0, 10)

	escaped := false

Loop:
	for {
		r, size := utf8.DecodeRuneInString(p.s[i:])

		switch {
		case size == 0:
			return "", errors.New("mail: unclosed quoted-string")

		case size == 1 && r == utf8.RuneError:
			return "", fmt.Errorf("mail: invalid utf-8 in quoted-string: %q", p.s)

		case escaped:
			//  quoted-pair = ("\" (VCHAR / WSP))

			if !isVchar(r) && !isWSP(r) {
				return "", fmt.Errorf("mail: bad character in quoted-string: %q", r)
			}

			qsb = append(qsb, r)
			escaped = false

		case isQtext(r) || isWSP(r):
			// qtext (printable US-ASCII excluding " and \), or
			// FWS (almost; we're ignoring CRLF)
			qsb = append(qsb, r)

		case r == '"':
			break Loop

		case r == '\\':
			escaped = true

		default:
			return "", fmt.Errorf("mail: bad character in quoted-string: %q", r)

		}

		i += size
	}
	p.s = p.s[i+1:]
	return string(qsb), nil
}

// consumeAtom parses an RFC 5322 atom at the start of p.
// If dot is true, consumeAtom parses an RFC 5322 dot-atom instead.
// If permissive is true, consumeAtom will not fail on:
// - leading/trailing/double dots in the atom (see golang.org/issue/4938)
func (p *addrParser) consumeAtom(dot bool, permissive bool) (atom string, err error) {
	i := 0

Loop:
	for {
		r, size := utf8.DecodeRuneInString(p.s[i:])
		switch {
		case size == 1 && r == utf8.RuneError:
			return "", fmt.Errorf("mail: invalid utf-8 in address: %q", p.s)

		case size == 0 || !isAtext(r, dot):
			break Loop

		default:
			i += size

		}
	}

	if i == 0 {
		return "", errors.New("mail: invalid string")
	}
	atom, p.s = p.s[:i], p.s[i:]
	if !permissive {
		if strings.HasPrefix(atom, ".") {
			return "", errors.New("mail: leading dot in atom")
		}
		if strings.Contains(atom, "..") {
			return "", errors.New("mail: double dot in atom")
		}
		if strings.HasSuffix(atom, ".") {
			return "", errors.New("mail: trailing dot in atom")
		}
	}
	return atom, nil
}

// consumeDomainLiteral parses an RFC 5322 domain-literal at the start of p.
func (p *addrParser) consumeDomainLiteral() (string, error) {
	// Skip the leading [
	if !p.consume('[') {
		return "", errors.New(`mail: missing "[" in domain-literal`)
	}

	// Parse the dtext
	var dtext string
	for {
		if p.empty() {
			return "", errors.New("mail: unclosed domain-literal")
		}
		if p.peek() == ']' {
			break
		}

		r, size := utf8.DecodeRuneInString(p.s)
		if size == 1 && r == utf8.RuneError {
			return "", fmt.Errorf("mail: invalid utf-8 in domain-literal: %q", p.s)
		}
		if !isDtext(r) {
			return "", fmt.Errorf("mail: bad character in domain-literal: %q", r)
		}

		dtext += p.s[:size]
		p.s = p.s[size:]
	}

	// Skip the trailing ]
	if !p.consume(']') {
		return "", errors.New("mail: unclosed domain-literal")
	}

	// Check if the domain literal is an IP address
	if net.ParseIP(dtext) == nil {
		return "", fmt.Errorf("mail: invalid IP address in domain-literal: %q", dtext)
	}

	return "[" + dtext + "]", nil
}

func (p *addrParser) consumeDisplayNameComment() (string, error) {
	if !p.consume('(') {
		return "", errors.New("mail: comment does not start with (")
	}
	comment, ok := p.consumeComment()
	if !ok {
		return "", errors.New("mail: misformatted parenthetical comment")
	}

	// TODO(stapelberg): parse quoted-string within comment
	words := strings.FieldsFunc(comment, func(r rune) bool { return r == ' ' || r == '\t' })
	for idx, word := range words {
		decoded, isEncoded, err := p.decodeRFC2047Word(word)
		if err != nil {
			return "", err
		}
		if isEncoded {
			words[idx] = decoded
		}
	}

	return strings.Join(words, " "), nil
}

func (p *addrParser) consume(c byte) bool {
	if p.empty() || p.peek() != c {
		return false
	}
	p.s = p.s[1:]
	return true
}

// skipSpace skips the leading space and tab characters.
func (p *addrParser) skipSpace() {
	p.s = strings.TrimLeft(p.s, " \t")
}

func (p *addrParser) peek() byte {
	return p.s[0]
}

func (p *addrParser) empty() bool {
	return p.len() == 0
}

func (p *addrParser) len() int {
	return len(p.s)
}

// skipCFWS skips CFWS as defined in RFC5322.
func (p *addrParser) skipCFWS() bool {
	p.skipSpace()

	for {
		if !p.consume('(') {
			break
		}

		if _, ok := p.consumeComment(); !ok {
			return false
		}

		p.skipSpace()
	}

	return true
}

func (p *addrParser) consumeComment() (string, bool) {
	// '(' already consumed.
	depth := 1

	var comment string
	for {
		if p.empty() || depth == 0 {
			break
		}

		if p.peek() == '\\' && p.len() > 1 {
			p.s = p.s[1:]
		} else if p.peek() == '(' {
			depth++
		} else if p.peek() == ')' {
			depth--
		}
		if depth > 0 {
			comment += p.s[:1]
		}
		p.s = p.s[1:]
	}

	return comment, depth == 0
}

func (p *addrParser) decodeRFC2047Word(s string) (word string, isEncoded bool, err error) {
	dec := p.dec
	if dec == nil {
		dec = &rfc2047Decoder
	}

	// Substitute our own CharsetReader function so that we can tell
	// whether an error from the Decode method was due to the
	// CharsetReader (meaning the charset is invalid).
	// We used to look for the charsetError type in the error result,
	// but that behaves badly with CharsetReaders other than the
	// one in rfc2047Decoder.
	adec := *dec
	charsetReaderError := false
	adec.CharsetReader = func(charset string, input io.Reader) (io.Reader, error) {
		if dec.CharsetReader == nil {
			charsetReaderError = true
			return nil, charsetError(charset)
		}
		r, err := dec.CharsetReader(charset, input)
		if err != nil {
			charsetReaderError = true
		}
		return r, err
	}
	word, err = adec.Decode(s)
	if err == nil {
		return word, true, nil
	}

	// If the error came from the character set reader
	// (meaning the character set itself is invalid
	// but the decoding worked fine until then),
	// return the original text and the error,
	// with isEncoded=true.
	if charsetReaderError {
		return s, true, err
	}

	// Ignore invalid RFC 2047 encoded-word errors.
	return s, false, nil
}

var rfc2047Decoder = mime.WordDecoder{
	CharsetReader: func(charset string, input io.Reader) (io.Reader, error) {
		return nil, charsetError(charset)
	},
}

type charsetError string

func (e charsetError) Error() string {
	return fmt.Sprintf("charset not supported: %q", string(e))
}

// isAtext reports whether r is an RFC 5322 atext character.
// If dot is true, period is included.
func isAtext(r rune, dot bool) bool {
	switch r {
	case '.':
		return dot

	// RFC 5322 3.2.3. specials
	case '(', ')', '<', '>', '[', ']', ':', ';', '@', '\\', ',', '"': // RFC 5322 3.2.3. specials
		return false
	}
	return isVchar(r)
}

// isQtext reports whether r is an RFC 5322 qtext character.
func isQtext(r rune) bool {
	// Printable US-ASCII, excluding backslash or quote.
	if r == '\\' || r == '"' {
		return false
	}
	return isVchar(r)
}

// quoteString renders a string as an RFC 5322 quoted-string.
func quoteString(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		if isQtext(r) || isWSP(r) {
			b.WriteRune(r)
		} else if isVchar(r) {
			b.WriteByte('\\')
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

// isVchar reports whether r is an RFC 5322 VCHAR character.
func isVchar(r rune) bool {
	// Visible (printing) characters.
	return '!' <= r && r <= '~' || isMultibyte(r)
}

// isMultibyte reports whether r is a multi-byte UTF-8 character
// as supported by RFC 6532.
func isMultibyte(r rune) bool {
	return r >= utf8.RuneSelf
}

// isWSP reports whether r is a WSP (white space).
// WSP is a space or horizontal tab (RFC 5234 Appendix B).
func isWSP(r rune) bool {
	return r == ' ' || r == '\t'
}

// isDtext reports whether r is an RFC 5322 dtext character.
func isDtext(r rune) bool {
	// Printable US-ASCII, excluding "[", "]", or "\".
	if r == '[' || r == ']' || r == '\\' {
		return false
	}
	return isVchar(r)
}
```