Response:
The user wants to understand the functionality of the Go code snippet provided, which is a test file for the `net/mail` package. I need to analyze the test functions and the data structures they use to infer the functionalities being tested.

Here's a breakdown of the thought process:

1. **Identify the core purpose:** The filename `message_test.go` and the package `mail` suggest this file tests the functionalities related to email messages.

2. **Analyze the test functions:** Look for functions starting with `Test`.
    * `TestParsing`: This function iterates through `parseTests` and uses `ReadMessage`. It checks if the parsed header and body match the expected values. This suggests it tests the parsing of email messages from a string.
    * `TestDateParsing`: This function iterates through `tests` and uses `hdr.Date()` and `ParseDate`. It checks if the parsed date matches the expected `time.Time` value. This suggests it tests the parsing of date headers in email messages.
    * `TestDateParsingCFWS`:  Similar to `TestDateParsing`, but includes a `valid` flag, implying it tests how date parsing handles comments and whitespace (CFWS - Comments and Folding Whitespace).
    * `TestAddressParsingError`: This function iterates through `mustErrTestCases` and expects an error from `ParseAddress`. This indicates it tests scenarios where address parsing should fail.
    * `TestAddressParsing`: This function iterates through `tests` and uses `ParseAddress` and `ParseAddressList`. It checks if the parsed address(es) match the expected `Address` struct. This implies it tests the parsing of email addresses.
    * `TestAddressParser`: This function is similar to `TestAddressParsing` but uses an `AddressParser` with a custom `WordDecoder`. This indicates it tests address parsing with specific decoding configurations.
    * `TestAddressString`: This function iterates through `tests` and calls the `String()` method on `Address` structs. It then tries to parse the output string back. This suggests it tests the formatting of email addresses into strings and if the formatted string can be parsed back correctly.
    * `TestAddressParsingAndFormatting`: This function tests the round-trip of parsing and formatting valid and invalid email addresses.
    * `TestAddressFormattingAndParsing`: This function tests the round-trip of formatting and then parsing email addresses.
    * `TestEmptyAddress`: This function tests the behavior of parsing empty or invalid address strings.

3. **Infer the functionalities being tested:** Based on the test functions, the code tests the following functionalities of the `net/mail` package:
    * Parsing an entire email message (headers and body).
    * Parsing the `Date` header.
    * Handling comments and whitespace in `Date` headers.
    * Parsing individual email addresses.
    * Parsing lists of email addresses.
    * Handling different encoding schemes (like RFC 2047) in email addresses.
    * Handling international characters (UTF-8) in email addresses.
    * Formatting email addresses into strings.
    * Handling errors during email address parsing.

4. **Provide code examples:**  Illustrate the usage of the tested functionalities using simplified examples. Focus on `ReadMessage`, `ParseDate`, `ParseAddress`, and `ParseAddressList`.

5. **Explain command-line arguments:**  Since the code is a test file, it doesn't directly use command-line arguments. Explain that the `go test` command is used to execute these tests.

6. **Identify common mistakes:** Based on the tests, common mistakes users might make include:
    * Incorrectly formatted date strings.
    * Invalid email address formats (missing `@`, special characters, etc.).
    * Not handling encoded words correctly when dealing with international characters.

7. **Structure the answer:** Organize the information logically with clear headings. Use code blocks for examples and format the output appropriately.
这段代码是 Go 语言标准库 `net/mail` 包的一部分，具体来说是 `message_test.go` 文件，它包含了用于测试邮件消息处理功能的单元测试。

以下是它的一些主要功能：

1. **测试邮件消息的解析 (Parsing):**
   - 它定义了一系列测试用例 (`parseTests`)，每个用例包含一个待解析的邮件字符串 (`in`)，以及期望解析出的邮件头 (`header`) 和消息体 (`body`)。
   - `TestParsing` 函数会读取这些邮件字符串，使用 `mail.ReadMessage` 函数进行解析，然后比较解析出的邮件头和消息体是否与预期一致。
   - 这部分测试了 `mail.ReadMessage` 函数的核心功能，即从 `io.Reader` 中读取并解析邮件消息的头部和正文。

   ```go
   package main

   import (
       "bytes"
       "fmt"
       "net/mail"
   )

   func main() {
       input := `From: John Doe <jdoe@machine.example>
   To: Mary Smith <mary@example.net>
   Subject: Saying Hello

   This is a message just to say hello.
   `
       msg, err := mail.ReadMessage(bytes.NewBufferString(input))
       if err != nil {
           fmt.Println("解析邮件失败:", err)
           return
       }

       fmt.Println("邮件头:", msg.Header)
       bodyBuf := new(bytes.Buffer)
       _, err = bodyBuf.ReadFrom(msg.Body)
       if err != nil {
           fmt.Println("读取邮件体失败:", err)
           return
       }
       fmt.Println("邮件体:", bodyBuf.String())
   }
   ```

   **假设输入:** 与 `parseTests` 中的第一个用例相同。
   **预期输出:**
   ```
   邮件头: map[Date:[Fri, 21 Nov 1997 09:55:06 -0600] From:[John Doe <jdoe@machine.example>] Message-Id:[<1234@local.machine.example>] Subject:[Saying Hello] To:[Mary Smith <mary@example.net>]]
   邮件体: This is a message just to say hello.
   So, "Hello".

   ```

2. **测试日期头的解析 (Date Header Parsing):**
   - `TestDateParsing` 函数测试了 `Header` 类型的 `Date()` 方法以及 `ParseDate` 函数，用于解析邮件头中的 `Date` 字段。
   - 它定义了一系列包含不同格式日期字符串的测试用例，并期望解析出对应的 `time.Time` 对象。
   - 这部分测试了 `mail` 包处理各种 RFC 规定的以及常见的日期格式的能力。

   ```go
   package main

   import (
       "fmt"
       "net/mail"
       "time"
   )

   func main() {
       dateString := "Fri, 21 Nov 1997 09:55:06 -0600"
       parsedTime, err := mail.ParseDate(dateString)
       if err != nil {
           fmt.Println("解析日期失败:", err)
           return
       }
       fmt.Println("解析后的时间:", parsedTime)

       header := mail.Header{"Date": []string{dateString}}
       timeFromHeader, err := header.Date()
       if err != nil {
           fmt.Println("从 Header 中解析日期失败:", err)
           return
       }
       fmt.Println("从 Header 中解析的时间:", timeFromHeader)
   }
   ```

   **假设输入:** `dateString` 为 "Fri, 21 Nov 1997 09:55:06 -0600"。
   **预期输出:**
   ```
   解析后的时间: 1997-11-21 09:55:06 -0600 -0600
   从 Header 中解析的时间: 1997-11-21 09:55:06 -0600 -0600
   ```

3. **测试日期头中注释和空白的处理 (CFWS in Date Header):**
   - `TestDateParsingCFWS` 函数扩展了日期头解析的测试，专门测试了在日期字符串中包含注释 (comments) 和折叠空白 (folding white space, FWS) 的情况。
   - 它验证了 `ParseDate` 和 `Header.Date()` 方法是否能正确处理这些语法元素。

4. **测试邮件地址的解析错误 (Address Parsing Errors):**
   - `TestAddressParsingError` 函数测试了各种无效的邮件地址字符串，并断言 `mail.ParseAddress` 函数会返回预期的错误。
   - 这有助于确保邮件地址解析器的健壮性，能够识别并拒绝不符合规范的地址。

5. **测试邮件地址的解析 (Address Parsing):**
   - `TestAddressParsing` 函数测试了 `mail.ParseAddress` 和 `mail.ParseAddressList` 函数，用于解析单个和多个邮件地址。
   - 它定义了各种有效的邮件地址格式，包括带有姓名、注释、编码字符等的地址，并验证解析结果是否正确。

   ```go
   package main

   import (
       "fmt"
       "net/mail"
   )

   func main() {
       addressString := "John Doe <jdoe@example.com>"
       addr, err := mail.ParseAddress(addressString)
       if err != nil {
           fmt.Println("解析地址失败:", err)
           return
       }
       fmt.Println("解析后的地址:", addr)

       addressListString := "John Doe <jdoe@example.com>, jane.doe@example.com"
       addrList, err := mail.ParseAddressList(addressListString)
       if err != nil {
           fmt.Println("解析地址列表失败:", err)
           return
       }
       fmt.Println("解析后的地址列表:", addrList)
   }
   ```

   **假设输入:** `addressString` 为 "John Doe <jdoe@example.com>"， `addressListString` 为 "John Doe <jdoe@example.com>, jane.doe@example.com"。
   **预期输出:**
   ```
   解析后的地址: John Doe <jdoe@example.com>
   解析后的地址列表: [John Doe <jdoe@example.com> jane.doe@example.com]
   ```

6. **测试自定义的地址解析器 (Address Parser):**
   - `TestAddressParser` 函数使用了 `mail.AddressParser` 类型，允许使用自定义的 `mime.WordDecoder`。
   - 这部分测试了在解析包含编码字符的邮件地址时，使用自定义解码器是否能正确工作。

7. **测试邮件地址的字符串表示 (Address String Representation):**
   - `TestAddressString` 函数测试了 `mail.Address` 类型的 `String()` 方法，该方法将 `Address` 对象格式化为字符串。
   - 它还测试了格式化后的字符串是否可以被 `ParseAddress` 函数再次解析成功，实现了双向验证。

8. **测试邮件地址的格式化和解析的完整性 (Address Parsing and Formatting Completeness):**
   - `TestAddressParsingAndFormatting` 函数通过一系列有效的和无效的邮件地址字符串，测试了 `ParseAddress` 函数的解析能力以及 `Address.String()` 方法的格式化能力。
   - 它确保了有效的地址可以被解析和格式化，而无效的地址会被拒绝。

9. **测试邮件地址的格式化和解析的顺序 (Address Formatting and Parsing Order):**
    - `TestAddressFormattingAndParsing` 函数测试了先格式化邮件地址，再进行解析是否能够得到原始的地址信息，特别关注包含特殊字符的地址。

10. **测试空邮件地址的解析 (Empty Address Parsing):**
    - `TestEmptyAddress` 函数测试了当输入为空字符串时，`ParseAddress` 和 `ParseAddressList` 函数的行为，期望返回 `nil` 和错误。

**关于命令行参数的具体处理：**

这段代码是测试代码，它本身不直接处理命令行参数。Go 语言的测试是通过 `go test` 命令来运行的。你可以使用一些 `go test` 的标志来控制测试的行为，例如：

- `-v`:  显示所有测试用例的详细输出，包括通过的测试。
- `-run <regexp>`:  只运行名称匹配正则表达式的测试用例。
- `-bench <regexp>`: 运行性能测试，这里没有性能测试。
- `-cover`:  显示代码覆盖率信息。

例如，要运行 `message_test.go` 中的所有测试用例，你需要在包含该文件的目录下执行：

```bash
go test
```

要运行名称包含 "Parsing" 的测试用例，可以执行：

```bash
go test -run Parsing
```

**使用者易犯错的点：**

在实际使用 `net/mail` 包时，使用者容易犯以下错误：

1. **日期格式不正确:** 邮件头中的 `Date` 字段必须符合 RFC 5322 或其他被 `ParseDate` 函数支持的格式。如果日期格式不正确，`Header.Date()` 或 `ParseDate()` 会返回错误。例如，忘记了星期几的缩写，或者时区格式错误。

   ```go
   package main

   import (
       "fmt"
       "net/mail"
   )

   func main() {
       invalidDate := "21 Nov 1997 09:55:06 -0600" // 缺少星期几
       _, err := mail.ParseDate(invalidDate)
       if err != nil {
           fmt.Println("解析日期失败:", err) // 输出错误
       }
   }
   ```

2. **邮件地址格式不规范:**  `ParseAddress` 和 `ParseAddressList` 对邮件地址的格式有严格的要求。常见的错误包括：
   - 缺少 `@` 符号。
   - 使用了不允许的特殊字符。
   - 引号或尖括号不匹配。

   ```go
   package main

   import (
       "fmt"
       "net/mail"
   )

   func main() {
       invalidAddress := "johndoeexample.com" // 缺少 @
       _, err := mail.ParseAddress(invalidAddress)
       if err != nil {
           fmt.Println("解析地址失败:", err) // 输出错误
       }
   }
   ```

3. **未处理编码字符:** 当邮件地址或姓名包含非 ASCII 字符时，可能会使用 RFC 2047 编码。直接使用未解码的字符串可能会导致解析错误或显示乱码。需要使用 `mime.WordDecoder` 进行解码。虽然 `net/mail` 包内部会处理一些基本的编码，但在某些复杂情况下可能需要显式处理。

   ```go
   package main

   import (
       "fmt"
       "mime"
       "net/mail"
   )

   func main() {
       encodedNameAddress := "=?utf-8?q?J=C3=B6rg_Doe?= <joerg@example.com>"
       addr, err := mail.ParseAddress(encodedNameAddress)
       if err != nil {
           fmt.Println("解析地址失败:", err)
           return
       }
       fmt.Println("解析后的地址:", addr)
   }
   ```

总而言之，`message_test.go` 文件通过大量的测试用例，覆盖了 `net/mail` 包中关于邮件消息解析、日期头解析和邮件地址解析的关键功能，确保这些功能按照预期工作，并且能够处理各种合法的和非法的输入。

### 提示词
```
这是路径为go/src/net/mail/message_test.go的go语言实现的一部分， 请列举一下它的功能, 　
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

package mail

import (
	"bytes"
	"io"
	"mime"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

var parseTests = []struct {
	in     string
	header Header
	body   string
}{
	{
		// RFC 5322, Appendix A.1.1
		in: `From: John Doe <jdoe@machine.example>
To: Mary Smith <mary@example.net>
Subject: Saying Hello
Date: Fri, 21 Nov 1997 09:55:06 -0600
Message-ID: <1234@local.machine.example>

This is a message just to say hello.
So, "Hello".
`,
		header: Header{
			"From":       []string{"John Doe <jdoe@machine.example>"},
			"To":         []string{"Mary Smith <mary@example.net>"},
			"Subject":    []string{"Saying Hello"},
			"Date":       []string{"Fri, 21 Nov 1997 09:55:06 -0600"},
			"Message-Id": []string{"<1234@local.machine.example>"},
		},
		body: "This is a message just to say hello.\nSo, \"Hello\".\n",
	},
	{
		// RFC 5965, Appendix B.1, a part of the multipart message (a header-only sub message)
		in: `Feedback-Type: abuse
User-Agent: SomeGenerator/1.0
Version: 1
`,
		header: Header{
			"Feedback-Type": []string{"abuse"},
			"User-Agent":    []string{"SomeGenerator/1.0"},
			"Version":       []string{"1"},
		},
		body: "",
	},
	{
		// RFC 5322 permits any printable ASCII character,
		// except colon, in a header key. Issue #58862.
		in: `From: iant@golang.org
Custom/Header: v

Body
`,
		header: Header{
			"From":          []string{"iant@golang.org"},
			"Custom/Header": []string{"v"},
		},
		body: "Body\n",
	},
	{
		// RFC 4155 mbox format. We've historically permitted this,
		// so we continue to permit it. Issue #60332.
		in: `From iant@golang.org Mon Jun 19 00:00:00 2023
From: iant@golang.org

Hello, gophers!
`,
		header: Header{
			"From":                               []string{"iant@golang.org"},
			"From iant@golang.org Mon Jun 19 00": []string{"00:00 2023"},
		},
		body: "Hello, gophers!\n",
	},
}

func TestParsing(t *testing.T) {
	for i, test := range parseTests {
		msg, err := ReadMessage(bytes.NewBuffer([]byte(test.in)))
		if err != nil {
			t.Errorf("test #%d: Failed parsing message: %v", i, err)
			continue
		}
		if !headerEq(msg.Header, test.header) {
			t.Errorf("test #%d: Incorrectly parsed message header.\nGot:\n%+v\nWant:\n%+v",
				i, msg.Header, test.header)
		}
		body, err := io.ReadAll(msg.Body)
		if err != nil {
			t.Errorf("test #%d: Failed reading body: %v", i, err)
			continue
		}
		bodyStr := string(body)
		if bodyStr != test.body {
			t.Errorf("test #%d: Incorrectly parsed message body.\nGot:\n%+v\nWant:\n%+v",
				i, bodyStr, test.body)
		}
	}
}

func headerEq(a, b Header) bool {
	if len(a) != len(b) {
		return false
	}
	for k, as := range a {
		bs, ok := b[k]
		if !ok {
			return false
		}
		if !slices.Equal(as, bs) {
			return false
		}
	}
	return true
}

func TestDateParsing(t *testing.T) {
	tests := []struct {
		dateStr string
		exp     time.Time
	}{
		// RFC 5322, Appendix A.1.1
		{
			"Fri, 21 Nov 1997 09:55:06 -0600",
			time.Date(1997, 11, 21, 9, 55, 6, 0, time.FixedZone("", -6*60*60)),
		},
		// RFC 5322, Appendix A.6.2
		// Obsolete date.
		{
			"21 Nov 97 09:55:06 GMT",
			time.Date(1997, 11, 21, 9, 55, 6, 0, time.FixedZone("GMT", 0)),
		},
		// Commonly found format not specified by RFC 5322.
		{
			"Fri, 21 Nov 1997 09:55:06 -0600 (MDT)",
			time.Date(1997, 11, 21, 9, 55, 6, 0, time.FixedZone("", -6*60*60)),
		},
		{
			"Thu, 20 Nov 1997 09:55:06 -0600 (MDT)",
			time.Date(1997, 11, 20, 9, 55, 6, 0, time.FixedZone("", -6*60*60)),
		},
		{
			"Thu, 20 Nov 1997 09:55:06 GMT (GMT)",
			time.Date(1997, 11, 20, 9, 55, 6, 0, time.UTC),
		},
		{
			"Fri, 21 Nov 1997 09:55:06 +1300 (TOT)",
			time.Date(1997, 11, 21, 9, 55, 6, 0, time.FixedZone("", +13*60*60)),
		},
	}
	for _, test := range tests {
		hdr := Header{
			"Date": []string{test.dateStr},
		}
		date, err := hdr.Date()
		if err != nil {
			t.Errorf("Header(Date: %s).Date(): %v", test.dateStr, err)
		} else if !date.Equal(test.exp) {
			t.Errorf("Header(Date: %s).Date() = %+v, want %+v", test.dateStr, date, test.exp)
		}

		date, err = ParseDate(test.dateStr)
		if err != nil {
			t.Errorf("ParseDate(%s): %v", test.dateStr, err)
		} else if !date.Equal(test.exp) {
			t.Errorf("ParseDate(%s) = %+v, want %+v", test.dateStr, date, test.exp)
		}
	}
}

func TestDateParsingCFWS(t *testing.T) {
	tests := []struct {
		dateStr string
		exp     time.Time
		valid   bool
	}{
		// FWS-only. No date.
		{
			"   ",
			// nil is not allowed
			time.Date(1997, 11, 21, 9, 55, 6, 0, time.FixedZone("", -6*60*60)),
			false,
		},
		// FWS is allowed before optional day of week.
		{
			"   Fri, 21 Nov 1997 09:55:06 -0600",
			time.Date(1997, 11, 21, 9, 55, 6, 0, time.FixedZone("", -6*60*60)),
			true,
		},
		{
			"21 Nov 1997 09:55:06 -0600",
			time.Date(1997, 11, 21, 9, 55, 6, 0, time.FixedZone("", -6*60*60)),
			true,
		},
		{
			"Fri 21 Nov 1997 09:55:06 -0600",
			time.Date(1997, 11, 21, 9, 55, 6, 0, time.FixedZone("", -6*60*60)),
			false, // missing ,
		},
		// FWS is allowed before day of month but HTAB fails.
		{
			"Fri,        21 Nov 1997 09:55:06 -0600",
			time.Date(1997, 11, 21, 9, 55, 6, 0, time.FixedZone("", -6*60*60)),
			true,
		},
		// FWS is allowed before and after year but HTAB fails.
		{
			"Fri, 21 Nov       1997     09:55:06 -0600",
			time.Date(1997, 11, 21, 9, 55, 6, 0, time.FixedZone("", -6*60*60)),
			true,
		},
		// FWS is allowed before zone but HTAB is not handled. Obsolete timezone is handled.
		{
			"Fri, 21 Nov 1997 09:55:06           CST",
			time.Time{},
			true,
		},
		// FWS is allowed after date and a CRLF is already replaced.
		{
			"Fri, 21 Nov 1997 09:55:06           CST (no leading FWS and a trailing CRLF) \r\n",
			time.Time{},
			true,
		},
		// CFWS is a reduced set of US-ASCII where space and accentuated are obsolete. No error.
		{
			"Fri, 21    Nov 1997    09:55:06 -0600 (MDT and non-US-ASCII signs éèç )",
			time.Date(1997, 11, 21, 9, 55, 6, 0, time.FixedZone("", -6*60*60)),
			true,
		},
		// CFWS is allowed after zone including a nested comment.
		// Trailing FWS is allowed.
		{
			"Fri, 21 Nov 1997 09:55:06 -0600    \r\n (thisisa(valid)cfws)   \t ",
			time.Date(1997, 11, 21, 9, 55, 6, 0, time.FixedZone("", -6*60*60)),
			true,
		},
		// CRLF is incomplete and misplaced.
		{
			"Fri, 21 Nov 1997 \r 09:55:06 -0600    \r\n (thisisa(valid)cfws)   \t ",
			time.Date(1997, 11, 21, 9, 55, 6, 0, time.FixedZone("", -6*60*60)),
			false,
		},
		// CRLF is complete but misplaced. No error is returned.
		{
			"Fri, 21 Nov 199\r\n7  09:55:06 -0600    \r\n (thisisa(valid)cfws)   \t ",
			time.Date(1997, 11, 21, 9, 55, 6, 0, time.FixedZone("", -6*60*60)),
			true, // should be false in the strict interpretation of RFC 5322.
		},
		// Invalid ASCII in date.
		{
			"Fri, 21 Nov 1997 ù 09:55:06 -0600    \r\n (thisisa(valid)cfws)   \t ",
			time.Date(1997, 11, 21, 9, 55, 6, 0, time.FixedZone("", -6*60*60)),
			false,
		},
		// CFWS chars () in date.
		{
			"Fri, 21 Nov () 1997 09:55:06 -0600    \r\n (thisisa(valid)cfws)   \t ",
			time.Date(1997, 11, 21, 9, 55, 6, 0, time.FixedZone("", -6*60*60)),
			false,
		},
		// Timezone is invalid but T is found in comment.
		{
			"Fri, 21 Nov 1997 09:55:06 -060    \r\n (Thisisa(valid)cfws)   \t ",
			time.Date(1997, 11, 21, 9, 55, 6, 0, time.FixedZone("", -6*60*60)),
			false,
		},
		// Date has no month.
		{
			"Fri, 21  1997 09:55:06 -0600",
			time.Date(1997, 11, 21, 9, 55, 6, 0, time.FixedZone("", -6*60*60)),
			false,
		},
		// Invalid month : OCT iso Oct
		{
			"Fri, 21 OCT 1997 09:55:06 CST",
			time.Time{},
			false,
		},
		// A too short time zone.
		{
			"Fri, 21 Nov 1997 09:55:06 -060",
			time.Date(1997, 11, 21, 9, 55, 6, 0, time.FixedZone("", -6*60*60)),
			false,
		},
		// A too short obsolete time zone.
		{
			"Fri, 21  1997 09:55:06 GT",
			time.Date(1997, 11, 21, 9, 55, 6, 0, time.FixedZone("", -6*60*60)),
			false,
		},
		// Ensure that the presence of "T" in the date
		// doesn't trip out ParseDate, as per issue 39260.
		{
			"Tue, 26 May 2020 14:04:40 GMT",
			time.Date(2020, 05, 26, 14, 04, 40, 0, time.UTC),
			true,
		},
		{
			"Tue, 26 May 2020 14:04:40 UT",
			time.Date(2020, 05, 26, 14, 04, 40, 0, time.UTC),
			true,
		},
		{
			"Thu, 21 May 2020 14:04:40 UT",
			time.Date(2020, 05, 21, 14, 04, 40, 0, time.UTC),
			true,
		},
		{
			"Tue, 26 May 2020 14:04:40 XT",
			time.Date(2020, 05, 26, 14, 04, 40, 0, time.UTC),
			false,
		},
		{
			"Thu, 21 May 2020 14:04:40 XT",
			time.Date(2020, 05, 21, 14, 04, 40, 0, time.UTC),
			false,
		},
		{
			"Thu, 21 May 2020 14:04:40 UTC",
			time.Date(2020, 05, 21, 14, 04, 40, 0, time.UTC),
			true,
		},
		{
			"Fri, 21 Nov 1997 09:55:06 GMT (GMT)",
			time.Date(1997, 11, 21, 9, 55, 6, 0, time.UTC),
			true,
		},
	}
	for _, test := range tests {
		hdr := Header{
			"Date": []string{test.dateStr},
		}
		date, err := hdr.Date()
		if err != nil && test.valid {
			t.Errorf("Header(Date: %s).Date(): %v", test.dateStr, err)
		} else if err == nil && test.exp.IsZero() {
			// OK.  Used when exact result depends on the
			// system's local zoneinfo.
		} else if err == nil && !date.Equal(test.exp) && test.valid {
			t.Errorf("Header(Date: %s).Date() = %+v, want %+v", test.dateStr, date, test.exp)
		} else if err == nil && !test.valid { // an invalid expression was tested
			t.Errorf("Header(Date: %s).Date() did not return an error but %v", test.dateStr, date)
		}

		date, err = ParseDate(test.dateStr)
		if err != nil && test.valid {
			t.Errorf("ParseDate(%s): %v", test.dateStr, err)
		} else if err == nil && test.exp.IsZero() {
			// OK.  Used when exact result depends on the
			// system's local zoneinfo.
		} else if err == nil && !test.valid { // an invalid expression was tested
			t.Errorf("ParseDate(%s) did not return an error but %v", test.dateStr, date)
		} else if err == nil && test.valid && !date.Equal(test.exp) {
			t.Errorf("ParseDate(%s) = %+v, want %+v", test.dateStr, date, test.exp)
		}
	}
}

func TestAddressParsingError(t *testing.T) {
	mustErrTestCases := [...]struct {
		text        string
		wantErrText string
	}{
		0:  {"=?iso-8859-2?Q?Bogl=E1rka_Tak=E1cs?= <unknown@gmail.com>", "charset not supported"},
		1:  {"a@gmail.com b@gmail.com", "expected single address"},
		2:  {string([]byte{0xed, 0xa0, 0x80}) + " <micro@example.net>", "invalid utf-8 in address"},
		3:  {"\"" + string([]byte{0xed, 0xa0, 0x80}) + "\" <half-surrogate@example.com>", "invalid utf-8 in quoted-string"},
		4:  {"\"\\" + string([]byte{0x80}) + "\" <escaped-invalid-unicode@example.net>", "invalid utf-8 in quoted-string"},
		5:  {"\"\x00\" <null@example.net>", "bad character in quoted-string"},
		6:  {"\"\\\x00\" <escaped-null@example.net>", "bad character in quoted-string"},
		7:  {"John Doe", "no angle-addr"},
		8:  {`<jdoe#machine.example>`, "missing @ in addr-spec"},
		9:  {`John <middle> Doe <jdoe@machine.example>`, "missing @ in addr-spec"},
		10: {"cfws@example.com (", "misformatted parenthetical comment"},
		11: {"empty group: ;", "empty group"},
		12: {"root group: embed group: null@example.com;", "no angle-addr"},
		13: {"group not closed: null@example.com", "expected comma"},
		14: {"group: first@example.com, second@example.com;", "group with multiple addresses"},
		15: {"john.doe", "missing '@' or angle-addr"},
		16: {"john.doe@", "missing '@' or angle-addr"},
		17: {"John Doe@foo.bar", "no angle-addr"},
		18: {" group: null@example.com; (asd", "misformatted parenthetical comment"},
		19: {" group: ; (asd", "misformatted parenthetical comment"},
		20: {`(John) Doe <jdoe@machine.example>`, "missing word in phrase:"},
		21: {"<jdoe@[" + string([]byte{0xed, 0xa0, 0x80}) + "192.168.0.1]>", "invalid utf-8 in domain-literal"},
		22: {"<jdoe@[[192.168.0.1]>", "bad character in domain-literal"},
		23: {"<jdoe@[192.168.0.1>", "unclosed domain-literal"},
		24: {"<jdoe@[256.0.0.1]>", "invalid IP address in domain-literal"},
	}

	for i, tc := range mustErrTestCases {
		_, err := ParseAddress(tc.text)
		if err == nil || !strings.Contains(err.Error(), tc.wantErrText) {
			t.Errorf(`mail.ParseAddress(%q) #%d want %q, got %v`, tc.text, i, tc.wantErrText, err)
		}
	}

	t.Run("CustomWordDecoder", func(t *testing.T) {
		p := &AddressParser{WordDecoder: &mime.WordDecoder{}}
		for i, tc := range mustErrTestCases {
			_, err := p.Parse(tc.text)
			if err == nil || !strings.Contains(err.Error(), tc.wantErrText) {
				t.Errorf(`p.Parse(%q) #%d want %q, got %v`, tc.text, i, tc.wantErrText, err)
			}
		}
	})

}

func TestAddressParsing(t *testing.T) {
	tests := []struct {
		addrsStr string
		exp      []*Address
	}{
		// Bare address
		{
			`jdoe@machine.example`,
			[]*Address{{
				Address: "jdoe@machine.example",
			}},
		},
		// RFC 5322, Appendix A.1.1
		{
			`John Doe <jdoe@machine.example>`,
			[]*Address{{
				Name:    "John Doe",
				Address: "jdoe@machine.example",
			}},
		},
		// RFC 5322, Appendix A.1.2
		{
			`"Joe Q. Public" <john.q.public@example.com>`,
			[]*Address{{
				Name:    "Joe Q. Public",
				Address: "john.q.public@example.com",
			}},
		},
		// Comment in display name
		{
			`John (middle) Doe <jdoe@machine.example>`,
			[]*Address{{
				Name:    "John Doe",
				Address: "jdoe@machine.example",
			}},
		},
		// Display name is quoted string, so comment is not a comment
		{
			`"John (middle) Doe" <jdoe@machine.example>`,
			[]*Address{{
				Name:    "John (middle) Doe",
				Address: "jdoe@machine.example",
			}},
		},
		{
			`"John <middle> Doe" <jdoe@machine.example>`,
			[]*Address{{
				Name:    "John <middle> Doe",
				Address: "jdoe@machine.example",
			}},
		},
		{
			`Mary Smith <mary@x.test>, jdoe@example.org, Who? <one@y.test>`,
			[]*Address{
				{
					Name:    "Mary Smith",
					Address: "mary@x.test",
				},
				{
					Address: "jdoe@example.org",
				},
				{
					Name:    "Who?",
					Address: "one@y.test",
				},
			},
		},
		{
			`<boss@nil.test>, "Giant; \"Big\" Box" <sysservices@example.net>`,
			[]*Address{
				{
					Address: "boss@nil.test",
				},
				{
					Name:    `Giant; "Big" Box`,
					Address: "sysservices@example.net",
				},
			},
		},
		// RFC 5322, Appendix A.6.1
		{
			`Joe Q. Public <john.q.public@example.com>`,
			[]*Address{{
				Name:    "Joe Q. Public",
				Address: "john.q.public@example.com",
			}},
		},
		// RFC 5322, Appendix A.1.3
		{
			`group1: groupaddr1@example.com;`,
			[]*Address{
				{
					Name:    "",
					Address: "groupaddr1@example.com",
				},
			},
		},
		{
			`empty group: ;`,
			[]*Address(nil),
		},
		{
			`A Group:Ed Jones <c@a.test>,joe@where.test,John <jdoe@one.test>;`,
			[]*Address{
				{
					Name:    "Ed Jones",
					Address: "c@a.test",
				},
				{
					Name:    "",
					Address: "joe@where.test",
				},
				{
					Name:    "John",
					Address: "jdoe@one.test",
				},
			},
		},
		// RFC5322 4.4 obs-addr-list
		{
			` , joe@where.test,,John <jdoe@one.test>,`,
			[]*Address{
				{
					Name:    "",
					Address: "joe@where.test",
				},
				{
					Name:    "John",
					Address: "jdoe@one.test",
				},
			},
		},
		{
			` , joe@where.test,,John <jdoe@one.test>,,`,
			[]*Address{
				{
					Name:    "",
					Address: "joe@where.test",
				},
				{
					Name:    "John",
					Address: "jdoe@one.test",
				},
			},
		},
		{
			`Group1: <addr1@example.com>;, Group 2: addr2@example.com;, John <addr3@example.com>`,
			[]*Address{
				{
					Name:    "",
					Address: "addr1@example.com",
				},
				{
					Name:    "",
					Address: "addr2@example.com",
				},
				{
					Name:    "John",
					Address: "addr3@example.com",
				},
			},
		},
		// RFC 2047 "Q"-encoded ISO-8859-1 address.
		{
			`=?iso-8859-1?q?J=F6rg_Doe?= <joerg@example.com>`,
			[]*Address{
				{
					Name:    `Jörg Doe`,
					Address: "joerg@example.com",
				},
			},
		},
		// RFC 2047 "Q"-encoded US-ASCII address. Dumb but legal.
		{
			`=?us-ascii?q?J=6Frg_Doe?= <joerg@example.com>`,
			[]*Address{
				{
					Name:    `Jorg Doe`,
					Address: "joerg@example.com",
				},
			},
		},
		// RFC 2047 "Q"-encoded UTF-8 address.
		{
			`=?utf-8?q?J=C3=B6rg_Doe?= <joerg@example.com>`,
			[]*Address{
				{
					Name:    `Jörg Doe`,
					Address: "joerg@example.com",
				},
			},
		},
		// RFC 2047 "Q"-encoded UTF-8 address with multiple encoded-words.
		{
			`=?utf-8?q?J=C3=B6rg?=  =?utf-8?q?Doe?= <joerg@example.com>`,
			[]*Address{
				{
					Name:    `JörgDoe`,
					Address: "joerg@example.com",
				},
			},
		},
		// RFC 2047, Section 8.
		{
			`=?ISO-8859-1?Q?Andr=E9?= Pirard <PIRARD@vm1.ulg.ac.be>`,
			[]*Address{
				{
					Name:    `André Pirard`,
					Address: "PIRARD@vm1.ulg.ac.be",
				},
			},
		},
		// Custom example of RFC 2047 "B"-encoded ISO-8859-1 address.
		{
			`=?ISO-8859-1?B?SvZyZw==?= <joerg@example.com>`,
			[]*Address{
				{
					Name:    `Jörg`,
					Address: "joerg@example.com",
				},
			},
		},
		// Custom example of RFC 2047 "B"-encoded UTF-8 address.
		{
			`=?UTF-8?B?SsO2cmc=?= <joerg@example.com>`,
			[]*Address{
				{
					Name:    `Jörg`,
					Address: "joerg@example.com",
				},
			},
		},
		// Custom example with "." in name. For issue 4938
		{
			`Asem H. <noreply@example.com>`,
			[]*Address{
				{
					Name:    `Asem H.`,
					Address: "noreply@example.com",
				},
			},
		},
		// RFC 6532 3.2.3, qtext /= UTF8-non-ascii
		{
			`"Gø Pher" <gopher@example.com>`,
			[]*Address{
				{
					Name:    `Gø Pher`,
					Address: "gopher@example.com",
				},
			},
		},
		// RFC 6532 3.2, atext /= UTF8-non-ascii
		{
			`µ <micro@example.com>`,
			[]*Address{
				{
					Name:    `µ`,
					Address: "micro@example.com",
				},
			},
		},
		// RFC 6532 3.2.2, local address parts allow UTF-8
		{
			`Micro <µ@example.com>`,
			[]*Address{
				{
					Name:    `Micro`,
					Address: "µ@example.com",
				},
			},
		},
		// RFC 6532 3.2.4, domains parts allow UTF-8
		{
			`Micro <micro@µ.example.com>`,
			[]*Address{
				{
					Name:    `Micro`,
					Address: "micro@µ.example.com",
				},
			},
		},
		// Issue 14866
		{
			`"" <emptystring@example.com>`,
			[]*Address{
				{
					Name:    "",
					Address: "emptystring@example.com",
				},
			},
		},
		// CFWS
		{
			`<cfws@example.com> (CFWS (cfws))  (another comment)`,
			[]*Address{
				{
					Name:    "",
					Address: "cfws@example.com",
				},
			},
		},
		{
			`<cfws@example.com> ()  (another comment), <cfws2@example.com> (another)`,
			[]*Address{
				{
					Name:    "",
					Address: "cfws@example.com",
				},
				{
					Name:    "",
					Address: "cfws2@example.com",
				},
			},
		},
		// Comment as display name
		{
			`john@example.com (John Doe)`,
			[]*Address{
				{
					Name:    "John Doe",
					Address: "john@example.com",
				},
			},
		},
		// Comment and display name
		{
			`John Doe <john@example.com> (Joey)`,
			[]*Address{
				{
					Name:    "John Doe",
					Address: "john@example.com",
				},
			},
		},
		// Comment as display name, no space
		{
			`john@example.com(John Doe)`,
			[]*Address{
				{
					Name:    "John Doe",
					Address: "john@example.com",
				},
			},
		},
		// Comment as display name, Q-encoded
		{
			`asjo@example.com (Adam =?utf-8?Q?Sj=C3=B8gren?=)`,
			[]*Address{
				{
					Name:    "Adam Sjøgren",
					Address: "asjo@example.com",
				},
			},
		},
		// Comment as display name, Q-encoded and tab-separated
		{
			`asjo@example.com (Adam	=?utf-8?Q?Sj=C3=B8gren?=)`,
			[]*Address{
				{
					Name:    "Adam Sjøgren",
					Address: "asjo@example.com",
				},
			},
		},
		// Nested comment as display name, Q-encoded
		{
			`asjo@example.com (Adam =?utf-8?Q?Sj=C3=B8gren?= (Debian))`,
			[]*Address{
				{
					Name:    "Adam Sjøgren (Debian)",
					Address: "asjo@example.com",
				},
			},
		},
		// Comment in group display name
		{
			`group (comment:): a@example.com, b@example.com;`,
			[]*Address{
				{
					Address: "a@example.com",
				},
				{
					Address: "b@example.com",
				},
			},
		},
		{
			`x(:"):"@a.example;("@b.example;`,
			[]*Address{
				{
					Address: `@a.example;(@b.example`,
				},
			},
		},
		// Domain-literal
		{
			`jdoe@[192.168.0.1]`,
			[]*Address{{
				Address: "jdoe@[192.168.0.1]",
			}},
		},
		{
			`John Doe <jdoe@[192.168.0.1]>`,
			[]*Address{{
				Name:    "John Doe",
				Address: "jdoe@[192.168.0.1]",
			}},
		},
	}
	for _, test := range tests {
		if len(test.exp) == 1 {
			addr, err := ParseAddress(test.addrsStr)
			if err != nil {
				t.Errorf("Failed parsing (single) %q: %v", test.addrsStr, err)
				continue
			}
			if !reflect.DeepEqual([]*Address{addr}, test.exp) {
				t.Errorf("Parse (single) of %q: got %+v, want %+v", test.addrsStr, addr, test.exp)
			}
		}

		addrs, err := ParseAddressList(test.addrsStr)
		if err != nil {
			t.Errorf("Failed parsing (list) %q: %v", test.addrsStr, err)
			continue
		}
		if !reflect.DeepEqual(addrs, test.exp) {
			t.Errorf("Parse (list) of %q: got %+v, want %+v", test.addrsStr, addrs, test.exp)
		}
	}
}

func TestAddressParser(t *testing.T) {
	tests := []struct {
		addrsStr string
		exp      []*Address
	}{
		// Bare address
		{
			`jdoe@machine.example`,
			[]*Address{{
				Address: "jdoe@machine.example",
			}},
		},
		// RFC 5322, Appendix A.1.1
		{
			`John Doe <jdoe@machine.example>`,
			[]*Address{{
				Name:    "John Doe",
				Address: "jdoe@machine.example",
			}},
		},
		// RFC 5322, Appendix A.1.2
		{
			`"Joe Q. Public" <john.q.public@example.com>`,
			[]*Address{{
				Name:    "Joe Q. Public",
				Address: "john.q.public@example.com",
			}},
		},
		{
			`Mary Smith <mary@x.test>, jdoe@example.org, Who? <one@y.test>`,
			[]*Address{
				{
					Name:    "Mary Smith",
					Address: "mary@x.test",
				},
				{
					Address: "jdoe@example.org",
				},
				{
					Name:    "Who?",
					Address: "one@y.test",
				},
			},
		},
		{
			`<boss@nil.test>, "Giant; \"Big\" Box" <sysservices@example.net>`,
			[]*Address{
				{
					Address: "boss@nil.test",
				},
				{
					Name:    `Giant; "Big" Box`,
					Address: "sysservices@example.net",
				},
			},
		},
		// RFC 2047 "Q"-encoded ISO-8859-1 address.
		{
			`=?iso-8859-1?q?J=F6rg_Doe?= <joerg@example.com>`,
			[]*Address{
				{
					Name:    `Jörg Doe`,
					Address: "joerg@example.com",
				},
			},
		},
		// RFC 2047 "Q"-encoded US-ASCII address. Dumb but legal.
		{
			`=?us-ascii?q?J=6Frg_Doe?= <joerg@example.com>`,
			[]*Address{
				{
					Name:    `Jorg Doe`,
					Address: "joerg@example.com",
				},
			},
		},
		// RFC 2047 "Q"-encoded ISO-8859-15 address.
		{
			`=?ISO-8859-15?Q?J=F6rg_Doe?= <joerg@example.com>`,
			[]*Address{
				{
					Name:    `Jörg Doe`,
					Address: "joerg@example.com",
				},
			},
		},
		// RFC 2047 "B"-encoded windows-1252 address.
		{
			`=?windows-1252?q?Andr=E9?= Pirard <PIRARD@vm1.ulg.ac.be>`,
			[]*Address{
				{
					Name:    `André Pirard`,
					Address: "PIRARD@vm1.ulg.ac.be",
				},
			},
		},
		// Custom example of RFC 2047 "B"-encoded ISO-8859-15 address.
		{
			`=?ISO-8859-15?B?SvZyZw==?= <joerg@example.com>`,
			[]*Address{
				{
					Name:    `Jörg`,
					Address: "joerg@example.com",
				},
			},
		},
		// Custom example of RFC 2047 "B"-encoded UTF-8 address.
		{
			`=?UTF-8?B?SsO2cmc=?= <joerg@example.com>`,
			[]*Address{
				{
					Name:    `Jörg`,
					Address: "joerg@example.com",
				},
			},
		},
		// Custom example with "." in name. For issue 4938
		{
			`Asem H. <noreply@example.com>`,
			[]*Address{
				{
					Name:    `Asem H.`,
					Address: "noreply@example.com",
				},
			},
		},
		// Domain-literal
		{
			`jdoe@[192.168.0.1]`,
			[]*Address{{
				Address: "jdoe@[192.168.0.1]",
			}},
		},
		{
			`John Doe <jdoe@[192.168.0.1]>`,
			[]*Address{{
				Name:    "John Doe",
				Address: "jdoe@[192.168.0.1]",
			}},
		},
	}

	ap := AddressParser{WordDecoder: &mime.WordDecoder{
		CharsetReader: func(charset string, input io.Reader) (io.Reader, error) {
			in, err := io.ReadAll(input)
			if err != nil {
				return nil, err
			}

			switch charset {
			case "iso-8859-15":
				in = bytes.ReplaceAll(in, []byte("\xf6"), []byte("ö"))
			case "windows-1252":
				in = bytes.ReplaceAll(in, []byte("\xe9"), []byte("é"))
			}

			return bytes.NewReader(in), nil
		},
	}}

	for _, test := range tests {
		if len(test.exp) == 1 {
			addr, err := ap.Parse(test.addrsStr)
			if err != nil {
				t.Errorf("Failed parsing (single) %q: %v", test.addrsStr, err)
				continue
			}
			if !reflect.DeepEqual([]*Address{addr}, test.exp) {
				t.Errorf("Parse (single) of %q: got %+v, want %+v", test.addrsStr, addr, test.exp)
			}
		}

		addrs, err := ap.ParseList(test.addrsStr)
		if err != nil {
			t.Errorf("Failed parsing (list) %q: %v", test.addrsStr, err)
			continue
		}
		if !reflect.DeepEqual(addrs, test.exp) {
			t.Errorf("Parse (list) of %q: got %+v, want %+v", test.addrsStr, addrs, test.exp)
		}
	}
}

func TestAddressString(t *testing.T) {
	tests := []struct {
		addr *Address
		exp  string
	}{
		{
			&Address{Address: "bob@example.com"},
			"<bob@example.com>",
		},
		{ // quoted local parts: RFC 5322, 3.4.1. and 3.2.4.
			&Address{Address: `my@idiot@address@example.com`},
			`<"my@idiot@address"@example.com>`,
		},
		{ // quoted local parts
			&Address{Address: ` @example.com`},
			`<" "@example.com>`,
		},
		{
			&Address{Name: "Bob", Address: "bob@example.com"},
			`"Bob" <bob@example.com>`,
		},
		{
			// note the ö (o with an umlaut)
			&Address{Name: "Böb", Address: "bob@example.com"},
			`=?utf-8?q?B=C3=B6b?= <bob@example.com>`,
		},
		{
			&Address{Name: "Bob Jane", Address: "bob@example.com"},
			`"Bob Jane" <bob@example.com>`,
		},
		{
			&Address{Name: "Böb Jacöb", Address: "bob@example.com"},
			`=?utf-8?q?B=C3=B6b_Jac=C3=B6b?= <bob@example.com>`,
		},
		{ // https://golang.org/issue/12098
			&Address{Name: "Rob", Address: ""},
			`"Rob" <@>`,
		},
		{ // https://golang.org/issue/12098
			&Address{Name: "Rob", Address: "@"},
			`"Rob" <@>`,
		},
		{
			&Address{Name: "Böb, Jacöb", Address: "bob@example.com"},
			`=?utf-8?b?QsO2YiwgSmFjw7Zi?= <bob@example.com>`,
		},
		{
			&Address{Name: "=??Q?x?=", Address: "hello@world.com"},
			`"=??Q?x?=" <hello@world.com>`,
		},
		{
			&Address{Name: "=?hello", Address: "hello@world.com"},
			`"=?hello" <hello@world.com>`,
		},
		{
			&Address{Name: "world?=", Address: "hello@world.com"},
			`"world?=" <hello@world.com>`,
		},
		{
			// should q-encode even for invalid utf-8.
			&Address{Name: string([]byte{0xed, 0xa0, 0x80}), Address: "invalid-utf8@example.net"},
			"=?utf-8?q?=ED=A0=80?= <invalid-utf8@example.net>",
		},
		// Domain-literal
		{
			&Address{Address: "bob@[192.168.0.1]"},
			"<bob@[192.168.0.1]>",
		},
		{
			&Address{Name: "Bob", Address: "bob@[192.168.0.1]"},
			`"Bob" <bob@[192.168.0.1]>`,
		},
	}
	for _, test := range tests {
		s := test.addr.String()
		if s != test.exp {
			t.Errorf("Address%+v.String() = %v, want %v", *test.addr, s, test.exp)
			continue
		}

		// Check round-trip.
		if test.addr.Address != "" && test.addr.Address != "@" {
			a, err := ParseAddress(test.exp)
			if err != nil {
				t.Errorf("ParseAddress(%#q): %v", test.exp, err)
				continue
			}
			if a.Name != test.addr.Name || a.Address != test.addr.Address {
				t.Errorf("ParseAddress(%#q) = %#v, want %#v", test.exp, a, test.addr)
			}
		}
	}
}

// Check if all valid addresses can be parsed, formatted and parsed again
func TestAddressParsingAndFormatting(t *testing.T) {

	// Should pass
	tests := []string{
		`<Bob@example.com>`,
		`<bob.bob@example.com>`,
		`<".bob"@example.com>`,
		`<" "@example.com>`,
		`<some.mail-with-dash@example.com>`,
		`<"dot.and space"@example.com>`,
		`<"very.unusual.@.unusual.com"@example.com>`,
		`<admin@mailserver1>`,
		`<postmaster@localhost>`,
		"<#!$%&'*+-/=?^_`{}|~@example.org>",
		`<"very.(),:;<>[]\".VERY.\"very@\\ \"very\".unusual"@strange.example.com>`, // escaped quotes
		`<"()<>[]:,;@\\\"!#$%&'*+-/=?^_{}| ~.a"@example.org>`,                      // escaped backslashes
		`<"Abc\\@def"@example.com>`,
		`<"Joe\\Blow"@example.com>`,
		`<test1/test2=test3@example.com>`,
		`<def!xyz%abc@example.com>`,
		`<_somename@example.com>`,
		`<joe@uk>`,
		`<~@example.com>`,
		`<"..."@test.com>`,
		`<"john..doe"@example.com>`,
		`<"john.doe."@example.com>`,
		`<".john.doe"@example.com>`,
		`<"."@example.com>`,
		`<".."@example.com>`,
		`<"0:"@0>`,
		`<Bob@[192.168.0.1]>`,
	}

	for _, test := range tests {
		addr, err := ParseAddress(test)
		if err != nil {
			t.Errorf("Couldn't parse address %s: %s", test, err.Error())
			continue
		}
		str := addr.String()
		addr, err = ParseAddress(str)
		if err != nil {
			t.Errorf("ParseAddr(%q) error: %v", test, err)
			continue
		}

		if addr.String() != test {
			t.Errorf("String() round-trip = %q; want %q", addr, test)
			continue
		}

	}

	// Should fail
	badTests := []string{
		`<Abc.example.com>`,
		`<A@b@c@example.com>`,
		`<a"b(c)d,e:f;g<h>i[j\k]l@example.com>`,
		`<just"not"right@example.com>`,
		`<this is"not\allowed@example.com>`,
		`<this\ still\"not\\allowed@example.com>`,
		`<john..doe@example.com>`,
		`<john.doe@example..com>`,
		`<john.doe@example..com>`,
		`<john.doe.@example.com>`,
		`<john.doe.@.example.com>`,
		`<.john.doe@example.com>`,
		`<@example.com>`,
		`<.@example.com>`,
		`<test@.>`,
		`< @example.com>`,
		`<""test""blah""@example.com>`,
		`<""@0>`,
	}

	for _, test := range badTests {
		_, err := ParseAddress(test)
		if err == nil {
			t.Errorf("Should have failed to parse address: %s", test)
			continue
		}

	}

}

func TestAddressFormattingAndParsing(t *testing.T) {
	tests := []*Address{
		{Name: "@lïce", Address: "alice@example.com"},
		{Name: "Böb O'Connor", Address: "bob@example.com"},
		{Name: "???", Address: "bob@example.com"},
		{Name: "Böb ???", Address: "bob@example.com"},
		{Name: "Böb (Jacöb)", Address: "bob@example.com"},
		{Name: "à#$%&'(),.:;<>@[]^`{|}~'", Address: "bob@example.com"},
		// https://golang.org/issue/11292
		{Name: "\"\\\x1f,\"", Address: "0@0"},
		// https://golang.org/issue/12782
		{Name: "naé, mée", Address: "test.mail@gmail.com"},
	}

	for i, test := range tests {
		parsed, err := ParseAddress(test.String())
		if err != nil {
			t.Errorf("test #%d: ParseAddr(%q) error: %v", i, test.String(), err)
			continue
		}
		if parsed.Name != test.Name {
			t.Errorf("test #%d: Parsed name = %q; want %q", i, parsed.Name, test.Name)
		}
		if parsed.Address != test.Address {
			t.Errorf("test #%d: Parsed address = %q; want %q", i, parsed.Address, test.Address)
		}
	}
}

func TestEmptyAddress(t *testing.T) {
	parsed, err := ParseAddress("")
	if parsed != nil || err == nil {
		t.Errorf(`ParseAddress("") = %v, %v, want nil, error`, parsed, err)
	}
	list, err := ParseAddressList("")
	if len(list) > 0 || err == nil {
		t.Errorf(`ParseAddressList("") = %v, %v, want nil, error`, list, err)
	}
	list, err = ParseAddressList(",")
	if len(list) > 0 || err == nil {
		t.Errorf(`ParseAddressList("") = %v, %v, want nil, error`, list, err)
	}
	list, err = ParseAddressList("a@b c@d")
	if len(list) > 0 || err == nil {
		t.Errorf(`ParseAddressList("") = %v, %v, want nil, error`, list, err)
	}
}
```