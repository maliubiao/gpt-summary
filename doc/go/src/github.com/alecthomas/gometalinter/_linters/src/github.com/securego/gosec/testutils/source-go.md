Response:
My thought process to answer the request goes like this:

1. **Understand the Goal:** The request asks for an explanation of the provided Go code, focusing on its functionality, potential use cases, examples, and common mistakes. The specific file path hints that this code is related to testing security linters.

2. **Initial Code Scan and Structure Recognition:** I quickly scan the code and notice the following key elements:
    * A `package testutils` declaration. This immediately suggests it's a utility package for testing purposes.
    * A `CodeSample` struct containing `Code` (a string) and `Errors` (an integer). This strongly implies that the code is designed to hold code snippets and the expected number of security vulnerabilities (or errors) in those snippets.
    * Several global variables like `SampleCodeG101`, `SampleCodeG102`, etc., which are slices of `CodeSample`. The naming convention (e.g., G101) likely corresponds to specific security checks or rules.

3. **Inferring Functionality:**  Based on the structure, I can deduce that this code serves as a repository of test cases for a security linter (like `gosec`, as indicated in the file path). Each `SampleCode` variable represents a set of code snippets designed to trigger (or not trigger) a specific security rule. The `Errors` field indicates how many times a particular vulnerability is expected to be found in the corresponding `Code`.

4. **Reasoning about the "What" and "Why":**  The purpose is clearly to test the accuracy and effectiveness of a security analysis tool. By providing code examples with known vulnerabilities, the tool's ability to detect those vulnerabilities can be verified. The variety of `SampleCodeGxxx` variables suggests testing for different vulnerability categories.

5. **Illustrative Go Code Example:** To demonstrate the usage, I need to show how this data structure would be used within a testing context. I'd imagine a loop iterating through the `SampleCode` slices, running the security linter against each `Code` snippet, and then comparing the linter's output (number of detected errors) with the expected `Errors` value. This leads to the example code showing how to iterate through `SampleCodeG101` and access the `Code` and `Errors` fields.

6. **Inferring Go Language Features:** The core Go features demonstrated are:
    * **Structs:**  `CodeSample` is a user-defined struct to group related data.
    * **Slices:** The `SampleCodeGxxx` variables are slices, allowing for a dynamic collection of test cases.
    * **String Literals:** The `Code` field stores Go source code as strings.

7. **Considering Command-Line Arguments:** This particular code snippet doesn't directly handle command-line arguments. It's a data structure. However, I can infer that the *security linter* that uses this data might have command-line arguments to specify which rules to run, which files to analyze, etc. I would provide a general explanation of typical linter command-line arguments.

8. **Identifying Potential User Mistakes:**  The most likely mistakes would be related to:
    * **Incorrect `Errors` values:**  Manually specifying the expected error count can be error-prone. If the linter's logic changes, the `Errors` values might become outdated, leading to false positives or negatives in tests.
    * **Invalid `Code` snippets:**  The `Code` strings must be valid Go code that compiles. If the syntax is incorrect, the test might fail for the wrong reason.

9. **Structuring the Answer:**  I organize the information logically, starting with the basic functionality, then moving to examples, underlying Go features, potential command-line usage (inferred for the broader linter), and finally, common pitfalls. Using clear headings and formatting (like code blocks) improves readability.

10. **Language and Tone:**  I ensure the answer is in Chinese, as requested, and maintains a clear and informative tone.

**(Self-Correction during the process):**

* Initially, I might focus too much on the specific security checks (G101, G102, etc.). I need to step back and explain the *overall purpose* of the `testutils` package first.
* I might initially think the code *executes* the tests directly. I need to realize it's just the *data definition* for tests. The actual test execution would happen in a separate testing file.
* I need to be careful not to over-speculate about the *exact* command-line arguments of `gosec`. It's better to provide a general overview of common linter arguments.

By following these steps, I can provide a comprehensive and accurate answer that addresses all aspects of the user's request.
这段Go语言代码片段是 `gometalinter` 项目中 `gosec` 安全检查工具的一部分，用于提供**测试用例**。它定义了一个用于描述代码样本及其预期错误数量的数据结构，并预置了一系列包含不同类型安全漏洞（或无漏洞）的Go代码示例。

**主要功能：**

1. **定义测试用例结构：**
   - `CodeSample` 结构体用于封装一个代码片段 (`Code` 字符串) 以及该代码片段预期被安全检查工具检测到的错误数量 (`Errors` 整数)。

2. **提供预定义的代码样本：**
   - 声明了多个全局变量（例如 `SampleCodeG101`, `SampleCodeG102` 等），每个变量都是一个 `CodeSample` 类型的切片 (`[]CodeSample`)。
   - 每个 `SampleCodeGxxx` 变量都对应一类特定的安全漏洞检查规则，例如：
     - `SampleCodeG101`: 硬编码凭据
     - `SampleCodeG102`: 网络绑定到所有接口
     - `SampleCodeG103`: 使用 `unsafe` 包
     - ... 等等。
   - 每个 `SampleCodeGxxx` 切片中包含了多个 `CodeSample` 实例，每个实例包含一段 Go 代码和预期的错误数量。

**它是什么Go语言功能的实现：**

这段代码主要利用了 Go 语言的以下功能：

- **结构体 (Struct):** 用于定义 `CodeSample` 这样的自定义数据类型，将相关的 `Code` 和 `Errors` 字段组合在一起。
- **切片 (Slice):** 用于存储一组 `CodeSample` 实例，方便组织和迭代测试用例。
- **字符串字面量 (String Literals):** 用于存储 Go 代码片段。

**Go代码举例说明其使用方式（推理）：**

假设 `gosec` 的测试代码会遍历这些 `SampleCode` 切片，对每个 `CodeSample` 中的代码进行静态分析，并将其检测到的错误数量与 `Errors` 字段进行比较。

```go
package main

import (
	"fmt"
	"strings" // 假设需要用到 strings 包
	"github.com/securego/gosec/testutils" // 假设 testutils 包的路径
)

func main() {
	// 假设我们正在测试 G101 规则
	for _, sample := range testutils.SampleCodeG101 {
		fmt.Printf("Testing code:\n%s\n", sample.Code)

		// 模拟运行 gosec 的代码分析过程 (这里只是一个简化示例)
		detectedErrors := analyzeCode(sample.Code)

		if detectedErrors == sample.Errors {
			fmt.Println("Test passed!")
		} else {
			fmt.Printf("Test failed! Expected %d errors, but got %d.\n", sample.Errors, detectedErrors)
		}
		fmt.Println(strings.Repeat("-", 20)) // 分隔线
	}
}

// 这是一个简化的代码分析函数，实际的 gosec 分析逻辑会更复杂
func analyzeCode(code string) int {
	errorCount := 0
	if strings.Contains(code, `password := "f62e5bcda4fae4f82370da0c6f20697b8f8447ef"`) {
		errorCount++
	}
	return errorCount
}
```

**假设的输入与输出：**

运行上面的示例代码，针对 `SampleCodeG101` 中的第一个 `CodeSample`：

**假设的输入 (来自 `SampleCodeG101` 的第一个元素):**

```go
Code: `
package main
import "fmt"
func main() {
	username := "admin"
	password := "f62e5bcda4fae4f82370da0c6f20697b8f8447ef"
	fmt.Println("Doing something with: ", username, password)
}`
Errors: 1
```

**假设的输出:**

```
Testing code:
package main
import "fmt"
func main() {
	username := "admin"
	password := "f62e5bcda4fae4f82370da0c6f20697b8f8447ef"
	fmt.Println("Doing something with: ", username, password)
}
Test passed!
--------------------
```

针对 `SampleCodeG101` 中的第二个 `CodeSample`：

**假设的输入 (来自 `SampleCodeG101` 的第二个元素):**

```go
Code: `
// Entropy check should not report this error by default
package main
import "fmt"
func main() {
	username := "admin"
	password := "secret"
	fmt.Println("Doing something with: ", username, password)
}`
Errors: 0
```

**假设的输出:**

```
Testing code:
// Entropy check should not report this error by default
package main
import "fmt"
func main() {
	username := "admin"
	password := "secret"
	fmt.Println("Doing something with: ", username, password)
}
Test passed!
--------------------
```

**命令行参数的具体处理：**

这段代码本身并不直接处理命令行参数。它只是定义了测试数据。但是，`gosec` 工具作为安全检查器，在实际使用时肯定会接收命令行参数来控制其行为。常见的命令行参数可能包括：

- **指定要扫描的目录或文件：**  例如 `gosec ./...` 扫描当前目录及其子目录下的所有 Go 文件。
- **指定要启用的安全规则：**  例如 `gosec -include=G101,G102` 只检查硬编码凭据和网络绑定问题。
- **指定要排除的安全规则：**  例如 `gosec -exclude=G304` 排除文件包含漏洞检查。
- **指定输出格式：**  例如 `gosec -fmt=json` 将结果以 JSON 格式输出。
- **设置报告的严重程度阈值：** 例如 `gosec -severity=medium` 只报告中等及以上严重程度的漏洞。
- **配置忽略规则：**  允许用户在代码中添加特殊的注释来忽略特定的告警。

**使用者易犯错的点：**

对于使用这段代码的开发者（主要是 `gosec` 的开发者或贡献者），一个容易犯错的点是在**更新或添加新的安全检查规则时，没有相应地更新或添加测试用例**。

例如，如果 `gosec` 添加了一个新的规则来检测使用不安全的随机数生成器（比如 `math/rand`），但 `SampleCodeG404` 中没有包含使用 `math/rand` 的代码，那么这个新规则的功能就得不到充分的测试。

另一个潜在的错误是在**修改现有规则的检测逻辑后，没有更新相应的 `Errors` 字段**。如果一个规则变得更加严格，可能会在一个现有的代码样本中检测到更多的错误，这时就需要更新 `Errors` 的值，否则测试就会失败。

总而言之，这段代码是 `gosec` 工具进行自动化测试的重要组成部分，它通过预定义的代码样本和预期的错误数量，帮助开发者验证安全检查规则的有效性和准确性。

Prompt: 
```
这是路径为go/src/github.com/alecthomas/gometalinter/_linters/src/github.com/securego/gosec/testutils/source.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
package testutils

// CodeSample encapsulates a snippet of source code that compiles, and how many errors should be detected
type CodeSample struct {
	Code   string
	Errors int
}

var (
	// SampleCodeG101 code snippets for hardcoded credentials
	SampleCodeG101 = []CodeSample{{`
package main
import "fmt"
func main() {
	username := "admin"
	password := "f62e5bcda4fae4f82370da0c6f20697b8f8447ef"
	fmt.Println("Doing something with: ", username, password)
}`, 1}, {`
// Entropy check should not report this error by default
package main
import "fmt"
func main() {
	username := "admin"
	password := "secret"
	fmt.Println("Doing something with: ", username, password)
}`, 0}, {`
package main
import "fmt"
var password = "f62e5bcda4fae4f82370da0c6f20697b8f8447ef"
func main() {
	username := "admin"
	fmt.Println("Doing something with: ", username, password)
}`, 1}, {`
package main
import "fmt"
const password = "f62e5bcda4fae4f82370da0c6f20697b8f8447ef"
func main() {
	username := "admin"
	fmt.Println("Doing something with: ", username, password)
}`, 1}, {`
package main
import "fmt"
const (
	username = "user"
	password = "f62e5bcda4fae4f82370da0c6f20697b8f8447ef"
)
func main() {
	fmt.Println("Doing something with: ", username, password)
}`, 1}, {`
package main
var password string
func init() {
	password = "f62e5bcda4fae4f82370da0c6f20697b8f8447ef"
}`, 1}, {`
package main
const (
	ATNStateSomethingElse = 1
	ATNStateTokenStart = 42
)
func main() {
	println(ATNStateTokenStart)
}`, 0}, {`
package main
const (
	ATNStateTokenStart = "f62e5bcda4fae4f82370da0c6f20697b8f8447ef"
)
func main() {
	println(ATNStateTokenStart)
}`, 1}}

	// SampleCodeG102 code snippets for network binding
	SampleCodeG102 = []CodeSample{
		// Bind to all networks explicitly
		{`
package main
import (
	"log"
   	"net"
)
func main() {
	l, err := net.Listen("tcp", "0.0.0.0:2000")
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()
}`, 1},

		// Bind to all networks implicitly (default if host omitted)
		{`
package main
import (
	"log"
   	"net"
)
func main() {
   	l, err := net.Listen("tcp", ":2000")
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()
}`, 1},
	}
	// SampleCodeG103 find instances of unsafe blocks for auditing purposes
	SampleCodeG103 = []CodeSample{
		{`
package main
import (
	"fmt"
	"unsafe"
)
type Fake struct{}
func (Fake) Good() {}
func main() {
	unsafeM := Fake{}
   	unsafeM.Good()
   	intArray := [...]int{1, 2}
   	fmt.Printf("\nintArray: %v\n", intArray)
   	intPtr := &intArray[0]
   	fmt.Printf("\nintPtr=%p, *intPtr=%d.\n", intPtr, *intPtr)
   	addressHolder := uintptr(unsafe.Pointer(intPtr)) + unsafe.Sizeof(intArray[0])
   	intPtr = (*int)(unsafe.Pointer(addressHolder))
   	fmt.Printf("\nintPtr=%p, *intPtr=%d.\n\n", intPtr, *intPtr)
}`, 3}}

	// SampleCodeG104 finds errors that aren't being handled
	SampleCodeG104 = []CodeSample{
		{`
package main
import "fmt"
func test() (int,error) {
	return 0, nil
}
func main() {
	v, _ := test()
	fmt.Println(v)
}`, 1}, {`
package main
import (
	"io/ioutil"
	"os"
	"fmt"
)
func a() error {
	return fmt.Errorf("This is an error")
}
func b() {
	fmt.Println("b")
	ioutil.WriteFile("foo.txt", []byte("bar"), os.ModeExclusive)
}
func c() string {
	return fmt.Sprintf("This isn't anything")
}
func main() {
	_ = a()
	a()
	b()
	c()
}`, 3}, {`
package main
import "fmt"
func test() error {
	return nil
}
func main() {
	e := test()
	fmt.Println(e)
}`, 0}}

	// SampleCodeG105 - bignum overflow
	SampleCodeG105 = []CodeSample{{`
package main
import (
	"math/big"
)
func main() {
	z := new(big.Int)
	x := new(big.Int)
	x = x.SetUint64(2)
	y := new(big.Int)
    y = y.SetUint64(4)
   	m := new(big.Int)
    m = m.SetUint64(0)
    z = z.Exp(x, y, m)
}`, 1}}

	// SampleCodeG106 - ssh InsecureIgnoreHostKey
	SampleCodeG106 = []CodeSample{{`
package main
import (
        "golang.org/x/crypto/ssh"
)
func main() {
        _ =  ssh.InsecureIgnoreHostKey()
}`, 1}}

	// SampleCodeG107 - SSRF via http requests with variable url
	SampleCodeG107 = []CodeSample{{`
package main
import (
	"net/http"
	"io/ioutil"
	"fmt"
	"os"
)
func main() {
	url := os.Getenv("tainted_url")
	resp, err := http.Get(url)
	if err != nil {
		panic(err)
	}
  	defer resp.Body.Close()
  	body, err := ioutil.ReadAll(resp.Body)
  	if err != nil {
    		panic(err)
  	}
  	fmt.Printf("%s", body)
}`, 1}, {`
package main

import (
	"fmt"
	"net/http"
)
const url = "http://127.0.0.1"
func main() {
	resp, err := http.Get(url)
	if err != nil {
		fmt.Println(err)
    	}
      	fmt.Println(resp.Status)
}`, 0}}
	// SampleCodeG201 - SQL injection via format string
	SampleCodeG201 = []CodeSample{
		{`
// Format string without proper quoting
package main
import (
	"database/sql"
	"fmt"
	"os"
	//_ "github.com/mattn/go-sqlite3"
)

func main(){
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		panic(err)
	}
	q := fmt.Sprintf("SELECT * FROM foo where name = '%s'", os.Args[1])
	rows, err := db.Query(q)
	if err != nil {
		panic(err)
	}
	defer rows.Close()
}`, 1}, {`
// Format string false positive, safe string spec.
package main
import (
	"database/sql"
	"fmt"
	"os"
	//_ "github.com/mattn/go-sqlite3"
)

func main(){
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		panic(err)
	}
	q := fmt.Sprintf("SELECT * FROM foo where id = %d", os.Args[1])
	rows, err := db.Query(q)
	if err != nil {
		panic(err)
	}
	defer rows.Close()
}`, 0}, {
			`
// Format string false positive
package main
import (
		"database/sql"
		//_ "github.com/mattn/go-sqlite3"
)
var staticQuery = "SELECT * FROM foo WHERE age < 32"
func main(){
		db, err := sql.Open("sqlite3", ":memory:")
		if err != nil {
				panic(err)
		}
		rows, err := db.Query(staticQuery)
		if err != nil {
				panic(err)
		}
		defer rows.Close()
}`, 0}}

	// SampleCodeG202 - SQL query string building via string concatenation
	SampleCodeG202 = []CodeSample{
		{`
package main
import (
	"database/sql"
	//_ "github.com/mattn/go-sqlite3"
	"os"
)
func main(){
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		panic(err)
	}
	rows, err := db.Query("SELECT * FROM foo WHERE name = " + os.Args[1])
	if err != nil {
		panic(err)
	}
	defer rows.Close()
}`, 1}, {`
// false positive
package main
import (
	"database/sql"
	//_ "github.com/mattn/go-sqlite3"
)
var staticQuery = "SELECT * FROM foo WHERE age < "
func main(){
	db, err := sql.Open("sqlite3", ":memory:")
    if err != nil {
		panic(err)
	}
	rows, err := db.Query(staticQuery + "32")
	if err != nil {
		panic(err)
	}
    defer rows.Close()
}`, 0}, {`
package main
import (
		"database/sql"
		//_ "github.com/mattn/go-sqlite3"
)
const age = "32"
var staticQuery = "SELECT * FROM foo WHERE age < "
func main(){
		db, err := sql.Open("sqlite3", ":memory:")
		if err != nil {
				panic(err)
		}
		rows, err := db.Query(staticQuery + age)
		if err != nil {
				panic(err)
		}
		defer rows.Close()
}
`, 0}}

	// SampleCodeG203 - Template checks
	SampleCodeG203 = []CodeSample{
		{`
// We assume that hardcoded template strings are safe as the programmer would
// need to be explicitly shooting themselves in the foot (as below)
package main
import (
	"html/template"
	"os"
)
const tmpl = ""
func main() {
	t := template.Must(template.New("ex").Parse(tmpl))
	v := map[string]interface{}{
		"Title":    "Test <b>World</b>",
		"Body":     template.HTML("<script>alert(1)</script>"),
	}
	t.Execute(os.Stdout, v)
}`, 0}, {
			`
// Using a variable to initialize could potentially be dangerous. Under the
// current model this will likely produce some false positives.
package main
import (
	"html/template"
	"os"
)
const tmpl = ""
func main() {
	a := "something from another place"
	t := template.Must(template.New("ex").Parse(tmpl))
	v := map[string]interface{}{
		"Title":    "Test <b>World</b>",
		"Body":     template.HTML(a),
	}
	t.Execute(os.Stdout, v)
}`, 1}, {
			`
package main
import (
	"html/template"
	"os"
)
const tmpl = ""
func main() {
	a := "something from another place"
	t := template.Must(template.New("ex").Parse(tmpl))
	v := map[string]interface{}{
		"Title":    "Test <b>World</b>",
		"Body":     template.JS(a),
	}
	t.Execute(os.Stdout, v)
}`, 1}, {
			`
package main
import (
	"html/template"
	"os"
)
const tmpl = ""
func main() {
	a := "something from another place"
	t := template.Must(template.New("ex").Parse(tmpl))
	v := map[string]interface{}{
		"Title":    "Test <b>World</b>",
		"Body":     template.URL(a),
	}
	t.Execute(os.Stdout, v)
}`, 1}}

	// SampleCodeG204 - Subprocess auditing
	SampleCodeG204 = []CodeSample{{`
package main
import "syscall"
func main() {
	syscall.Exec("/bin/cat", []string{ "/etc/passwd" }, nil)
}`, 1}, {`
package main
import (
	"log"
	"os/exec"
)
func main() {
	cmd := exec.Command("sleep", "5")
	err := cmd.Start()
 	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Waiting for command to finish...")
  	err = cmd.Wait()
  	log.Printf("Command finished with error: %v", err)
}`, 1}, {`
package main
import (
	"log"
	"os/exec"
	"context"
)
func main() {
	err := exec.CommandContext(context.Background(), "sleep", "5").Run()
 	if err != nil {
		log.Fatal(err)
	}
  	log.Printf("Command finished with error: %v", err)
}`, 1}, {`
package main
import (
	"log"
	"os"
	"os/exec"
)
func main() {
	run := "sleep" + os.Getenv("SOMETHING")
	cmd := exec.Command(run, "5")
	err := cmd.Start()
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Waiting for command to finish...")
	err = cmd.Wait()
	log.Printf("Command finished with error: %v", err)
}`, 1}}

	// SampleCodeG301 - mkdir permission check
	SampleCodeG301 = []CodeSample{{`
package main
import "os"
func main() {
	os.Mkdir("/tmp/mydir", 0777)
	os.Mkdir("/tmp/mydir", 0600)
	os.MkdirAll("/tmp/mydir/mysubidr", 0775)
}`, 2}}

	// SampleCodeG302 - file create / chmod permissions check
	SampleCodeG302 = []CodeSample{{`
package main
import "os"
func main() {
	os.Chmod("/tmp/somefile", 0777)
	os.Chmod("/tmp/someotherfile", 0600)
	os.OpenFile("/tmp/thing", os.O_CREATE|os.O_WRONLY, 0666)
	os.OpenFile("/tmp/thing", os.O_CREATE|os.O_WRONLY, 0600)
}`, 2}}

	// SampleCodeG303 - bad tempfile permissions & hardcoded shared path
	SampleCodeG303 = []CodeSample{{`
package samples
import (
	"io/ioutil"
	"os"
)
func main() {
	file1, _ := os.Create("/tmp/demo1")
	defer file1.Close()
	ioutil.WriteFile("/tmp/demo2", []byte("This is some data"), 0644)
}`, 2}}

	// SampleCodeG304 - potential file inclusion vulnerability
	SampleCodeG304 = []CodeSample{{`
package main
import (
"os"
"io/ioutil"
"log"
)
func main() {
f := os.Getenv("tainted_file")
body, err := ioutil.ReadFile(f)
if err != nil {
 log.Printf("Error: %v\n", err)
}
log.Print(body)

}`, 1}, {`
package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
)

func main() {
	http.HandleFunc("/bar", func(w http.ResponseWriter, r *http.Request) {
  		title := r.URL.Query().Get("title")
		f, err := os.Open(title)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
		}
		body := make([]byte, 5)
		if _, err = f.Read(body); err != nil {
			fmt.Printf("Error: %v\n", err)
		}
		fmt.Fprintf(w, "%s", body)
	})
	log.Fatal(http.ListenAndServe(":3000", nil))
}`, 1}, {`
package main

import (
	"log"
	"os"
	"io/ioutil"
)

	func main() {
		f2 := os.Getenv("tainted_file2")
		body, err := ioutil.ReadFile("/tmp/" + f2)
		if err != nil {
		log.Printf("Error: %v\n", err)
	  }
		log.Print(body)
 }`, 1}, {`
 package main

 import (
	 "bufio"
	 "fmt"
	 "os"
	 "path/filepath"
 )

func main() {
	reader := bufio.NewReader(os.Stdin)
  fmt.Print("Please enter file to read: ")
	file, _ := reader.ReadString('\n')
	file = file[:len(file)-1]
	f, err := os.Open(filepath.Join("/tmp/service/", file))
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	}
	contents := make([]byte, 15)
  if _, err = f.Read(contents); err != nil {
		fmt.Printf("Error: %v\n", err)
	}
  fmt.Println(string(contents))
}`, 1}, {`
package main

import (
	"log"
	"os"
	"io/ioutil"
	"path/filepath"
)

func main() {
	dir := os.Getenv("server_root")
	f3 := os.Getenv("tainted_file3")
	// edge case where both a binary expression and file Join are used.
	body, err := ioutil.ReadFile(filepath.Join("/var/"+dir, f3))
	if err != nil {
		log.Printf("Error: %v\n", err)
	}
	log.Print(body)
}`, 1}}

	// SampleCodeG305 - File path traversal when extracting zip archives
	SampleCodeG305 = []CodeSample{{`
package unzip

import (
	"archive/zip"
	"io"
	"os"
	"path/filepath"
)

func unzip(archive, target string) error {
	reader, err := zip.OpenReader(archive)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(target, 0750); err != nil {
		return err
	}

	for _, file := range reader.File {
		path := filepath.Join(target, file.Name)
		if file.FileInfo().IsDir() {
			os.MkdirAll(path, file.Mode()) // #nosec
			continue
		}

		fileReader, err := file.Open()
		if err != nil {
			return err
		}
		defer fileReader.Close()

		targetFile, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, file.Mode())
		if err != nil {
			return err
		}
		defer targetFile.Close()

		if _, err := io.Copy(targetFile, fileReader); err != nil {
			return err
		}
	}

	return nil
}`, 1}, {`
package unzip

import (
	"archive/zip"
	"io"
	"os"
	"path/filepath"
)

func unzip(archive, target string) error {
	reader, err := zip.OpenReader(archive)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(target, 0750); err != nil {
		return err
	}

	for _, file := range reader.File {
                archiveFile := file.Name
		path := filepath.Join(target, archiveFile)
		if file.FileInfo().IsDir() {
			os.MkdirAll(path, file.Mode()) // #nosec
			continue
		}

		fileReader, err := file.Open()
		if err != nil {
			return err
		}
		defer fileReader.Close()

		targetFile, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, file.Mode())
		if err != nil {
			return err
		}
		defer targetFile.Close()

		if _, err := io.Copy(targetFile, fileReader); err != nil {
			return err
		}
	}

	return nil
}`, 1}}

	// SampleCodeG401 - Use of weak crypto MD5
	SampleCodeG401 = []CodeSample{
		{`
package main
import (
	"crypto/md5"
	"fmt"
	"io"
	"log"
	"os"
)
func main() {
	f, err := os.Open("file.txt")
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	h := md5.New()
	if _, err := io.Copy(h, f); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%x", h.Sum(nil))
}`, 1}}

	// SampleCodeG401b - Use of weak crypto SHA1
	SampleCodeG401b = []CodeSample{
		{`
package main
import (
	"crypto/sha1"
	"fmt"
	"io"
	"log"
	"os"
)
func main() {
	f, err := os.Open("file.txt")
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	h := sha1.New()
	if _, err := io.Copy(h, f); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%x", h.Sum(nil))
}`, 1}}

	// SampleCodeG402 - TLS settings
	SampleCodeG402 = []CodeSample{{`
// InsecureSkipVerify
package main
import (
	"crypto/tls"
	"fmt"
	"net/http"
)
func main() {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	client := &http.Client{Transport: tr}
	_, err := client.Get("https://golang.org/")
	if err != nil {
		fmt.Println(err)
	}
}`, 1}, {
		`
// Insecure minimum version
package main
import (
	"crypto/tls"
	"fmt"
	"net/http"
)
func main() {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{MinVersion: 0},
	}
	client := &http.Client{Transport: tr}
	_, err := client.Get("https://golang.org/")
	if err != nil {
		fmt.Println(err)
	}
}`, 1}, {`
// Insecure max version
package main
import (
	"crypto/tls"
	"fmt"
	"net/http"
)
func main() {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{MaxVersion: 0},
	}
	client := &http.Client{Transport: tr}
	_, err := client.Get("https://golang.org/")
	if err != nil {
		fmt.Println(err)
	}
}
`, 1}, {
		`
// Insecure ciphersuite selection
package main
import (
	"crypto/tls"
	"fmt"
	"net/http"
)
func main() {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{CipherSuites: []uint16{
						tls.TLS_RSA_WITH_RC4_128_SHA,
						tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
						},},
	}
	client := &http.Client{Transport: tr}
	_, err := client.Get("https://golang.org/")
	if err != nil {
		fmt.Println(err)
	}
}`, 1}}

	// SampleCodeG403 - weak key strength
	SampleCodeG403 = []CodeSample{
		{`
package main
import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
)
func main() {
	//Generate Private Key
	pvk, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(pvk)
}`, 1}}

	// SampleCodeG404 - weak random number
	SampleCodeG404 = []CodeSample{
		{`
package main
import "crypto/rand"
func main() {
	good, _ := rand.Read(nil)
	println(good)
}`, 0}, {`
package main
import "math/rand"
func main() {
	bad := rand.Int()
	println(bad)
}`, 1}, {`
package main
import (
	"crypto/rand"
	mrand "math/rand"
)
func main() {
	good, _ := rand.Read(nil)
	println(good)
	i := mrand.Int31()
	println(i)
}`, 0}}

	// SampleCodeG501 - Blacklisted import MD5
	SampleCodeG501 = []CodeSample{
		{`
package main
import (
	"crypto/md5"
	"fmt"
	"os"
)
func main() {
	for _, arg := range os.Args {
		fmt.Printf("%x - %s\n", md5.Sum([]byte(arg)), arg)
	}
}`, 1}}

	// SampleCodeG502 - Blacklisted import DES
	SampleCodeG502 = []CodeSample{
		{`
package main
import (
	"crypto/cipher"
	"crypto/des"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
)
func main() {
	block, err := des.NewCipher([]byte("sekritz"))
	if err != nil {
		panic(err)
	}
	plaintext := []byte("I CAN HAZ SEKRIT MSG PLZ")
	ciphertext := make([]byte, des.BlockSize+len(plaintext))
	iv := ciphertext[:des.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[des.BlockSize:], plaintext)
	fmt.Println("Secret message is: %s", hex.EncodeToString(ciphertext))
}`, 1}}

	// SampleCodeG503 - Blacklisted import RC4
	SampleCodeG503 = []CodeSample{{`
package main
import (
	"crypto/rc4"
	"encoding/hex"
	"fmt"
)
func main() {
	cipher, err := rc4.NewCipher([]byte("sekritz"))
	if err != nil {
		panic(err)
	}
	plaintext := []byte("I CAN HAZ SEKRIT MSG PLZ")
	ciphertext := make([]byte, len(plaintext))
	cipher.XORKeyStream(ciphertext, plaintext)
	fmt.Println("Secret message is: %s", hex.EncodeToString(ciphertext))
}`, 1}}

	// SampleCodeG504 - Blacklisted import CGI
	SampleCodeG504 = []CodeSample{{`
package main
import (
	"net/http/cgi"
	"net/http"
 )
func main() {
	cgi.Serve(http.FileServer(http.Dir("/usr/share/doc")))
}`, 1}}
	// SampleCodeG505 - Blacklisted import SHA1
	SampleCodeG505 = []CodeSample{
		{`
package main
import (
	"crypto/sha1"
	"fmt"
	"os"
)
func main() {
	for _, arg := range os.Args {
		fmt.Printf("%x - %s\n", sha1.Sum([]byte(arg)), arg)
	}
}`, 1}}
	// SampleCode601 - Go build tags
	SampleCode601 = []CodeSample{{`
// +build test

package main
func main() {
  fmt.Println("no package imported error")
}`, 1}}
)

"""



```