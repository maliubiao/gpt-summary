Response:
Let's break down the thought process for analyzing the provided Go code and generating the response.

**1. Understanding the Goal:**

The primary goal is to understand the purpose and functionality of the given Go code snippet, which is a test file for a tool named `impl`. The request asks for a functional overview, inference about the underlying functionality, code examples, explanation of command-line arguments (if applicable), and common pitfalls.

**2. Initial Code Scan and Identification of Test Functions:**

The first step is to scan the code and identify the key elements. The presence of `import "testing"` immediately signals that this is a test file. The functions starting with `Test` are the core components we need to analyze. We see functions like `TestFindInterface`, `TestTypeSpec`, `TestFuncs`, `TestValidReceiver`, `TestValidMethodComments`, and `TestStubGeneration`.

**3. Analyzing Individual Test Functions:**

For each test function, the strategy is to:

* **Identify the Unit Under Test (UUT):** Look for the function being called within the test. For example, `TestFindInterface` calls `findInterface`, `TestTypeSpec` calls `typeSpec`, and so on. This is crucial for understanding what functionality is being tested.
* **Examine the Test Cases:** Look at the `cases` variable within each test function. These are the inputs and expected outputs used to verify the UUT's behavior.
* **Infer the Functionality Based on Test Cases:** By analyzing the input and expected output pairs, we can deduce the purpose of the UUT.

**Example - `TestFindInterface`:**

* **UUT:** `findInterface`
* **Test Cases:**
    * `{"net.Conn", "net", "Conn", false}`:  Input is "net.Conn", expects "net" as path and "Conn" as ID, no error.
    * `{"http.ResponseWriter", "net/http", "ResponseWriter", false}`: Input is "http.ResponseWriter", expects "net/http" and "ResponseWriter", no error.
    * Various error cases: Invalid interface strings are expected to return errors.
* **Inference:** `findInterface` likely takes an interface name as input and attempts to parse it into its package path and identifier. It also handles invalid interface names.

**Example - `TestFuncs`:**

* **UUT:** `funcs`
* **Test Cases:**
    * `{"io.ReadWriter", ...}`: Input is "io.ReadWriter", expects a list of `Func` structs representing the `Read` and `Write` methods with their parameters and return types.
    * `{"http.ResponseWriter", ...}`: Similar structure for `http.ResponseWriter`.
    * Error case: Invalid interface name.
* **Inference:** `funcs` likely extracts the function signatures (name, parameters, return types) from a given interface.

**4. Looking for Patterns and Connections:**

After analyzing individual tests, we can start to see connections. The names of the tested functions (`findInterface`, `typeSpec`, `funcs`, `genStubs`) suggest a workflow. It appears the tool is designed to:

1. **Parse interface names:** (`findInterface`)
2. **Get type information:** (`typeSpec`)
3. **Extract function signatures:** (`funcs`)
4. **Generate stub implementations:** (`genStubs`)

**5. Inferring the Overall Purpose:**

Based on the individual function analysis and the inferred workflow, the overall purpose of the `impl` tool becomes clearer. It seems to be a tool that helps generate boilerplate code for implementing Go interfaces.

**6. Constructing the Code Examples:**

Once the functionality is understood, constructing the code examples becomes straightforward. The examples demonstrate how the inferred functions might be used and illustrate the expected inputs and outputs. For `findInterface`, the example shows how it parses the interface name. For `funcs`, it shows how to extract function signatures.

**7. Considering Command-Line Arguments:**

At this point, a crucial observation is that the provided code is purely a test file. It doesn't directly demonstrate how command-line arguments are handled. Therefore, the correct answer is to state that the test file itself doesn't show command-line argument processing, but the *impl* tool likely *does*. This requires a bit of deduction based on the tool's likely purpose. A tool for generating interface implementations would almost certainly take the interface name as a command-line argument.

**8. Identifying Potential Pitfalls:**

Common mistakes when using such a tool would likely involve:

* **Incorrect interface names:**  Typographical errors or not fully qualified names.
* **Misunderstanding receiver names:**  Not providing a valid receiver name for the generated methods.

**9. Structuring the Response:**

Finally, the information needs to be organized into a clear and understandable answer, addressing all the points raised in the original request:

* **的功能:**  Summarize the core functionalities of the tested functions.
* **是什么go语言功能的实现:**  Provide a high-level explanation of the tool's purpose (interface implementation generation).
* **go代码举例说明:**  Give concrete examples demonstrating the usage of the inferred functions with input and output.
* **命令行参数的具体处理:**  Explain that the test file doesn't show this, but deduce likely command-line arguments.
* **使用者易犯错的点:**  Provide examples of common errors users might encounter.

**Self-Correction/Refinement:**

During the process, there might be moments of uncertainty. For example, initially, one might be unsure about the exact purpose of `typeSpec`. However, by seeing its usage in conjunction with `funcs`, it becomes clearer that it's involved in retrieving type information necessary for function signature extraction. Similarly, the `genStubs` function strongly suggests the goal of code generation. This iterative process of analyzing individual parts and then synthesizing the overall picture is key.
这个Go语言实现文件 `impl_test.go` 是 `impl` 工具的测试文件。`impl` 工具的主要功能是**根据给定的接口定义，自动生成该接口的空实现代码（也称为桩代码或存根）**。

让我们详细分析一下这个测试文件中的各个测试用例，从而更深入地理解 `impl` 工具的功能：

**1. `TestFindInterface(t *testing.T)`:**

   - **功能:** 测试 `findInterface` 函数，该函数负责解析接口名称字符串，并从中提取接口所在的包路径和接口名称。
   - **推断:** `findInterface` 接收一个接口的完整名称字符串（例如 "net.Conn" 或 "net/http.ResponseWriter"），并返回该接口所在的包路径（例如 "net" 或 "net/http"）以及接口的标识符（例如 "Conn" 或 "ResponseWriter"）。
   - **代码举例:**
     ```go
     package main

     import "fmt"

     func main() {
         path, id, err := findInterface("net.Conn", ".")
         if err != nil {
             fmt.Println("Error:", err)
         } else {
             fmt.Printf("Path: %s, ID: %s\n", path, id) // 输出: Path: net, ID: Conn
         }

         path, id, err = findInterface("github.com/youruser/yourpackage.YourInterface", ".")
         if err != nil {
             fmt.Println("Error:", err)
         } else {
             fmt.Printf("Path: %s, ID: %s\n", path, id) // 输出: Path: github.com/youruser/yourpackage, ID: YourInterface
         }

         _, _, err = findInterface("invalid interface name", ".")
         if err != nil {
             fmt.Println("Error:", err) // 输出: Error: ... (具体的错误信息)
         }
     }
     ```
   - **假设的输入与输出:**
     - 输入: "net.Conn"
     - 输出: path = "net", id = "Conn", err = nil
     - 输入: "net/http.ResponseWriter"
     - 输出: path = "net/http", id = "ResponseWriter", err = nil
     - 输入: "net.Tennis" (假设 `net` 包下没有 `Tennis` 接口)
     - 输出: err != nil (返回一个错误)
     - 输入: "a + b" (无效的接口名称)
     - 输出: err != nil (返回一个错误)

**2. `TestTypeSpec(t *testing.T)`:**

   - **功能:** 测试 `typeSpec` 函数，该函数根据给定的包路径和接口标识符，查找并返回接口的类型规范（`TypeSpec`）。
   - **推断:** `typeSpec` 接收包路径和接口名称，然后在指定的包中查找对应的接口定义，并返回包含该接口详细信息的结构体。
   - **代码举例:**
     ```go
     package main

     import (
         "fmt"
         "go/ast"
     )

     func main() {
         pkg, spec, err := typeSpec("net", "Conn", "")
         if err != nil {
             fmt.Println("Error:", err)
         } else {
             fmt.Printf("Package: %v, Spec: %T\n", pkg, spec) // 输出: Package: {}, Spec: *ast.TypeSpec
             ifaceSpec := spec.(*ast.TypeSpec).Type.(*ast.InterfaceType)
             fmt.Println("Number of methods:", len(ifaceSpec.Methods.List)) // 输出接口的方法数量
         }

         _, _, err = typeSpec("net", "Con", "") // 假设 net 包下没有 Con 这个类型
         if err != nil {
             fmt.Println("Error:", err) // 输出: Error: ... (找不到类型的错误)
         }
     }
     ```
   - **假设的输入与输出:**
     - 输入: path = "net", id = "Conn"
     - 输出: pkg (包含 net 包的信息), spec (*ast.TypeSpec, 代表 net.Conn 的类型定义), err = nil
     - 输入: path = "net", id = "Con" (假设 net 包下没有名为 "Con" 的类型)
     - 输出: err != nil (返回一个错误)

**3. `TestFuncs(t *testing.T)`:**

   - **功能:** 测试 `funcs` 函数，该函数根据给定的接口名称，提取该接口中定义的所有方法及其签名信息（参数和返回值）。
   - **推断:** `funcs` 接收一个接口的完整名称，然后解析该接口的定义，并返回一个包含 `Func` 结构体切片，每个 `Func` 结构体描述一个方法的名称、参数列表和返回值列表。
   - **代码举例:**
     ```go
     package main

     import "fmt"

     func main() {
         funcs, err := funcs("io.ReadWriter", "")
         if err != nil {
             fmt.Println("Error:", err)
         } else {
             fmt.Println("Methods of io.ReadWriter:")
             for _, f := range funcs {
                 fmt.Printf("  Name: %s, Params: %v, Results: %v\n", f.Name, f.Params, f.Res)
             }
         }

         funcs, err = funcs("net.Tennis", "") // 假设 net 包下没有 Tennis 接口
         if err != nil {
             fmt.Println("Error:", err) // 输出: Error: ... (找不到接口的错误)
         }
     }
     ```
   - **假设的输入与输出:**
     - 输入: "io.ReadWriter"
     - 输出:
       ```
       []main.Func{
           {Name: "Read", Params: []main.Param{{Name: "p", Type: "[]byte"}}, Res: []main.Param{{Name: "n", Type: "int"}, {Name: "err", Type: "error"}}},
           {Name: "Write", Params: []main.Param{{Name: "p", Type: "[]byte"}}, Res: []main.Param{{Name: "n", Type: "int"}, {Name: "err", Type: "error"}}},
       }
       ```
     - 输入: "http.ResponseWriter"
     - 输出: 包含 `Header`, `Write`, `WriteHeader` 等方法的 `Func` 结构体切片。
     - 输入: "net.Tennis" (假设 `net` 包下没有 `Tennis` 接口)
     - 输出: err != nil (返回一个错误)

**4. `TestValidReceiver(t *testing.T)`:**

   - **功能:** 测试 `validReceiver` 函数，该函数用于验证给定的接收器（receiver）名称是否有效。
   - **推断:** `validReceiver` 检查接收器的命名是否符合 Go 语言的规范，例如可以是单个小写字母、大写字母，或者是指针类型。
   - **代码举例:**
     ```go
     package main

     import "fmt"

     func main() {
         fmt.Println(validReceiver("r"))     // 输出: true
         fmt.Println(validReceiver("R"))     // 输出: true
         fmt.Println(validReceiver("r *MyType")) // 输出: true
         fmt.Println(validReceiver(""))    // 输出: false
         fmt.Println(validReceiver("a+b"))   // 输出: false
     }
     ```
   - **假设的输入与输出:**
     - 输入: "f"
     - 输出: true
     - 输入: "F"
     - 输出: true
     - 输入: "f *MyStruct"
     - 输出: true
     - 输入: ""
     - 输出: false
     - 输入: "a+b"
     - 输出: false

**5. `TestValidMethodComments(t *testing.T)`:**

   - **功能:** 测试 `funcs` 函数在提取接口方法信息时，是否能够正确地解析和包含方法的注释。
   - **推断:**  这部分测试验证 `funcs` 函数除了提取方法名、参数和返回值外，还能获取方法声明前的注释信息。
   - **代码举例:** (此功能已经在 `TestFuncs` 的推断中有所体现，这里主要是验证注释的提取)
   - **假设的输入与输出:**
     - 输入: "github.com/josharian/impl/testdata.Interface1" (该接口的定义包含方法注释)
     - 输出: 返回的 `Func` 结构体中，`Comments` 字段会包含对应方法的注释内容。

**6. `TestStubGeneration(t *testing.T)`:**

   - **功能:** 测试 `genStubs` 函数，该函数负责根据给定的接收器名称和接口的方法信息，生成接口实现的桩代码。
   - **推断:** `genStubs` 接收一个接收器名称（例如 "r *MyImpl"）和一个包含接口方法信息的 `Func` 结构体切片，然后生成一个符合 Go 语言语法的代码片段，其中包含了该接口所有方法的空实现。
   - **代码举例:**
     ```go
     package main

     import "fmt"

     func main() {
         funcs, _ := funcs("io.ReadWriter", "")
         stubCode := genStubs("rw *MyReadWriter", funcs)
         fmt.Println(string(stubCode))
         /*
         Output 可能如下:
         func (rw *MyReadWriter) Read(p []byte) (n int, err error) {
             panic("not implemented")
         }

         func (rw *MyReadWriter) Write(p []byte) (n int, err error) {
             panic("not implemented")
         }
         */
     }
     ```
   - **假设的输入与输出:**
     - 输入: receiver = "r *Receiver", fns (来自 "io.ReadWriter" 接口的 `Func` 结构体)
     - 输出: 生成如下 Go 代码字符串:
       ```go
       func (r *Receiver) Read(p []byte) (n int, err error) {
           panic("not implemented")
       }

       func (r *Receiver) Write(p []byte) (n int, err error) {
           panic("not implemented")
       }
       ```

**总结 `impl` 工具的功能:**

根据以上测试用例的分析，我们可以得出 `impl` 工具的主要功能是：

1. **解析接口名称:** 能够正确解析各种格式的接口名称字符串，提取包路径和接口标识符。
2. **查找接口定义:** 能够根据包路径和接口标识符，在 Go 代码中找到对应的接口定义。
3. **提取方法信息:** 能够从接口定义中提取所有方法的名称、参数列表、返回值列表以及注释信息。
4. **生成桩代码:** 能够根据给定的接收器名称和接口的方法信息，自动生成该接口的空实现代码。

**命令行参数的具体处理:**

虽然这个测试文件本身没有展示命令行参数的处理，但可以推断 `impl` 工具很可能通过命令行参数接收以下信息：

- **接口名称:**  指定要实现哪个接口，例如 `impl net.Conn`。
- **接收器名称:** 指定生成的实现类型的方法接收器名称，例如 `impl -r "c *MyConn" net.Conn`。
- **输出文件路径（可选）:** 指定生成的代码输出到哪个文件。

**使用者易犯错的点:**

1. **错误的接口名称:** 用户可能会输入错误的接口名称，例如拼写错误或者没有包含完整的包路径，导致工具无法找到对应的接口。
   - **例子:** 假设要实现 `net/http` 包下的 `ResponseWriter` 接口，如果用户输入 `impl ResponseWriter`，则会因为缺少包路径而报错。正确的输入应该是 `impl net/http.ResponseWriter`。

2. **接收器命名不规范:**  用户可能会使用不符合 Go 语言规范的接收器名称，导致生成的代码无法编译通过。
   - **例子:** 如果用户使用 `impl -r "1a *MyConn" net.Conn`，由于 "1a" 不是一个合法的标识符开头，生成的代码会编译失败。正确的做法是使用字母开头的标识符，例如 `impl -r "c *MyConn" net.Conn`。

总而言之，`go/src/github.com/josharian/impl/impl_test.go` 文件是用于测试 `impl` 这个 Go 语言工具的核心功能的测试代码，通过分析这些测试用例，我们可以清晰地理解 `impl` 工具是如何解析接口、提取方法信息以及生成接口实现代码的。

Prompt: 
```
这是路径为go/src/github.com/josharian/impl/impl_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
package main

import (
	"reflect"
	"testing"

	"github.com/josharian/impl/testdata"
)

type errBool bool

func (b errBool) String() string {
	if b {
		return "an error"
	}
	return "no error"
}

func TestFindInterface(t *testing.T) {
	cases := []struct {
		iface   string
		path    string
		id      string
		wantErr bool
	}{
		{iface: "net.Conn", path: "net", id: "Conn"},
		{iface: "http.ResponseWriter", path: "net/http", id: "ResponseWriter"},
		{iface: "net.Tennis", wantErr: true},
		{iface: "a + b", wantErr: true},
		{iface: "a/b/c/", wantErr: true},
		{iface: "a/b/c/pkg", wantErr: true},
		{iface: "a/b/c/pkg.", wantErr: true},
		{iface: "a/b/c/pkg.Typ", path: "a/b/c/pkg", id: "Typ"},
		{iface: "a/b/c/pkg.Typ.Foo", wantErr: true},
	}

	for _, tt := range cases {
		path, id, err := findInterface(tt.iface, ".")
		gotErr := err != nil
		if tt.wantErr != gotErr {
			t.Errorf("findInterface(%q).err=%v want %s", tt.iface, err, errBool(tt.wantErr))
			continue
		}
		if tt.path != path {
			t.Errorf("findInterface(%q).path=%q want %q", tt.iface, path, tt.path)
		}
		if tt.id != id {
			t.Errorf("findInterface(%q).id=%q want %q", tt.iface, id, tt.id)
		}
	}
}

func TestTypeSpec(t *testing.T) {
	// For now, just test whether we can find the interface.
	cases := []struct {
		path    string
		id      string
		wantErr bool
	}{
		{path: "net", id: "Conn"},
		{path: "net", id: "Con", wantErr: true},
	}

	for _, tt := range cases {
		p, spec, err := typeSpec(tt.path, tt.id, "")
		gotErr := err != nil
		if tt.wantErr != gotErr {
			t.Errorf("typeSpec(%q, %q).err=%v want %s", tt.path, tt.id, err, errBool(tt.wantErr))
			continue
		}
		if err == nil {
			if reflect.DeepEqual(p, Pkg{}) {
				t.Errorf("typeSpec(%q, %q).pkg=Pkg{} want non-nil", tt.path, tt.id)
			}
			if reflect.DeepEqual(spec, Spec{}) {
				t.Errorf("typeSpec(%q, %q).spec=Spec{} want non-nil", tt.path, tt.id)
			}
		}
	}
}

func TestFuncs(t *testing.T) {
	cases := []struct {
		iface   string
		want    []Func
		wantErr bool
	}{
		{
			iface: "io.ReadWriter",
			want: []Func{
				{
					Name:   "Read",
					Params: []Param{{Name: "p", Type: "[]byte"}},
					Res: []Param{
						{Name: "n", Type: "int"},
						{Name: "err", Type: "error"},
					},
				},
				{
					Name:   "Write",
					Params: []Param{{Name: "p", Type: "[]byte"}},
					Res: []Param{
						{Name: "n", Type: "int"},
						{Name: "err", Type: "error"},
					},
				},
			},
		},
		{
			iface: "http.ResponseWriter",
			want: []Func{
				{
					Name: "Header",
					Res:  []Param{{Type: "http.Header"}},
				},
				{
					Name:   "Write",
					Params: []Param{{Name: "_", Type: "[]byte"}},
					Res:    []Param{{Type: "int"}, {Type: "error"}},
				},
				{
					Name:   "WriteHeader",
					Params: []Param{{Type: "int", Name: "statusCode"}},
				},
			},
		},
		{
			iface: "http.Handler",
			want: []Func{
				{
					Name: "ServeHTTP",
					Params: []Param{
						{Name: "_", Type: "http.ResponseWriter"},
						{Name: "_", Type: "*http.Request"},
					},
				},
			},
		},
		{
			iface: "ast.Node",
			want: []Func{
				{
					Name: "Pos",
					Res:  []Param{{Type: "token.Pos"}},
				},
				{
					Name: "End",
					Res:  []Param{{Type: "token.Pos"}},
				},
			},
		},
		{
			iface: "cipher.AEAD",
			want: []Func{
				{
					Name: "NonceSize",
					Res:  []Param{{Type: "int"}},
				},
				{
					Name: "Overhead",
					Res:  []Param{{Type: "int"}},
				},
				{
					Name: "Seal",
					Params: []Param{
						{Name: "dst", Type: "[]byte"},
						{Name: "nonce", Type: "[]byte"},
						{Name: "plaintext", Type: "[]byte"},
						{Name: "additionalData", Type: "[]byte"},
					},
					Res: []Param{{Type: "[]byte"}},
				},
				{
					Name: "Open",
					Params: []Param{
						{Name: "dst", Type: "[]byte"},
						{Name: "nonce", Type: "[]byte"},
						{Name: "ciphertext", Type: "[]byte"},
						{Name: "additionalData", Type: "[]byte"},
					},
					Res: []Param{{Type: "[]byte"}, {Type: "error"}},
				},
			},
		},
		{
			iface: "error",
			want: []Func{
				{
					Name: "Error",
					Res:  []Param{{Type: "string"}},
				},
			},
		},
		{
			iface: "error",
			want: []Func{
				{
					Name: "Error",
					Res:  []Param{{Type: "string"}},
				},
			},
		},
		{
			iface: "http.Flusher",
			want: []Func{
				{
					Name:     "Flush",
					Comments: "// Flush sends any buffered data to the client.\n",
				},
			},
		},
		{
			iface: "net.Listener",
			want: []Func{
				{
					Name: "Accept",
					Res:  []Param{{Type: "net.Conn"}, {Type: "error"}},
				},
				{
					Name: "Close",
					Res:  []Param{{Type: "error"}},
				},
				{
					Name: "Addr",
					Res:  []Param{{Type: "net.Addr"}},
				},
			},
		},
		{iface: "net.Tennis", wantErr: true},
	}

	for _, tt := range cases {
		fns, err := funcs(tt.iface, "")
		gotErr := err != nil
		if tt.wantErr != gotErr {
			t.Errorf("funcs(%q).err=%v want %s", tt.iface, err, errBool(tt.wantErr))
			continue
		}

		if len(fns) != len(tt.want) {
			t.Errorf("funcs(%q).fns=\n%v\nwant\n%v\n", tt.iface, fns, tt.want)
		}
		for i, fn := range fns {
			if fn.Name != tt.want[i].Name ||
				!reflect.DeepEqual(fn.Params, tt.want[i].Params) ||
				!reflect.DeepEqual(fn.Res, tt.want[i].Res) {

				t.Errorf("funcs(%q).fns=\n%v\nwant\n%v\n", tt.iface, fns, tt.want)
			}
		}
		continue
	}
}

func TestValidReceiver(t *testing.T) {
	cases := []struct {
		recv string
		want bool
	}{
		{recv: "f", want: true},
		{recv: "F", want: true},
		{recv: "f F", want: true},
		{recv: "f *F", want: true},
		{recv: "", want: false},
		{recv: "a+b", want: false},
	}

	for _, tt := range cases {
		got := validReceiver(tt.recv)
		if got != tt.want {
			t.Errorf("validReceiver(%q)=%t want %t", tt.recv, got, tt.want)
		}
	}
}

func TestValidMethodComments(t *testing.T) {
	cases := []struct {
		iface string
		want  []Func
	}{
		{
			iface: "github.com/josharian/impl/testdata.Interface1",
			want: []Func{
				Func{
					Name: "Method1",
					Params: []Param{
						Param{
							Name: "arg1",
							Type: "string",
						}, Param{
							Name: "arg2",
							Type: "string",
						}},
					Res: []Param{
						Param{
							Name: "result",
							Type: "string",
						},
						Param{
							Name: "err",
							Type: "error",
						},
					}, Comments: "// Method1 is the first method of Interface1.\n",
				},
				Func{
					Name: "Method2",
					Params: []Param{
						Param{
							Name: "arg1",
							Type: "int",
						},
						Param{
							Name: "arg2",
							Type: "int",
						},
					},
					Res: []Param{
						Param{
							Name: "result",
							Type: "int",
						},
						Param{
							Name: "err",
							Type: "error",
						},
					},
					Comments: "// Method2 is the second method of Interface1.\n",
				},
				Func{
					Name: "Method3",
					Params: []Param{
						Param{
							Name: "arg1",
							Type: "bool",
						},
						Param{
							Name: "arg2",
							Type: "bool",
						},
					},
					Res: []Param{
						Param{
							Name: "result",
							Type: "bool",
						},
						Param{
							Name: "err",
							Type: "error",
						},
					},
					Comments: "// Method3 is the third method of Interface1.\n",
				},
			},
		},
		{
			iface: "github.com/josharian/impl/testdata.Interface2",
			want: []Func{
				Func{
					Name: "Method1",
					Params: []Param{
						Param{
							Name: "arg1",
							Type: "int64",
						},
						Param{
							Name: "arg2",
							Type: "int64",
						},
					},
					Res: []Param{
						Param{
							Name: "result",
							Type: "int64",
						},
						Param{
							Name: "err",
							Type: "error",
						},
					},
					Comments: "/*\n\t\tMethod1 is the first method of Interface2.\n\t*/\n",
				},
				Func{
					Name: "Method2",
					Params: []Param{
						Param{
							Name: "arg1",
							Type: "float64",
						},
						Param{
							Name: "arg2",
							Type: "float64",
						},
					},
					Res: []Param{
						Param{
							Name: "result",
							Type: "float64",
						},
						Param{
							Name: "err",
							Type: "error",
						},
					},
					Comments: "/*\n\t\tMethod2 is the second method of Interface2.\n\t*/\n",
				},
				Func{
					Name: "Method3",
					Params: []Param{
						Param{
							Name: "arg1",
							Type: "interface{}",
						},
						Param{
							Name: "arg2",
							Type: "interface{}",
						},
					},
					Res: []Param{
						Param{
							Name: "result",
							Type: "interface{}",
						},
						Param{
							Name: "err",
							Type: "error",
						},
					},
					Comments: "/*\n\t\tMethod3 is the third method of Interface2.\n\t*/\n",
				},
			},
		},
		{
			iface: "github.com/josharian/impl/testdata.Interface3",
			want: []Func{
				Func{
					Name: "Method1",
					Params: []Param{
						Param{
							Name: "_",
							Type: "string",
						}, Param{
							Name: "_",
							Type: "string",
						}},
					Res: []Param{
						Param{
							Name: "",
							Type: "string",
						},
						Param{
							Name: "",
							Type: "error",
						},
					}, Comments: "// Method1 is the first method of Interface3.\n",
				},
				Func{
					Name: "Method2",
					Params: []Param{
						Param{
							Name: "_",
							Type: "int",
						},
						Param{
							Name: "arg2",
							Type: "int",
						},
					},
					Res: []Param{
						Param{
							Name: "_",
							Type: "int",
						},
						Param{
							Name: "err",
							Type: "error",
						},
					},
					Comments: "// Method2 is the second method of Interface3.\n",
				},
				Func{
					Name: "Method3",
					Params: []Param{
						Param{
							Name: "arg1",
							Type: "bool",
						},
						Param{
							Name: "arg2",
							Type: "bool",
						},
					},
					Res: []Param{
						Param{
							Name: "result1",
							Type: "bool",
						},
						Param{
							Name: "result2",
							Type: "bool",
						},
					},
					Comments: "// Method3 is the third method of Interface3.\n",
				},
			},
		},
	}

	for _, tt := range cases {
		fns, err := funcs(tt.iface, ".")
		if err != nil {
			t.Errorf("funcs(%q).err=%v", tt.iface, err)
		}
		if !reflect.DeepEqual(fns, tt.want) {
			t.Errorf("funcs(%q).fns=\n%v\nwant\n%v\n", tt.iface, fns, tt.want)
		}
	}
}

func TestStubGeneration(t *testing.T) {
	cases := []struct {
		iface string
		want  string
	}{
		{
			iface: "github.com/josharian/impl/testdata.Interface1",
			want:  testdata.Interface1Output,
		},
		{
			iface: "github.com/josharian/impl/testdata.Interface2",
			want:  testdata.Interface2Output,
		},
		{
			iface: "github.com/josharian/impl/testdata.Interface3",
			want:  testdata.Interface3Output,
		},
	}
	for _, tt := range cases {
		fns, err := funcs(tt.iface, ".")
		if err != nil {
			t.Errorf("funcs(%q).err=%v", tt.iface, err)
		}
		src := genStubs("r *Receiver", fns)
		if string(src) != tt.want {
			t.Errorf("genStubs(\"r *Receiver\", %+#v).src=\n%s\nwant\n%s\n", fns, string(src), tt.want)
		}
	}
}

"""



```