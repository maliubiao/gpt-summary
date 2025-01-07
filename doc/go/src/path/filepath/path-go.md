Response:
My thought process to answer the request goes like this:

1. **Understand the Core Task:** The request asks for a summary of the `path/filepath` package's functionality based on the provided Go source code. It also asks for examples, explanations, and common pitfalls.

2. **Initial Scan and Categorization:** I'd quickly read through the code, noting the function names and their accompanying comments. This helps to broadly categorize the functionalities. My mental categories would likely include:

    * Path cleaning and normalization
    * Path manipulation (joining, splitting, getting parts)
    * Absolute/relative path handling
    * Traversal (walking directories)
    * Platform-specific handling
    * List manipulation

3. **Detailed Function Analysis:** I'd then go through each function, paying close attention to its comment and implementation (even if the implementation calls a `filepathlite` function, the comment usually explains the behavior). For each function, I'd consider:

    * **Purpose:** What does this function do?  What problem does it solve?
    * **Input(s):** What kind of data does it take?
    * **Output(s):** What kind of data does it return?
    * **Special Cases/Edge Cases:** Are there any unusual inputs that lead to specific outputs? (e.g., empty path for `Base`, paths with only separators for `Dir`)
    * **Platform Dependence:**  Does the function behave differently on different operating systems?

4. **Example Generation (Crucial Step):**  The request specifically asks for Go code examples. For each core functionality, I'd devise a simple, illustrative example. This involves:

    * **Choosing Representative Inputs:**  Select input paths that demonstrate the function's main purpose and potentially some edge cases.
    * **Predicting the Output:**  Mentally (or actually) run the function with the chosen input to determine the expected output. This is where understanding the function's logic is key.
    * **Writing Clear Go Code:**  Present the example in a readable format using `fmt.Println` to display the results. Include comments to explain the example.
    * **Considering Different OS:** If a function behaves differently on Windows and Unix, provide separate examples or clearly indicate the OS-specific behavior.

5. **Identifying Underlying Go Features:** The prompt asks if I can identify the *Go language features* being implemented. In this case, `path/filepath` is primarily about string manipulation and interacting with the operating system's file system. Key Go features at play include:

    * **String Manipulation:** Functions like `Clean`, `Join`, `Split`, `Base`, `Dir` heavily rely on Go's string handling capabilities.
    * **OS Interaction:**  The package uses `os.PathSeparator`, `os.PathListSeparator`, `os.Getwd`, `os.Lstat`, `os.ReadDir`, and `os.Open`. This highlights the package's role in bridging the gap between Go programs and the OS file system.
    * **Interfaces (`fs.FileInfo`, `fs.DirEntry`, `fs.WalkDirFunc`):** The `Walk` and `WalkDir` functions utilize the `io/fs` package's interfaces for interacting with the file system in an abstract way.
    * **Error Handling:**  Many functions return errors, demonstrating Go's emphasis on explicit error management.

6. **Addressing Command-Line Arguments:** The `filepath` package itself doesn't directly deal with command-line arguments. However, its functions are *used* extensively when processing file paths provided as command-line arguments. I would explain this indirect relationship.

7. **Highlighting Common Mistakes:**  Based on my understanding of how these functions are used, I'd consider common errors. For example:

    * **Misunderstanding `Clean`:**  People might not fully grasp how `..` is handled.
    * **Incorrectly using `Join`:**  Forgetting that it handles empty strings.
    * **Ignoring OS differences:**  Not realizing that separators are different on Windows and Unix.
    * **Overlooking `EvalSymlinks`:**  Not being aware that symbolic links aren't resolved by default.

8. **Structuring the Answer:** Organize the information logically with clear headings and bullet points. Use clear and concise language. Start with a high-level overview, then go into details for each function, examples, and potential issues.

9. **Review and Refinement:** Before submitting the answer, I'd reread it to ensure accuracy, clarity, and completeness. I'd check if the examples are correct and if the explanations are easy to understand.

By following these steps, I can provide a comprehensive and accurate answer that addresses all aspects of the prompt. The key is to break down the problem, analyze each component, and provide concrete examples to illustrate the concepts.
这段代码是 Go 语言标准库 `path/filepath` 包的一部分，它提供了一系列用于操作文件名路径的实用程序，这些操作会考虑到目标操作系统定义的文件路径约定。 核心思想是让 Go 程序能够以平台无关的方式处理文件路径。

以下是这段代码的主要功能及其详细解释：

**核心功能概览:**

* **路径清理和规范化:**  将路径转换为标准形式，例如移除多余的分隔符、`.` 和 `..`。
* **路径分解和组合:**  将路径分解成目录和文件名，或者将多个路径元素组合成一个完整路径。
* **路径类型判断:**  判断路径是绝对路径还是相对路径，是否是本地路径。
* **路径转换:**  在不同格式的路径之间转换，例如将斜杠分隔的路径转换为操作系统特定的路径。
* **目录遍历:**  递归地遍历目录树，并对每个文件或目录执行指定的操作。
* **扩展名处理:**  提取文件名的扩展名。
* **符号链接处理:**  解析符号链接，获取其指向的真实路径。

**具体功能及 Go 代码示例:**

1. **`Clean(path string) string`**: 清理路径字符串，返回等效的最短路径名。

   * **规则：**
     1. 将多个分隔符替换为一个。
     2. 移除 `.` (当前目录)。
     3. 移除内部的 `..` (父目录) 及其前面的非 `..` 元素。
     4. 移除以根路径开头的 `..`，例如将 `/..` 替换为 `/` (假设分隔符是 `/`)。
     5. 将斜杠替换为操作系统特定的分隔符。
   * **示例:**
     ```go
     package main

     import (
         "fmt"
         "path/filepath"
         "runtime"
     )

     func main() {
         paths := []string{
             "a//b/c",
             "a/./b/../c",
             "/a/../b",
             "..",
             "/..",
         }
         for _, p := range paths {
             cleaned := filepath.Clean(p)
             fmt.Printf("原始路径: %s, 清理后路径: %s\n", p, cleaned)
         }
     }
     ```
   * **假设输入和输出 (在 Unix 系统上):**
     ```
     原始路径: a//b/c, 清理后路径: a/b/c
     原始路径: a/./b/../c, 清理后路径: a/c
     原始路径: /a/../b, 清理后路径: /b
     原始路径: .., 清理后路径: ..
     原始路径: /.., 清理后路径: /
     ```
   * **假设输入和输出 (在 Windows 系统上):**
     ```
     原始路径: a//b/c, 清理后路径: a\b\c
     原始路径: a/./b/../c, 清理后路径: a\c
     原始路径: /a/../b, 清理后路径: \b
     原始路径: .., 清理后路径: ..
     原始路径: /.., 清理后路径: \
     ```

2. **`IsLocal(path string) bool`**: 判断路径是否是本地路径。

   * **特性：**
     * 在评估路径的目录下。
     * 不是绝对路径。
     * 不是空字符串。
     * 在 Windows 上，不是保留名称 (例如 "NUL")。
   * **示例:**
     ```go
     package main

     import (
         "fmt"
         "path/filepath"
         "runtime"
     )

     func main() {
         paths := []string{
             "a/b",
             "./a",
             "../b",
             "/a/b",
             "",
             "NUL", // Windows specific
         }
         for _, p := range paths {
             isLocal := filepath.IsLocal(p)
             fmt.Printf("路径: %s, 是本地路径: %t\n", p, isLocal)
         }
     }
     ```
   * **假设输入和输出 (通用):**
     ```
     路径: a/b, 是本地路径: true
     路径: ./a, 是本地路径: true
     路径: ../b, 是本地路径: true
     路径: /a/b, 是本地路径: false
     路径: , 是本地路径: false
     ```
   * **假设输入和输出 (Windows):**
     ```
     路径: NUL, 是本地路径: false
     ```

3. **`Join(elem ...string) string`**: 将任意数量的路径元素连接成一个单一的路径，使用操作系统特定的分隔符。

   * **特点：** 空元素会被忽略，结果会被 `Clean` 函数处理。
   * **示例:**
     ```go
     package main

     import (
         "fmt"
         "path/filepath"
         "runtime"
     )

     func main() {
         elements := [][]string{
             {"a", "b", "c"},
             {"a", "", "c"},
             {"/a", "b"},
             {"C:", "foo"}, // Windows
             {"//host", "share", "file"}, // UNC path on Windows
         }
         for _, e := range elements {
             joined := filepath.Join(e...)
             fmt.Printf("元素: %v, 连接后路径: %s\n", e, joined)
         }
     }
     ```
   * **假设输入和输出 (在 Unix 系统上):**
     ```
     元素: [a b c], 连接后路径: a/b/c
     元素: [a  c], 连接后路径: a/c
     元素: [/a b], 连接后路径: /a/b
     元素: [C: foo], 连接后路径: C:/foo
     元素: [//host share file], 连接后路径: //host/share/file
     ```
   * **假设输入和输出 (在 Windows 系统上):**
     ```
     元素: [a b c], 连接后路径: a\b\c
     元素: [a  c], 连接后路径: a\c
     元素: [/a b], 连接后路径: \a\b
     元素: [C: foo], 连接后路径: C:\foo
     元素: [//host share file], 连接后路径: \\host\share\file
     ```

4. **`Split(path string) (dir, file string)`**: 将路径分割成目录和文件名部分。

   * **规则：** 在最后一个分隔符之后分割。如果没有分隔符，则目录为空字符串，文件为整个路径。
   * **示例:**
     ```go
     package main

     import (
         "fmt"
         "path/filepath"
         "runtime"
     )

     func main() {
         paths := []string{
             "/a/b/c",
             "a/b/c",
             "file.txt",
         }
         for _, p := range paths {
             dir, file := filepath.Split(p)
             fmt.Printf("路径: %s, 目录: %s, 文件: %s\n", p, dir, file)
         }
     }
     ```
   * **假设输入和输出 (在 Unix 系统上):**
     ```
     路径: /a/b/c, 目录: /a/b/, 文件: c
     路径: a/b/c, 目录: a/b/, 文件: c
     路径: file.txt, 目录: , 文件: file.txt
     ```
   * **假设输入和输出 (在 Windows 系统上):**
     ```
     路径: \a\b\c, 目录: \a\b\, 文件: c
     路径: a\b\c, 目录: a\b\, 文件: c
     路径: file.txt, 目录: , 文件: file.txt
     ```

5. **`Ext(path string) string`**: 返回路径的文件扩展名。

   * **规则：** 扩展名是从最后一个 `.` 开始到路径结尾的后缀。如果没有 `.`，则返回空字符串。
   * **示例:**
     ```go
     package main

     import (
         "fmt"
         "path/filepath"
         "runtime"
     )

     func main() {
         paths := []string{
             "file.txt",
             "archive.tar.gz",
             "README",
             ".bashrc",
         }
         for _, p := range paths {
             ext := filepath.Ext(p)
             fmt.Printf("路径: %s, 扩展名: %s\n", p, ext)
         }
     }
     ```
   * **假设输入和输出 (通用):**
     ```
     路径: file.txt, 扩展名: .txt
     路径: archive.tar.gz, 扩展名: .gz
     路径: README, 扩展名:
     路径: .bashrc, 扩展名: .bashrc
     ```

6. **`EvalSymlinks(path string) (string, error)`**: 返回解析任何符号链接后的路径名。

   * **功能：** 如果 `path` 包含符号链接，此函数会找到符号链接指向的实际路径。
   * **示例:**
     ```go
     // 需要在文件系统中有符号链接才能有效演示
     // 假设存在一个符号链接 /tmp/mylink 指向 /home/user/myfile.txt
     package main

     import (
         "fmt"
         "os"
         "path/filepath"
     )

     func main() {
         symlinkPath := "/tmp/mylink" // 假设的符号链接路径
         resolvedPath, err := filepath.EvalSymlinks(symlinkPath)
         if err != nil {
             fmt.Println("解析符号链接失败:", err)
             return
         }
         fmt.Printf("符号链接路径: %s, 解析后路径: %s\n", symlinkPath, resolvedPath)
     }
     ```
   * **假设输入和输出 (假设符号链接存在):**
     ```
     符号链接路径: /tmp/mylink, 解析后路径: /home/user/myfile.txt
     ```

7. **`IsAbs(path string) bool`**: 判断路径是否是绝对路径。

   * **示例:**
     ```go
     package main

     import (
         "fmt"
         "path/filepath"
         "runtime"
     )

     func main() {
         paths := []string{
             "/a/b",
             "a/b",
             "C:\\Windows", // Windows
         }
         for _, p := range paths {
             isAbs := filepath.IsAbs(p)
             fmt.Printf("路径: %s, 是绝对路径: %t\n", p, isAbs)
         }
     }
     ```
   * **假设输入和输出 (在 Unix 系统上):**
     ```
     路径: /a/b, 是绝对路径: true
     路径: a/b, 是绝对路径: false
     路径: C:\Windows, 是绝对路径: false
     ```
   * **假设输入和输出 (在 Windows 系统上):**
     ```
     路径: /a/b, 是绝对路径: false
     路径: a/b, 是绝对路径: false
     路径: C:\Windows, 是绝对路径: true
     ```

8. **`Abs(path string) (string, error)`**: 返回路径的绝对路径表示。

   * **功能：** 如果路径不是绝对路径，它会与当前工作目录连接。
   * **示例:**
     ```go
     package main

     import (
         "fmt"
         "os"
         "path/filepath"
     )

     func main() {
         paths := []string{
             "a/b",
             "/tmp/file.txt",
         }
         for _, p := range paths {
             absPath, err := filepath.Abs(p)
             if err != nil {
                 fmt.Println("获取绝对路径失败:", err)
                 continue
             }
             fmt.Printf("路径: %s, 绝对路径: %s\n", p, absPath)
         }
     }
     ```
   * **假设输入和输出 (假设当前工作目录是 `/home/user`):**
     ```
     路径: a/b, 绝对路径: /home/user/a/b
     路径: /tmp/file.txt, 绝对路径: /tmp/file.txt
     ```

9. **`Rel(basepath, targpath string) (string, error)`**: 返回一个相对于 `basepath` 的 `targpath` 相对路径。

   * **功能：** 计算从 `basepath` 到 `targpath` 的相对路径。
   * **示例:**
     ```go
     package main

     import (
         "fmt"
         "path/filepath"
     )

     func main() {
         base := "/a/b"
         targets := []string{
             "/a/b/c/d",
             "/a/x/y",
             "/p/q",
         }
         for _, target := range targets {
             relPath, err := filepath.Rel(base, target)
             if err != nil {
                 fmt.Println("计算相对路径失败:", err)
                 continue
             }
             fmt.Printf("Base: %s, Target: %s, Relative Path: %s\n", base, target, relPath)
         }
     }
     ```
   * **假设输入和输出 (在 Unix 系统上):**
     ```
     Base: /a/b, Target: /a/b/c/d, Relative Path: c/d
     Base: /a/b, Target: /a/x/y, Relative Path: ../x/y
     Base: /a/b, Target: /p/q, Relative Path: ../../p/q
     ```

10. **`Walk(root string, fn WalkFunc) error` 和 `WalkDir(root string, fn fs.WalkDirFunc) error`**: 遍历以 `root` 为根的目录树，并对每个文件或目录调用 `fn`。

    * **`Walk` 使用 `WalkFunc`：** 每次访问文件或目录时都会调用 `os.Lstat`。
    * **`WalkDir` 使用 `fs.WalkDirFunc`：** 效率更高，避免了对每个访问的文件或目录调用 `os.Lstat`。
    * **`WalkFunc` 和 `fs.WalkDirFunc` 的返回值:**
        * `nil`: 继续遍历。
        * `filepath.SkipDir`: 跳过当前目录。
        * `filepath.SkipAll`: 跳过所有剩余的文件和目录。
        * 任何其他非 `nil` 错误：停止遍历并返回错误。

    * **示例:**
      ```go
      package main

      import (
          "fmt"
          "os"
          "path/filepath"
      )

      func main() {
          root := "." // 当前目录
          err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
              if err != nil {
                  fmt.Printf("访问路径 %s 时出错: %v\n", path, err)
                  return nil // 忽略错误并继续
              }
              fmt.Printf("访问了: %s\n", path)
              return nil
          })
          if err != nil {
              fmt.Println("遍历目录时出错:", err)
          }
      }
      ```
    * **命令行参数处理：** `Walk` 和 `WalkDir` 的 `root` 参数通常可以来自命令行参数，用于指定要遍历的起始目录。例如，如果你的 Go 程序名为 `walker`，并且你运行 `go run walker.go /path/to/directory`，那么 `/path/to/directory` 就可以作为 `Walk` 或 `WalkDir` 的 `root` 参数。

11. **`Base(path string) string`**: 返回路径的最后一个元素。

    * **示例:**
      ```go
      package main

      import (
          "fmt"
          "path/filepath"
      )

      func main() {
          paths := []string{
              "/a/b/c",
              "a/b/c",
              "file.txt",
              "/",
              "",
          }
          for _, p := range paths {
              base := filepath.Base(p)
              fmt.Printf("路径: %s, 最后一个元素: %s\n", p, base)
          }
      }
      ```
    * **假设输入和输出 (在 Unix 系统上):**
      ```
      路径: /a/b/c, 最后一个元素: c
      路径: a/b/c, 最后一个元素: c
      路径: file.txt, 最后一个元素: file.txt
      路径: /, 最后一个元素:
      路径: , 最后一个元素: .
      ```

12. **`Dir(path string) string`**: 返回路径中除了最后一个元素以外的所有部分，通常是路径的目录。

    * **示例:**
      ```go
      package main

      import (
          "fmt"
          "path/filepath"
      )

      func main() {
          paths := []string{
              "/a/b/c",
              "a/b/c",
              "file.txt",
              "/",
              "",
          }
          for _, p := range paths {
              dir := filepath.Dir(p)
              fmt.Printf("路径: %s, 目录部分: %s\n", p, dir)
          }
      }
      ```
    * **假设输入和输出 (在 Unix 系统上):**
      ```
      路径: /a/b/c, 目录部分: /a/b
      路径: a/b/c, 目录部分: a/b
      路径: file.txt, 目录部分: .
      路径: /, 目录部分: /
      路径: , 目录部分: .
      ```

13. **`VolumeName(path string) string`**: 返回路径的卷名。

    * **功能：** 在 Windows 上，对于 `C:\foo\bar` 返回 `C:`，对于 `\\host\share\foo` 返回 `\\host\share`。在其他平台上返回空字符串。
    * **示例:**
      ```go
      package main

      import (
          "fmt"
          "path/filepath"
          "runtime"
      )

      func main() {
          paths := []string{
              "C:\\foo\\bar",  // Windows
              "\\\\host\\share\\foo", // Windows UNC
              "/home/user/file", // Unix
          }
          for _, p := range paths {
              volume := filepath.VolumeName(p)
              fmt.Printf("路径: %s, 卷名: %s\n", p, volume)
          }
      }
      ```
    * **假设输入和输出 (在 Windows 系统上):**
      ```
      路径: C:\foo\bar, 卷名: C:
      路径: \\host\share\foo, 卷名: \\host\share
      路径: /home/user/file, 卷名:
      ```
    * **假设输入和输出 (在 Unix 系统上):**
      ```
      路径: C:\foo\bar, 卷名:
      路径: \\host\share\foo, 卷名:
      路径: /home/user/file, 卷名:
      ```

**命令行参数的具体处理:**

`path/filepath` 包本身不直接处理命令行参数。但是，它的功能通常被用于处理从命令行接收的文件路径参数。

例如，一个程序可能接收一个目录路径作为命令行参数，然后使用 `filepath.Walk` 或 `filepath.WalkDir` 遍历该目录。

```go
package main

import (
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Println("用法: go run main.go <目录路径>")
		return
	}

	root := os.Args[1]

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			fmt.Printf("访问路径 %s 时出错: %v\n", path, err)
			return nil
		}
		fmt.Println(path)
		return nil
	})

	if err != nil {
		fmt.Println("遍历目录出错:", err)
	}
}
```

在这个例子中，`os.Args[1]` 获取了命令行提供的目录路径，并将其作为 `filepath.Walk` 的 `root` 参数。

**使用者易犯错的点:**

* **混淆斜杠和反斜杠:**  在编写跨平台程序时，容易忘记 Windows 使用反斜杠 `\` 作为路径分隔符，而 Unix/Linux/macOS 使用斜杠 `/`。应该使用 `filepath.Join` 来安全地组合路径，或者使用 `filepath.Separator` 获取当前系统的分隔符。
    ```go
    // 错误的做法 (可能在 Windows 上出错)
    path := "/a/" + "b" + "/c"

    // 正确的做法
    path := filepath.Join("a", "b", "c")
    ```
* **不理解 `Clean` 的作用:**  可能不清楚 `Clean` 如何处理 `.` 和 `..`，导致在某些情况下得到意外的路径。
    ```go
    path := "a/../b"
    cleanedPath := filepath.Clean(path) // 结果是 "b"
    ```
* **忘记处理 `EvalSymlinks` 的错误:**  当尝试解析不存在的符号链接时，`EvalSymlinks` 会返回错误，应该进行适当的错误处理。
* **假设路径总是以特定分隔符开头或结尾:**  应该使用 `filepath.IsAbs` 来检查路径是否是绝对路径，并根据需要使用 `filepath.Join` 或其他函数来规范化路径。
* **在不同操作系统上硬编码路径:**  例如，在代码中硬编码 `/tmp/file.txt` 在 Windows 上将无法工作。应该使用相对路径或根据需要构建平台相关的路径。

总而言之，`path/filepath` 包是 Go 语言中处理文件路径的关键工具，它提供了丰富的功能来确保路径操作的正确性和跨平台兼容性。理解其各个函数的功能和注意事项对于编写健壮的 Go 程序至关重要。

Prompt: 
```
这是路径为go/src/path/filepath/path.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package filepath implements utility routines for manipulating filename paths
// in a way compatible with the target operating system-defined file paths.
//
// The filepath package uses either forward slashes or backslashes,
// depending on the operating system. To process paths such as URLs
// that always use forward slashes regardless of the operating
// system, see the [path] package.
package filepath

import (
	"errors"
	"internal/bytealg"
	"internal/filepathlite"
	"io/fs"
	"os"
	"slices"
)

const (
	Separator     = os.PathSeparator
	ListSeparator = os.PathListSeparator
)

// Clean returns the shortest path name equivalent to path
// by purely lexical processing. It applies the following rules
// iteratively until no further processing can be done:
//
//  1. Replace multiple [Separator] elements with a single one.
//  2. Eliminate each . path name element (the current directory).
//  3. Eliminate each inner .. path name element (the parent directory)
//     along with the non-.. element that precedes it.
//  4. Eliminate .. elements that begin a rooted path:
//     that is, replace "/.." by "/" at the beginning of a path,
//     assuming Separator is '/'.
//
// The returned path ends in a slash only if it represents a root directory,
// such as "/" on Unix or `C:\` on Windows.
//
// Finally, any occurrences of slash are replaced by Separator.
//
// If the result of this process is an empty string, Clean
// returns the string ".".
//
// On Windows, Clean does not modify the volume name other than to replace
// occurrences of "/" with `\`.
// For example, Clean("//host/share/../x") returns `\\host\share\x`.
//
// See also Rob Pike, “Lexical File Names in Plan 9 or
// Getting Dot-Dot Right,”
// https://9p.io/sys/doc/lexnames.html
func Clean(path string) string {
	return filepathlite.Clean(path)
}

// IsLocal reports whether path, using lexical analysis only, has all of these properties:
//
//   - is within the subtree rooted at the directory in which path is evaluated
//   - is not an absolute path
//   - is not empty
//   - on Windows, is not a reserved name such as "NUL"
//
// If IsLocal(path) returns true, then
// Join(base, path) will always produce a path contained within base and
// Clean(path) will always produce an unrooted path with no ".." path elements.
//
// IsLocal is a purely lexical operation.
// In particular, it does not account for the effect of any symbolic links
// that may exist in the filesystem.
func IsLocal(path string) bool {
	return filepathlite.IsLocal(path)
}

// Localize converts a slash-separated path into an operating system path.
// The input path must be a valid path as reported by [io/fs.ValidPath].
//
// Localize returns an error if the path cannot be represented by the operating system.
// For example, the path a\b is rejected on Windows, on which \ is a separator
// character and cannot be part of a filename.
//
// The path returned by Localize will always be local, as reported by IsLocal.
func Localize(path string) (string, error) {
	return filepathlite.Localize(path)
}

// ToSlash returns the result of replacing each separator character
// in path with a slash ('/') character. Multiple separators are
// replaced by multiple slashes.
func ToSlash(path string) string {
	return filepathlite.ToSlash(path)
}

// FromSlash returns the result of replacing each slash ('/') character
// in path with a separator character. Multiple slashes are replaced
// by multiple separators.
//
// See also the Localize function, which converts a slash-separated path
// as used by the io/fs package to an operating system path.
func FromSlash(path string) string {
	return filepathlite.FromSlash(path)
}

// SplitList splits a list of paths joined by the OS-specific [ListSeparator],
// usually found in PATH or GOPATH environment variables.
// Unlike strings.Split, SplitList returns an empty slice when passed an empty
// string.
func SplitList(path string) []string {
	return splitList(path)
}

// Split splits path immediately following the final [Separator],
// separating it into a directory and file name component.
// If there is no Separator in path, Split returns an empty dir
// and file set to path.
// The returned values have the property that path = dir+file.
func Split(path string) (dir, file string) {
	return filepathlite.Split(path)
}

// Join joins any number of path elements into a single path,
// separating them with an OS specific [Separator]. Empty elements
// are ignored. The result is Cleaned. However, if the argument
// list is empty or all its elements are empty, Join returns
// an empty string.
// On Windows, the result will only be a UNC path if the first
// non-empty element is a UNC path.
func Join(elem ...string) string {
	return join(elem)
}

// Ext returns the file name extension used by path.
// The extension is the suffix beginning at the final dot
// in the final element of path; it is empty if there is
// no dot.
func Ext(path string) string {
	return filepathlite.Ext(path)
}

// EvalSymlinks returns the path name after the evaluation of any symbolic
// links.
// If path is relative the result will be relative to the current directory,
// unless one of the components is an absolute symbolic link.
// EvalSymlinks calls [Clean] on the result.
func EvalSymlinks(path string) (string, error) {
	return evalSymlinks(path)
}

// IsAbs reports whether the path is absolute.
func IsAbs(path string) bool {
	return filepathlite.IsAbs(path)
}

// Abs returns an absolute representation of path.
// If the path is not absolute it will be joined with the current
// working directory to turn it into an absolute path. The absolute
// path name for a given file is not guaranteed to be unique.
// Abs calls [Clean] on the result.
func Abs(path string) (string, error) {
	return abs(path)
}

func unixAbs(path string) (string, error) {
	if IsAbs(path) {
		return Clean(path), nil
	}
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	return Join(wd, path), nil
}

// Rel returns a relative path that is lexically equivalent to targpath when
// joined to basepath with an intervening separator. That is,
// [Join](basepath, Rel(basepath, targpath)) is equivalent to targpath itself.
// On success, the returned path will always be relative to basepath,
// even if basepath and targpath share no elements.
// An error is returned if targpath can't be made relative to basepath or if
// knowing the current working directory would be necessary to compute it.
// Rel calls [Clean] on the result.
func Rel(basepath, targpath string) (string, error) {
	baseVol := VolumeName(basepath)
	targVol := VolumeName(targpath)
	base := Clean(basepath)
	targ := Clean(targpath)
	if sameWord(targ, base) {
		return ".", nil
	}
	base = base[len(baseVol):]
	targ = targ[len(targVol):]
	if base == "." {
		base = ""
	} else if base == "" && filepathlite.VolumeNameLen(baseVol) > 2 /* isUNC */ {
		// Treat any targetpath matching `\\host\share` basepath as absolute path.
		base = string(Separator)
	}

	// Can't use IsAbs - `\a` and `a` are both relative in Windows.
	baseSlashed := len(base) > 0 && base[0] == Separator
	targSlashed := len(targ) > 0 && targ[0] == Separator
	if baseSlashed != targSlashed || !sameWord(baseVol, targVol) {
		return "", errors.New("Rel: can't make " + targpath + " relative to " + basepath)
	}
	// Position base[b0:bi] and targ[t0:ti] at the first differing elements.
	bl := len(base)
	tl := len(targ)
	var b0, bi, t0, ti int
	for {
		for bi < bl && base[bi] != Separator {
			bi++
		}
		for ti < tl && targ[ti] != Separator {
			ti++
		}
		if !sameWord(targ[t0:ti], base[b0:bi]) {
			break
		}
		if bi < bl {
			bi++
		}
		if ti < tl {
			ti++
		}
		b0 = bi
		t0 = ti
	}
	if base[b0:bi] == ".." {
		return "", errors.New("Rel: can't make " + targpath + " relative to " + basepath)
	}
	if b0 != bl {
		// Base elements left. Must go up before going down.
		seps := bytealg.CountString(base[b0:bl], Separator)
		size := 2 + seps*3
		if tl != t0 {
			size += 1 + tl - t0
		}
		buf := make([]byte, size)
		n := copy(buf, "..")
		for i := 0; i < seps; i++ {
			buf[n] = Separator
			copy(buf[n+1:], "..")
			n += 3
		}
		if t0 != tl {
			buf[n] = Separator
			copy(buf[n+1:], targ[t0:])
		}
		return string(buf), nil
	}
	return targ[t0:], nil
}

// SkipDir is used as a return value from [WalkFunc] to indicate that
// the directory named in the call is to be skipped. It is not returned
// as an error by any function.
var SkipDir error = fs.SkipDir

// SkipAll is used as a return value from [WalkFunc] to indicate that
// all remaining files and directories are to be skipped. It is not returned
// as an error by any function.
var SkipAll error = fs.SkipAll

// WalkFunc is the type of the function called by [Walk] to visit each
// file or directory.
//
// The path argument contains the argument to Walk as a prefix.
// That is, if Walk is called with root argument "dir" and finds a file
// named "a" in that directory, the walk function will be called with
// argument "dir/a".
//
// The directory and file are joined with Join, which may clean the
// directory name: if Walk is called with the root argument "x/../dir"
// and finds a file named "a" in that directory, the walk function will
// be called with argument "dir/a", not "x/../dir/a".
//
// The info argument is the fs.FileInfo for the named path.
//
// The error result returned by the function controls how Walk continues.
// If the function returns the special value [SkipDir], Walk skips the
// current directory (path if info.IsDir() is true, otherwise path's
// parent directory). If the function returns the special value [SkipAll],
// Walk skips all remaining files and directories. Otherwise, if the function
// returns a non-nil error, Walk stops entirely and returns that error.
//
// The err argument reports an error related to path, signaling that Walk
// will not walk into that directory. The function can decide how to
// handle that error; as described earlier, returning the error will
// cause Walk to stop walking the entire tree.
//
// Walk calls the function with a non-nil err argument in two cases.
//
// First, if an [os.Lstat] on the root directory or any directory or file
// in the tree fails, Walk calls the function with path set to that
// directory or file's path, info set to nil, and err set to the error
// from os.Lstat.
//
// Second, if a directory's Readdirnames method fails, Walk calls the
// function with path set to the directory's path, info, set to an
// [fs.FileInfo] describing the directory, and err set to the error from
// Readdirnames.
type WalkFunc func(path string, info fs.FileInfo, err error) error

var lstat = os.Lstat // for testing

// walkDir recursively descends path, calling walkDirFn.
func walkDir(path string, d fs.DirEntry, walkDirFn fs.WalkDirFunc) error {
	if err := walkDirFn(path, d, nil); err != nil || !d.IsDir() {
		if err == SkipDir && d.IsDir() {
			// Successfully skipped directory.
			err = nil
		}
		return err
	}

	dirs, err := os.ReadDir(path)
	if err != nil {
		// Second call, to report ReadDir error.
		err = walkDirFn(path, d, err)
		if err != nil {
			if err == SkipDir && d.IsDir() {
				err = nil
			}
			return err
		}
	}

	for _, d1 := range dirs {
		path1 := Join(path, d1.Name())
		if err := walkDir(path1, d1, walkDirFn); err != nil {
			if err == SkipDir {
				break
			}
			return err
		}
	}
	return nil
}

// walk recursively descends path, calling walkFn.
func walk(path string, info fs.FileInfo, walkFn WalkFunc) error {
	if !info.IsDir() {
		return walkFn(path, info, nil)
	}

	names, err := readDirNames(path)
	err1 := walkFn(path, info, err)
	// If err != nil, walk can't walk into this directory.
	// err1 != nil means walkFn want walk to skip this directory or stop walking.
	// Therefore, if one of err and err1 isn't nil, walk will return.
	if err != nil || err1 != nil {
		// The caller's behavior is controlled by the return value, which is decided
		// by walkFn. walkFn may ignore err and return nil.
		// If walkFn returns SkipDir or SkipAll, it will be handled by the caller.
		// So walk should return whatever walkFn returns.
		return err1
	}

	for _, name := range names {
		filename := Join(path, name)
		fileInfo, err := lstat(filename)
		if err != nil {
			if err := walkFn(filename, fileInfo, err); err != nil && err != SkipDir {
				return err
			}
		} else {
			err = walk(filename, fileInfo, walkFn)
			if err != nil {
				if !fileInfo.IsDir() || err != SkipDir {
					return err
				}
			}
		}
	}
	return nil
}

// WalkDir walks the file tree rooted at root, calling fn for each file or
// directory in the tree, including root.
//
// All errors that arise visiting files and directories are filtered by fn:
// see the [fs.WalkDirFunc] documentation for details.
//
// The files are walked in lexical order, which makes the output deterministic
// but requires WalkDir to read an entire directory into memory before proceeding
// to walk that directory.
//
// WalkDir does not follow symbolic links.
//
// WalkDir calls fn with paths that use the separator character appropriate
// for the operating system. This is unlike [io/fs.WalkDir], which always
// uses slash separated paths.
func WalkDir(root string, fn fs.WalkDirFunc) error {
	info, err := os.Lstat(root)
	if err != nil {
		err = fn(root, nil, err)
	} else {
		err = walkDir(root, fs.FileInfoToDirEntry(info), fn)
	}
	if err == SkipDir || err == SkipAll {
		return nil
	}
	return err
}

// Walk walks the file tree rooted at root, calling fn for each file or
// directory in the tree, including root.
//
// All errors that arise visiting files and directories are filtered by fn:
// see the [WalkFunc] documentation for details.
//
// The files are walked in lexical order, which makes the output deterministic
// but requires Walk to read an entire directory into memory before proceeding
// to walk that directory.
//
// Walk does not follow symbolic links.
//
// Walk is less efficient than [WalkDir], introduced in Go 1.16,
// which avoids calling os.Lstat on every visited file or directory.
func Walk(root string, fn WalkFunc) error {
	info, err := os.Lstat(root)
	if err != nil {
		err = fn(root, nil, err)
	} else {
		err = walk(root, info, fn)
	}
	if err == SkipDir || err == SkipAll {
		return nil
	}
	return err
}

// readDirNames reads the directory named by dirname and returns
// a sorted list of directory entry names.
func readDirNames(dirname string) ([]string, error) {
	f, err := os.Open(dirname)
	if err != nil {
		return nil, err
	}
	names, err := f.Readdirnames(-1)
	f.Close()
	if err != nil {
		return nil, err
	}
	slices.Sort(names)
	return names, nil
}

// Base returns the last element of path.
// Trailing path separators are removed before extracting the last element.
// If the path is empty, Base returns ".".
// If the path consists entirely of separators, Base returns a single separator.
func Base(path string) string {
	return filepathlite.Base(path)
}

// Dir returns all but the last element of path, typically the path's directory.
// After dropping the final element, Dir calls [Clean] on the path and trailing
// slashes are removed.
// If the path is empty, Dir returns ".".
// If the path consists entirely of separators, Dir returns a single separator.
// The returned path does not end in a separator unless it is the root directory.
func Dir(path string) string {
	return filepathlite.Dir(path)
}

// VolumeName returns leading volume name.
// Given "C:\foo\bar" it returns "C:" on Windows.
// Given "\\host\share\foo" it returns "\\host\share".
// On other platforms it returns "".
func VolumeName(path string) string {
	return filepathlite.VolumeName(path)
}

"""



```