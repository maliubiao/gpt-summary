Response:
Let's break down the thought process for analyzing the given Go code snippet.

**1. Understanding the Goal:**

The core request is to understand the *functionality* of the provided Go code. Specifically, it's a set of examples within the `os` package's testing framework. This immediately tells us the primary purpose is to demonstrate how to use various functions in the `os` package.

**2. Initial Scan and Grouping:**

The first step is to quickly read through the code and identify individual `func Example...()`. Each of these functions is a self-contained example. We can group them based on the `os` package function they demonstrate. For example:

* `ExampleOpenFile` and `ExampleOpenFile_append` both relate to opening files.
* `ExampleChmod` relates to changing file permissions.
* `ExampleExpand` and `ExampleExpandEnv` relate to environment variable expansion.

This grouping helps in organizing the analysis.

**3. Analyzing Each Example:**

For each `Example...()` function, we need to determine:

* **What `os` function is being demonstrated?**  This is usually evident from the function name within the example.
* **What is the purpose of the example?**  What specific usage scenario is being shown?
* **Are there any specific flags or options being used?** For example, `os.O_RDWR|os.O_CREATE` in `ExampleOpenFile`.
* **What is the expected output?** Look for `// Output:` comments. These are crucial for understanding the intended behavior.
* **Are there any error handling considerations?** Most examples include checks for `err != nil`.

**4. Identifying Go Language Features:**

The examples inherently demonstrate various Go language features, including:

* **Function calls:**  `os.OpenFile`, `os.Chmod`, etc.
* **Error handling:**  `if err != nil` blocks.
* **String manipulation:**  `filepath.Join`.
* **File I/O:** Reading and writing files.
* **Environment variables:** `os.Setenv`, `os.Getenv`, etc.
* **File system operations:** Creating directories, checking file existence, etc.
* **Time manipulation:** `time.Date` in `ExampleChtimes`.
* **Anonymous functions (closures):** The `mapper` function in `ExampleExpand`.
* **Switches:**  The `switch` statement in `ExampleFileMode`.
* **Deferred function calls:** `defer os.RemoveAll(dir)`, `defer f.Close()`.
* **Sync package:** `sync.Once` in `ExampleUserCacheDir`.

**5. Code Example Generation (If Applicable):**

For some functions, providing a separate, simple example can be beneficial for clarity. This is especially true for functions like `os.Expand` where the mapping function is a key part of its functionality. The goal is to create a minimal, runnable example that isolates the specific feature being demonstrated.

**6. Considering Command-Line Arguments:**

While none of the examples *directly* involve parsing command-line arguments using packages like `flag`, some examples *implicitly* interact with the environment, which can be influenced by command-line settings. For instance, the temporary directory used by `MkdirTemp` can be affected by environment variables. It's important to acknowledge this connection, even if the examples don't explicitly demonstrate command-line argument processing.

**7. Identifying Potential Pitfalls:**

This requires thinking about common mistakes developers might make when using the demonstrated functions:

* **Forgetting to close files:**  Hence, the emphasis on `defer f.Close()`.
* **Incorrect file permissions:**  The `Chmod` example highlights this.
* **Not handling errors properly:**  The repeated `if err != nil` blocks emphasize this.
* **Misunderstanding file modes:**  The `ExampleFileMode` clarifies the different file types.
* **Not cleaning up temporary files/directories:**  The use of `defer os.RemoveAll` and `defer os.Remove` addresses this.
* **Assumptions about environment variables:**  Using `LookupEnv` to check for existence is a good practice.

**8. Structuring the Output:**

Finally, organize the analysis clearly and logically. Use headings, bullet points, and code blocks to make the information easy to understand. Address each part of the prompt systematically.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Maybe focus on just listing the functions.
* **Correction:** The prompt asks for *functionality*, which requires more explanation than just the function names. Need to describe what each example *does*.
* **Initial thought:**  Just copy the output from the comments.
* **Correction:**  While the `// Output:` comments are helpful, it's important to *explain* what that output means in the context of the example.
* **Initial thought:**  Only focus on the `os` package functions.
* **Correction:**  The prompt also asks about Go language features, so identify the broader language concepts being illustrated.

By following this structured approach, we can systematically analyze the provided Go code and generate a comprehensive and helpful response.
这段代码是 Go 语言标准库 `os` 包中用于演示各种文件和操作系统相关功能的示例代码。这些示例主要用于文档和测试目的，帮助开发者理解如何使用 `os` 包中的函数。

以下是这段代码中各个示例的功能：

**1. 文件操作：**

* **`ExampleOpenFile()`:** 演示如何打开一个文件，如果文件不存在则创建它，并进行读写操作。
    * **功能：** 打开名为 "notes.txt" 的文件，具有读写权限，如果不存在则创建。设置文件权限为 0644（用户读写，组和其他用户只读）。最后关闭文件。
    * **Go 代码示例：**
      ```go
      package main

      import (
          "log"
          "os"
      )

      func main() {
          f, err := os.OpenFile("my_file.txt", os.O_RDWR|os.O_CREATE, 0666)
          if err != nil {
              log.Fatal(err)
          }
          defer f.Close() // 确保在函数退出时关闭文件

          // 可以对文件进行读写操作
          _, err = f.WriteString("Hello, world!\n")
          if err != nil {
              log.Fatal(err)
          }
      }
      ```
      * **假设输入：** 当前目录下不存在名为 "my_file.txt" 的文件。
      * **输出：**  在当前目录下创建一个名为 "my_file.txt" 的文件，并写入 "Hello, world!\n"。

* **`ExampleOpenFile_append()`:** 演示如何以追加模式打开文件，如果文件不存在则创建它，并写入数据。
    * **功能：** 打开名为 "access.log" 的文件，以追加模式写入，如果不存在则创建。设置文件权限为 0644。向文件中写入 "appended some data\n"。
    * **Go 代码示例：**
      ```go
      package main

      import (
          "log"
          "os"
      )

      func main() {
          f, err := os.OpenFile("log_file.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
          if err != nil {
              log.Fatal(err)
          }
          defer f.Close()

          _, err = f.WriteString("This is a new log entry.\n")
          if err != nil {
              log.Fatal(err)
          }
      }
      ```
      * **假设输入：** 当前目录下可能存在也可能不存在名为 "log_file.log" 的文件。
      * **输出：** 如果文件不存在则创建，如果存在则在文件末尾追加 "This is a new log entry.\n"。

* **`ExampleReadFile()`:** 演示如何读取整个文件的内容。
    * **功能：** 读取名为 "testdata/hello" 的文件的内容，并将内容输出到标准输出。
    * **Go 代码示例：**
      ```go
      package main

      import (
          "fmt"
          "log"
          "os"
      )

      func main() {
          data, err := os.ReadFile("my_data.txt")
          if err != nil {
              log.Fatal(err)
          }
          fmt.Print(string(data))
      }
      ```
      * **假设输入：** 当前目录下存在一个名为 "my_data.txt" 的文件，内容为 "Some data here."。
      * **输出：** `Some data here.`

* **`ExampleWriteFile()`:** 演示如何将数据写入到文件中，如果文件存在则覆盖。
    * **功能：** 将 "Hello, Gophers!" 写入到名为 "testdata/hello" 的文件中，设置文件权限为 0666。
    * **Go 代码示例：**
      ```go
      package main

      import (
          "log"
          "os"
      )

      func main() {
          err := os.WriteFile("output.txt", []byte("New content!"), 0644)
          if err != nil {
              log.Fatal(err)
          }
      }
      ```
      * **假设输入：** 当前目录下可能存在也可能不存在名为 "output.txt" 的文件。
      * **输出：** 创建或覆盖名为 "output.txt" 的文件，并写入 "New content!"。

* **`ExampleCreateTemp()` 和 `ExampleCreateTemp_suffix()`:** 演示如何创建临时文件。
    * **功能：** 创建一个具有指定前缀或后缀的临时文件。
    * **Go 代码示例：**
      ```go
      package main

      import (
          "fmt"
          "log"
          "os"
          "path/filepath"
      )

      func main() {
          tmpFile, err := os.CreateTemp("", "myprefix-*.log")
          if err != nil {
              log.Fatal(err)
          }
          defer os.Remove(tmpFile.Name()) // 清理临时文件

          fmt.Println("临时文件路径:", tmpFile.Name())

          _, err = tmpFile.WriteString("Temporary data")
          if err != nil {
              log.Fatal(err)
          }
          tmpFile.Close()
      }
      ```
      * **假设输入：** 无特定输入。
      * **输出：** 打印出类似 `/tmp/myprefix-123456789.log` 的临时文件路径。

**2. 文件/目录属性操作：**

* **`ExampleChmod()`:** 演示如何修改文件的权限。
    * **功能：** 将名为 "some-filename" 的文件的权限修改为 0644。
    * **Go 代码示例：**
      ```go
      package main

      import (
          "log"
          "os"
      )

      func main() {
          err := os.Chmod("my_script.sh", 0755) // 设置可执行权限
          if err != nil {
              log.Fatal(err)
          }
      }
      ```
      * **假设输入：** 当前目录下存在名为 "my_script.sh" 的文件。
      * **输出：** 将 "my_script.sh" 文件的权限设置为用户可读写执行，组和其他用户可读可执行。

* **`ExampleChtimes()`:** 演示如何修改文件的访问时间和修改时间。
    * **功能：** 将名为 "some-filename" 的文件的访问时间和修改时间设置为指定的 `time.Time` 值。
    * **Go 代码示例：**
      ```go
      package main

      import (
          "log"
          "os"
          "time"
      )

      func main() {
          modTime := time.Now().Add(-time.Hour * 24) // 24小时前
          accTime := time.Now().Add(-time.Hour * 12) // 12小时前
          err := os.Chtimes("my_data.txt", accTime, modTime)
          if err != nil {
              log.Fatal(err)
          }
      }
      ```
      * **假设输入：** 当前目录下存在名为 "my_data.txt" 的文件。
      * **输出：** 修改 "my_data.txt" 文件的访问时间和修改时间。

* **`ExampleFileMode()`:** 演示如何获取文件的模式信息（权限、类型等）。
    * **功能：** 获取名为 "some-filename" 的文件的模式信息，并打印其权限以及判断文件类型（常规文件、目录、符号链接、命名管道）。
    * **Go 代码示例：**
      ```go
      package main

      import (
          "fmt"
          "log"
          "os"
          "io/fs"
      )

      func main() {
          fi, err := os.Stat("my_image.png")
          if err != nil {
              log.Fatal(err)
          }

          fmt.Printf("Permissions: %#o\n", fi.Mode().Perm())
          if fi.Mode().IsRegular() {
              fmt.Println("This is a regular file.")
          }
      }
      ```
      * **假设输入：** 当前目录下存在名为 "my_image.png" 的常规文件。
      * **输出：** 类似 `Permissions: 0o644` 和 `This is a regular file.`。

**3. 目录操作：**

* **`ExampleMkdir()`:** 演示如何创建一个目录。
    * **功能：** 创建名为 "testdir" 的目录，权限为 0750。
    * **Go 代码示例：**
      ```go
      package main

      import (
          "log"
          "os"
      )

      func main() {
          err := os.Mkdir("my_directory", 0777)
          if err != nil && !os.IsExist(err) { // 忽略已存在错误
              log.Fatal(err)
          }
      }
      ```
      * **假设输入：** 当前目录下不存在名为 "my_directory" 的目录。
      * **输出：** 创建名为 "my_directory" 的目录。

* **`ExampleMkdirAll()`:** 演示如何创建多级目录。
    * **功能：** 创建 "test/subdir" 目录结构，权限为 0750。
    * **Go 代码示例：**
      ```go
      package main

      import (
          "log"
          "os"
      )

      func main() {
          err := os.MkdirAll("parent/child/grandchild", 0700)
          if err != nil {
              log.Fatal(err)
          }
      }
      ```
      * **假设输入：** 当前目录下不存在 "parent" 或其子目录。
      * **输出：** 创建 "parent", "parent/child", "parent/child/grandchild" 目录。

* **`ExampleReadDir()`:** 演示如何读取目录中的文件和子目录。
    * **功能：** 读取当前目录下的所有文件和子目录，并打印它们的名称。
    * **Go 代码示例：**
      ```go
      package main

      import (
          "fmt"
          "log"
          "os"
      )

      func main() {
          files, err := os.ReadDir(".")
          if err != nil {
              log.Fatal(err)
          }
          for _, file := range files {
              fmt.Println(file.Name())
          }
      }
      ```
      * **假设输入：** 当前目录下有文件 "file1.txt", "file2.go" 和目录 "subdir"。
      * **输出：** 可能的输出包括 "file1.txt", "file2.go", "subdir" (顺序可能不同)。

* **`ExampleMkdirTemp()` 和 `ExampleMkdirTemp_suffix()`:** 演示如何创建临时目录。
    * **功能：** 创建具有指定前缀或后缀的临时目录。
    * **Go 代码示例：**
      ```go
      package main

      import (
          "fmt"
          "log"
          "os"
          "path/filepath"
      )

      func main() {
          tmpDir, err := os.MkdirTemp("", "myprefix-*")
          if err != nil {
              log.Fatal(err)
          }
          defer os.RemoveAll(tmpDir) // 清理临时目录

          fmt.Println("临时目录路径:", tmpDir)

          // 在临时目录中创建文件
          os.WriteFile(filepath.Join(tmpDir, "tempfile.txt"), []byte("data"), 0644)
      }
      ```
      * **假设输入：** 无特定输入。
      * **输出：** 打印出类似 `/tmp/myprefix-123456789` 的临时目录路径。

**4. 环境变量操作：**

* **`ExampleExpand()`:** 演示如何使用自定义的映射函数扩展字符串中的占位符。
    * **功能：** 使用提供的 `mapper` 函数将字符串中的 "${DAY_PART}" 和 "$NAME" 替换为 "morning" 和 "Gopher"。
    * **Go 代码示例：**  （此示例本身就是 Go 代码，无需额外示例）
      * **假设输入：** 字符串 "Good ${DAY_PART}, $NAME!" 和 `mapper` 函数。
      * **输出：** `Good morning, Gopher!`

* **`ExampleExpandEnv()`:** 演示如何扩展字符串中的环境变量。
    * **功能：** 将字符串中的 "$NAME" 和 "${BURROW}" 替换为相应的环境变量值。
    * **Go 代码示例：** （此示例本身就是 Go 代码，无需额外示例）
      * **假设输入：** 设置环境变量 `NAME="gopher"` 和 `BURROW="/usr/gopher"`。
      * **输出：** `gopher lives in /usr/gopher.`

* **`ExampleLookupEnv()`:** 演示如何安全地查找环境变量，判断环境变量是否存在。
    * **功能：** 查找并打印 "SOME_KEY"、"EMPTY_KEY" 和 "MISSING_KEY" 环境变量的值，如果不存在则打印 "not set"。
    * **Go 代码示例：** （此示例本身就是 Go 代码，无需额外示例）
      * **假设输入：** 设置环境变量 `SOME_KEY="value"` 和 `EMPTY_KEY=""`。
      * **输出：**
        ```
        SOME_KEY=value
        EMPTY_KEY=
        MISSING_KEY not set
        ```

* **`ExampleGetenv()`:** 演示如何获取环境变量的值。
    * **功能：** 获取并打印 "NAME" 和 "BURROW" 环境变量的值。
    * **Go 代码示例：** （此示例本身就是 Go 代码，无需额外示例）
      * **假设输入：** 设置环境变量 `NAME="gopher"` 和 `BURROW="/usr/gopher"`。
      * **输出：** `gopher lives in /usr/gopher.`

* **`ExampleUnsetenv()`:** 演示如何取消设置环境变量。
    * **功能：** 设置环境变量 "TMPDIR" 为 "/my/tmp"，然后使用 `defer` 在函数退出时取消设置。
    * **Go 代码示例：** （此示例本身就是 Go 代码，主要用于演示 `defer` 的用法，实际运行效果可能不易观察到）

**5. 错误处理：**

* **`ExampleErrNotExist()`:** 演示如何判断文件不存在的错误。
    * **功能：** 尝试获取一个不存在的文件的信息，并使用 `errors.Is` 判断是否是 `fs.ErrNotExist` 错误。
    * **Go 代码示例：** （此示例本身就是 Go 代码，无需额外示例）
      * **假设输入：** 当前目录下不存在名为 "a-nonexistent-file" 的文件。
      * **输出：** `file does not exist`

**6. 符号链接：**

* **`ExampleReadlink()`:** 演示如何创建和读取符号链接。
    * **功能：** 创建一个指向 "hello.txt" 的相对符号链接 "hello.link"，然后使用 `Readlink` 读取链接的目标路径。
    * **Go 代码示例：** （此示例本身就是 Go 代码，无需额外示例）
      * **假设输入：** 在临时目录中创建 "hello.txt"。
      * **输出：** `hello.link links to hello.txt`

**7. 用户目录：**

* **`ExampleUserCacheDir()`:** 演示如何获取用户缓存目录。
    * **功能：** 获取用户缓存目录，并演示如何在其中创建和读取缓存文件。
    * **Go 代码示例：** （此示例本身就是 Go 代码，无需额外示例）

* **`ExampleUserConfigDir()`:** 演示如何获取用户配置目录。
    * **功能：** 获取用户配置目录，并演示如何在其中读取和保存配置文件。
    * **Go 代码示例：** （此示例本身就是 Go 代码，无需额外示例）

**推理出的 Go 语言功能实现：**

这段代码主要演示了 `os` 包提供的与文件系统和操作系统交互的各种功能，包括：

* **文件的创建、打开、读取、写入和关闭。**
* **文件权限的修改。**
* **文件访问时间和修改时间的修改。**
* **获取文件和目录的信息（模式、类型等）。**
* **目录的创建和读取。**
* **临时文件和目录的创建。**
* **环境变量的获取、设置、查找和扩展。**
* **错误处理，特别是文件不存在的错误。**
* **符号链接的创建和读取。**
* **用户缓存和配置目录的获取。**

**命令行参数处理：**

这段代码本身主要是示例代码，不直接涉及命令行参数的处理。如果要在实际应用中使用 `os` 包的功能，通常会结合 `flag` 包来处理命令行参数，例如指定要操作的文件名、目录名等。

**使用者易犯错的点：**

* **忘记关闭打开的文件：**  这会导致资源泄漏。应该始终使用 `defer f.Close()` 来确保文件在使用完毕后被关闭。
  ```go
  f, _ := os.Open("myfile.txt")
  // ... 对文件进行操作 ...
  // 忘记 f.Close()
  ```
* **不正确地处理错误：**  `os` 包中的许多函数会返回错误，必须检查并处理这些错误，否则可能会导致程序崩溃或行为异常。
  ```go
  os.Remove("nonexistent_file.txt") // 如果文件不存在会返回错误
  ```
* **对文件权限理解不足：**  不理解文件权限的八进制表示（例如 0644、0777）可能导致设置的权限不符合预期。
* **在临时文件和目录使用完毕后忘记清理：**  这会导致磁盘空间占用过多。应该使用 `defer os.Remove` 或 `defer os.RemoveAll` 来清理临时文件和目录。
* **直接使用硬编码的文件路径：**  应该使用 `path/filepath` 包中的函数来构建跨平台的路径，避免在不同操作系统上出现问题。
* **对环境变量的假设：**  不应该假设某些环境变量总是存在或具有特定的值，应该使用 `os.LookupEnv` 来安全地获取环境变量。

总而言之，这段代码是学习和理解 Go 语言 `os` 包的宝贵资源，它通过简洁的示例展示了各种文件和操作系统相关的功能的使用方法。理解这些示例可以帮助开发者编写出更可靠和高效的 Go 程序。

Prompt: 
```
这是路径为go/src/os/example_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package os_test

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

func ExampleOpenFile() {
	f, err := os.OpenFile("notes.txt", os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		log.Fatal(err)
	}
	if err := f.Close(); err != nil {
		log.Fatal(err)
	}
}

func ExampleOpenFile_append() {
	// If the file doesn't exist, create it, or append to the file
	f, err := os.OpenFile("access.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal(err)
	}
	if _, err := f.Write([]byte("appended some data\n")); err != nil {
		f.Close() // ignore error; Write error takes precedence
		log.Fatal(err)
	}
	if err := f.Close(); err != nil {
		log.Fatal(err)
	}
}

func ExampleChmod() {
	if err := os.Chmod("some-filename", 0644); err != nil {
		log.Fatal(err)
	}
}

func ExampleChtimes() {
	mtime := time.Date(2006, time.February, 1, 3, 4, 5, 0, time.UTC)
	atime := time.Date(2007, time.March, 2, 4, 5, 6, 0, time.UTC)
	if err := os.Chtimes("some-filename", atime, mtime); err != nil {
		log.Fatal(err)
	}
}

func ExampleFileMode() {
	fi, err := os.Lstat("some-filename")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("permissions: %#o\n", fi.Mode().Perm()) // 0o400, 0o777, etc.
	switch mode := fi.Mode(); {
	case mode.IsRegular():
		fmt.Println("regular file")
	case mode.IsDir():
		fmt.Println("directory")
	case mode&fs.ModeSymlink != 0:
		fmt.Println("symbolic link")
	case mode&fs.ModeNamedPipe != 0:
		fmt.Println("named pipe")
	}
}

func ExampleErrNotExist() {
	filename := "a-nonexistent-file"
	if _, err := os.Stat(filename); errors.Is(err, fs.ErrNotExist) {
		fmt.Println("file does not exist")
	}
	// Output:
	// file does not exist
}

func ExampleExpand() {
	mapper := func(placeholderName string) string {
		switch placeholderName {
		case "DAY_PART":
			return "morning"
		case "NAME":
			return "Gopher"
		}

		return ""
	}

	fmt.Println(os.Expand("Good ${DAY_PART}, $NAME!", mapper))

	// Output:
	// Good morning, Gopher!
}

func ExampleExpandEnv() {
	os.Setenv("NAME", "gopher")
	os.Setenv("BURROW", "/usr/gopher")

	fmt.Println(os.ExpandEnv("$NAME lives in ${BURROW}."))

	// Output:
	// gopher lives in /usr/gopher.
}

func ExampleLookupEnv() {
	show := func(key string) {
		val, ok := os.LookupEnv(key)
		if !ok {
			fmt.Printf("%s not set\n", key)
		} else {
			fmt.Printf("%s=%s\n", key, val)
		}
	}

	os.Setenv("SOME_KEY", "value")
	os.Setenv("EMPTY_KEY", "")

	show("SOME_KEY")
	show("EMPTY_KEY")
	show("MISSING_KEY")

	// Output:
	// SOME_KEY=value
	// EMPTY_KEY=
	// MISSING_KEY not set
}

func ExampleGetenv() {
	os.Setenv("NAME", "gopher")
	os.Setenv("BURROW", "/usr/gopher")

	fmt.Printf("%s lives in %s.\n", os.Getenv("NAME"), os.Getenv("BURROW"))

	// Output:
	// gopher lives in /usr/gopher.
}

func ExampleUnsetenv() {
	os.Setenv("TMPDIR", "/my/tmp")
	defer os.Unsetenv("TMPDIR")
}

func ExampleReadDir() {
	files, err := os.ReadDir(".")
	if err != nil {
		log.Fatal(err)
	}

	for _, file := range files {
		fmt.Println(file.Name())
	}
}

func ExampleMkdirTemp() {
	dir, err := os.MkdirTemp("", "example")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(dir) // clean up

	file := filepath.Join(dir, "tmpfile")
	if err := os.WriteFile(file, []byte("content"), 0666); err != nil {
		log.Fatal(err)
	}
}

func ExampleMkdirTemp_suffix() {
	logsDir, err := os.MkdirTemp("", "*-logs")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(logsDir) // clean up

	// Logs can be cleaned out earlier if needed by searching
	// for all directories whose suffix ends in *-logs.
	globPattern := filepath.Join(os.TempDir(), "*-logs")
	matches, err := filepath.Glob(globPattern)
	if err != nil {
		log.Fatalf("Failed to match %q: %v", globPattern, err)
	}

	for _, match := range matches {
		if err := os.RemoveAll(match); err != nil {
			log.Printf("Failed to remove %q: %v", match, err)
		}
	}
}

func ExampleCreateTemp() {
	f, err := os.CreateTemp("", "example")
	if err != nil {
		log.Fatal(err)
	}
	defer os.Remove(f.Name()) // clean up

	if _, err := f.Write([]byte("content")); err != nil {
		log.Fatal(err)
	}
	if err := f.Close(); err != nil {
		log.Fatal(err)
	}
}

func ExampleCreateTemp_suffix() {
	f, err := os.CreateTemp("", "example.*.txt")
	if err != nil {
		log.Fatal(err)
	}
	defer os.Remove(f.Name()) // clean up

	if _, err := f.Write([]byte("content")); err != nil {
		f.Close()
		log.Fatal(err)
	}
	if err := f.Close(); err != nil {
		log.Fatal(err)
	}
}

func ExampleReadFile() {
	data, err := os.ReadFile("testdata/hello")
	if err != nil {
		log.Fatal(err)
	}
	os.Stdout.Write(data)

	// Output:
	// Hello, Gophers!
}

func ExampleWriteFile() {
	err := os.WriteFile("testdata/hello", []byte("Hello, Gophers!"), 0666)
	if err != nil {
		log.Fatal(err)
	}
}

func ExampleMkdir() {
	err := os.Mkdir("testdir", 0750)
	if err != nil && !os.IsExist(err) {
		log.Fatal(err)
	}
	err = os.WriteFile("testdir/testfile.txt", []byte("Hello, Gophers!"), 0660)
	if err != nil {
		log.Fatal(err)
	}
}

func ExampleMkdirAll() {
	err := os.MkdirAll("test/subdir", 0750)
	if err != nil {
		log.Fatal(err)
	}
	err = os.WriteFile("test/subdir/testfile.txt", []byte("Hello, Gophers!"), 0660)
	if err != nil {
		log.Fatal(err)
	}
}

func ExampleReadlink() {
	// First, we create a relative symlink to a file.
	d, err := os.MkdirTemp("", "")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(d)
	targetPath := filepath.Join(d, "hello.txt")
	if err := os.WriteFile(targetPath, []byte("Hello, Gophers!"), 0644); err != nil {
		log.Fatal(err)
	}
	linkPath := filepath.Join(d, "hello.link")
	if err := os.Symlink("hello.txt", filepath.Join(d, "hello.link")); err != nil {
		if errors.Is(err, errors.ErrUnsupported) {
			// Allow the example to run on platforms that do not support symbolic links.
			fmt.Printf("%s links to %s\n", filepath.Base(linkPath), "hello.txt")
			return
		}
		log.Fatal(err)
	}

	// Readlink returns the relative path as passed to os.Symlink.
	dst, err := os.Readlink(linkPath)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s links to %s\n", filepath.Base(linkPath), dst)

	var dstAbs string
	if filepath.IsAbs(dst) {
		dstAbs = dst
	} else {
		// Symlink targets are relative to the directory containing the link.
		dstAbs = filepath.Join(filepath.Dir(linkPath), dst)
	}

	// Check that the target is correct by comparing it with os.Stat
	// on the original target path.
	dstInfo, err := os.Stat(dstAbs)
	if err != nil {
		log.Fatal(err)
	}
	targetInfo, err := os.Stat(targetPath)
	if err != nil {
		log.Fatal(err)
	}
	if !os.SameFile(dstInfo, targetInfo) {
		log.Fatalf("link destination (%s) is not the same file as %s", dstAbs, targetPath)
	}

	// Output:
	// hello.link links to hello.txt
}

func ExampleUserCacheDir() {
	dir, dirErr := os.UserCacheDir()
	if dirErr == nil {
		dir = filepath.Join(dir, "ExampleUserCacheDir")
	}

	getCache := func(name string) ([]byte, error) {
		if dirErr != nil {
			return nil, &os.PathError{Op: "getCache", Path: name, Err: os.ErrNotExist}
		}
		return os.ReadFile(filepath.Join(dir, name))
	}

	var mkdirOnce sync.Once
	putCache := func(name string, b []byte) error {
		if dirErr != nil {
			return &os.PathError{Op: "putCache", Path: name, Err: dirErr}
		}
		mkdirOnce.Do(func() {
			if err := os.MkdirAll(dir, 0700); err != nil {
				log.Printf("can't create user cache dir: %v", err)
			}
		})
		return os.WriteFile(filepath.Join(dir, name), b, 0600)
	}

	// Read and store cached data.
	// …
	_ = getCache
	_ = putCache

	// Output:
}

func ExampleUserConfigDir() {
	dir, dirErr := os.UserConfigDir()

	var (
		configPath string
		origConfig []byte
	)
	if dirErr == nil {
		configPath = filepath.Join(dir, "ExampleUserConfigDir", "example.conf")
		var err error
		origConfig, err = os.ReadFile(configPath)
		if err != nil && !os.IsNotExist(err) {
			// The user has a config file but we couldn't read it.
			// Report the error instead of ignoring their configuration.
			log.Fatal(err)
		}
	}

	// Use and perhaps make changes to the config.
	config := bytes.Clone(origConfig)
	// …

	// Save changes.
	if !bytes.Equal(config, origConfig) {
		if configPath == "" {
			log.Printf("not saving config changes: %v", dirErr)
		} else {
			err := os.MkdirAll(filepath.Dir(configPath), 0700)
			if err == nil {
				err = os.WriteFile(configPath, config, 0600)
			}
			if err != nil {
				log.Printf("error saving config changes: %v", err)
			}
		}
	}

	// Output:
}

"""



```