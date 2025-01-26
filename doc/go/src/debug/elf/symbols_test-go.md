Response:
我的思考过程如下：

1. **理解目标：** 提问者想了解 `go/src/debug/elf/symbols_test.go` 文件的功能，以及它如何测试 Go 语言的 ELF 文件符号表读取功能。

2. **代码结构分析：**
   - 导入了 `io`, `path`, `reflect`, `testing` 包，说明这是一个测试文件。
   - 定义了一个名为 `TestSymbols` 的测试函数，这是 Go 语言测试的标准命名约定。
   - `TestSymbols` 内部定义了一个辅助函数 `do`，用于执行具体的测试逻辑。
   - 定义了两个 `map` 类型的全局变量 `symbolsGolden` 和 `dynamicSymbolsGolden`，它们存储了预期符号表数据。

3. **`TestSymbols` 函数的功能：**
   - 遍历 `symbolsGolden` 和 `dynamicSymbolsGolden` 这两个 map。
   - 对于每个 map 中的键值对（文件名和预期的符号列表），调用 `do` 函数进行测试。
   - `do` 函数接收文件名、预期的符号列表和一个获取符号表的函数作为参数。

4. **`do` 函数的功能：**
   - 根据文件名后缀判断是否为 `.gz` 文件，如果是则先解压缩。
   - 使用 `elf.Open` 或 `elf.NewFile` 打开 ELF 文件。
   - 调用传入的 `getfunc` (即 `(*File).Symbols` 或 `(*File).DynamicSymbols`) 获取符号表。
   - 处理 `ErrNoSymbols` 错误，如果发生则将符号列表置为空。
   - 使用 `reflect.DeepEqual` 比较实际获取的符号列表和预期的符号列表。
   - 遍历获取的符号列表，检查 `HasVersion` 和 `VersionIndex` 字段的一致性。

5. **推断实现的 Go 语言功能：**
   - 通过 `(*File).Symbols` 和 `(*File).DynamicSymbols` 这两个方法名，可以推断出该文件测试的是 `debug/elf` 包中读取 ELF 文件符号表的功能。
   - 具体来说，`Symbols` 方法应该读取常规符号表，而 `DynamicSymbols` 方法应该读取动态符号表。

6. **Go 代码举例说明：**
   - 需要演示如何使用 `elf` 包读取 ELF 文件的符号表。
   - 示例代码应该包含打开 ELF 文件，调用 `Symbols` 和 `DynamicSymbols` 方法，并处理可能的错误。
   - 假设输入一个名为 `executable` 的 ELF 文件。
   - 输出可以是打印符号表的名称。

7. **代码推理（带假设的输入与输出）：**
   - `symbolsGolden` 和 `dynamicSymbolsGolden` 中存储的是预期的符号表数据。
   - `do` 函数会打开指定的文件，调用 `Symbols` 或 `DynamicSymbols`，并将结果与 `symbolsGolden` 或 `dynamicSymbolsGolden` 中对应的数据进行比较。
   - 假设输入文件是 `testdata/gcc-amd64-linux-exec`，调用 `(*File).Symbols`，那么输出应该与 `symbolsGolden["testdata/gcc-amd64-linux-exec"]` 中的数据一致。

8. **命令行参数处理：**
   - 该测试文件本身不处理命令行参数，它依赖 Go 的测试框架。
   - 可以通过 `go test ./debug/elf` 命令来运行测试。
   - 如果想运行特定的测试用例，可以使用 `-run` 参数，例如 `go test -run TestSymbols ./debug/elf`。

9. **使用者易犯错的点：**
   - 主要在于理解 `Symbol` 结构体的各个字段含义，例如 `Name`, `Info`, `Value`, `Size` 等。
   - 另一个易错点是区分静态符号表和动态符号表。

10. **组织答案：**
    - 按照提问的顺序，逐步解释文件的功能、实现的 Go 语言功能、代码示例、代码推理、命令行参数处理和易错点。
    - 使用清晰的中文表达，并使用代码块格式化代码。

通过以上分析，我能够生成最终的答案。核心思路是理解测试代码的目的，分析其结构和逻辑，并结合 `debug/elf` 包的知识来推断其功能和用法。

这个 Go 语言源文件 `go/src/debug/elf/symbols_test.go` 的主要功能是**测试 `debug/elf` 包中解析 ELF (Executable and Linkable Format) 文件符号表的功能**。

具体来说，它测试了以下两个核心功能：

1. **读取 ELF 文件的符号表 (`Symbols` 方法):**  测试了 `elf.File` 类型的 `Symbols` 方法，该方法用于读取 ELF 文件中的常规符号表。

2. **读取 ELF 文件的动态符号表 (`DynamicSymbols` 方法):** 测试了 `elf.File` 类型的 `DynamicSymbols` 方法，该方法用于读取 ELF 文件中的动态符号表。

**它如何实现测试:**

该测试文件使用了 "golden file" 的方法进行测试。它维护了两个 map 类型的全局变量：

* **`symbolsGolden`:**  存储了不同 ELF 文件的路径以及其对应的**预期**的常规符号表数据 (`[]Symbol`)。这些预期数据是通过 `testdata/getgoldsym.c` 程序生成的。
* **`dynamicSymbolsGolden`:** 存储了不同 ELF 文件的路径以及其对应的**预期**的动态符号表数据 (`[]Symbol`)。

`TestSymbols` 函数是主要的测试函数。它的工作流程如下：

1. **遍历 Golden 数据:** 遍历 `symbolsGolden` 和 `dynamicSymbolsGolden` 这两个 map。
2. **执行测试辅助函数 `do`:** 对于每个 map 中的键值对 (文件名和预期的符号列表)，调用 `do` 函数来执行具体的测试。
3. **`do` 函数的核心逻辑:**
   - **打开 ELF 文件:**  根据文件名后缀判断是否为 gzip 压缩的文件 (`.gz`)，并使用 `elf.Open` 或先解压缩再使用 `elf.NewFile` 打开 ELF 文件。
   - **获取符号表:** 调用传入的 `getfunc` 函数来获取符号表。对于 `symbolsGolden`，`getfunc` 是 `(*File).Symbols`；对于 `dynamicSymbolsGolden`，`getfunc` 是 `(*File).DynamicSymbols`。
   - **处理 `ErrNoSymbols`:** 如果获取符号表时返回 `elf.ErrNoSymbols` 错误，则认为该文件没有符号表，将获取到的符号列表置为空。
   - **比较结果:** 使用 `reflect.DeepEqual` 函数将实际获取的符号列表与预期的符号列表进行深度比较。如果两者不一致，则测试失败。
   - **版本信息检查:** 遍历获取到的符号列表，如果符号有版本信息 (`s.HasVersion` 为 true)，则检查其版本索引 (`s.VersionIndex`) 是否为隐藏版本，并验证 `VersionIndex.Index()` 的返回值是否与 `uint16(s.VersionIndex)` 相同。

**Go 语言功能实现举例:**

假设我们想读取一个名为 `my_program` 的 ELF 文件的符号表，可以使用以下 Go 代码：

```go
package main

import (
	"debug/elf"
	"fmt"
	"log"
)

func main() {
	filename := "my_program" // 替换为你的 ELF 文件路径

	f, err := elf.Open(filename)
	if err != nil {
		log.Fatalf("无法打开 ELF 文件: %v", err)
	}
	defer f.Close()

	// 获取常规符号表
	symbols, err := f.Symbols()
	if err != nil && err != elf.ErrNoSymbols {
		log.Fatalf("无法读取符号表: %v", err)
	}

	fmt.Println("常规符号表:")
	for _, s := range symbols {
		fmt.Printf("  Name: %s, Value: 0x%X, Size: %d\n", s.Name, s.Value, s.Size)
	}

	// 获取动态符号表
	dynamicSymbols, err := f.DynamicSymbols()
	if err != nil && err != elf.ErrNoSymbols {
		log.Fatalf("无法读取动态符号表: %v", err)
	}

	fmt.Println("\n动态符号表:")
	for _, s := range dynamicSymbols {
		fmt.Printf("  Name: %s, Value: 0x%X, Size: %d", s.Name, s.Value, s.Size)
		if s.HasVersion {
			fmt.Printf(", Version: %s, Library: %s", s.Version, s.Library)
		}
		fmt.Println()
	}
}
```

**假设的输入与输出:**

假设 `my_program` 是一个简单的可执行文件，它的 `symbolsGolden` 中可能有类似以下的条目（简化）：

```go
var symbolsGolden = map[string][]Symbol{
	"my_program": {
		Symbol{Name: "", Info: 0x3, Other: 0x0, Section: 0x1, Value: 0x1000, Size: 0x0},
		Symbol{Name: "main.main", Info: 0x12, Other: 0x0, Section: 0x5, Value: 0x1050, Size: 0x20},
		Symbol{Name: "fmt.Println", Info: 0x12, Other: 0x0, Section: 0x8, Value: 0x10A0, Size: 0x30},
		// ... 更多符号
	},
}
```

运行上面的 Go 代码，假设 `my_program` 的实际符号表与 `symbolsGolden` 中的预期一致，那么输出可能包含：

```
常规符号表:
  Name: , Value: 0x1000, Size: 0
  Name: main.main, Value: 0x1050, Size: 32
  Name: fmt.Println, Value: 0x10A0, Size: 48
  // ... 更多符号

动态符号表:
  Name: runtime.morestack_noctxt, Value: 0x0, Size: 0, Version: , Library:
  Name: runtime.mallocgc, Value: 0x0, Size: 0, Version: , Library:
  Name: os.Exit, Value: 0x0, Size: 0, Version: , Library:
  // ... 更多动态符号
```

**命令行参数的具体处理:**

该测试文件本身并不处理命令行参数。它是通过 Go 的 `testing` 包来运行的。你可以使用 `go test` 命令来执行测试：

```bash
go test ./debug/elf
```

如果你只想运行 `symbols_test.go` 文件中的测试，可以使用以下命令：

```bash
go test -run TestSymbols ./debug/elf
```

`-run TestSymbols` 参数告诉 `go test` 命令只运行名称匹配 "TestSymbols" 的测试函数。

**使用者易犯错的点:**

一个可能容易犯错的点是**混淆静态符号表和动态符号表**。

* **静态符号表 (通过 `Symbols()` 获取):**  通常包含程序内部定义的函数、变量等符号。这些符号在编译链接时就已经确定。
* **动态符号表 (通过 `DynamicSymbols()` 获取):**  主要包含程序运行时需要动态链接的共享库中的符号。这些符号在程序启动时或运行时才会被解析。

例如，如果你想查找一个标准库函数（比如 `fmt.Println`）的定义地址，它很可能出现在静态符号表中。而如果你想查找一个外部共享库（比如 `libc.so` 中的 `printf`）的地址，它会出现在动态符号表中。

因此，在使用 `debug/elf` 包读取符号表时，需要根据你要查找的符号的性质来选择调用 `Symbols()` 还是 `DynamicSymbols()` 方法。 如果调用了错误的函数，可能就找不到你想要的符号信息。

Prompt: 
```
这是路径为go/src/debug/elf/symbols_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package elf

import (
	"io"
	"path"
	"reflect"
	"testing"
)

// TODO: remove duplicate code
func TestSymbols(t *testing.T) {
	do := func(file string, ts []Symbol, getfunc func(*File) ([]Symbol, error)) {
		var f *File
		var err error
		if path.Ext(file) == ".gz" {
			var r io.ReaderAt
			if r, err = decompress(file); err == nil {
				f, err = NewFile(r)
			}
		} else {
			f, err = Open(file)
		}
		if err != nil {
			t.Errorf("TestSymbols: cannot open file %s: %v", file, err)
			return
		}
		defer f.Close()
		fs, err := getfunc(f)
		if err != nil && err != ErrNoSymbols {
			t.Error(err)
			return
		} else if err == ErrNoSymbols {
			fs = []Symbol{}
		}
		if !reflect.DeepEqual(ts, fs) {
			t.Errorf("%s: Symbols = %v, want %v", file, fs, ts)
		}

		for i, s := range fs {
			if s.HasVersion {
				// No hidden versions here.
				if s.VersionIndex.IsHidden() {
					t.Errorf("%s: symbol %d: unexpected hidden version", file, i)
				}
				if got, want := s.VersionIndex.Index(), uint16(s.VersionIndex); got != want {
					t.Errorf("%s: symbol %d: VersionIndex.Index() == %d, want %d", file, i, got, want)
				}
			}
		}

	}
	for file, ts := range symbolsGolden {
		do(file, ts, (*File).Symbols)
	}
	for file, ts := range dynamicSymbolsGolden {
		do(file, ts, (*File).DynamicSymbols)
	}
}

// golden symbol table data generated by testdata/getgoldsym.c

var symbolsGolden = map[string][]Symbol{
	"testdata/gcc-amd64-linux-exec": {
		Symbol{
			Name:         "",
			Info:         0x3,
			Other:        0x0,
			HasVersion:   false,
			VersionIndex: 0,
			Section:      0x1,
			Value:        0x400200,
			Size:         0x0,
		},
		Symbol{
			Name:         "",
			Info:         0x3,
			Other:        0x0,
			HasVersion:   false,
			VersionIndex: 0,
			Section:      0x2,
			Value:        0x40021C,
			Size:         0x0,
		},
		Symbol{
			Name:         "",
			Info:         0x3,
			Other:        0x0,
			HasVersion:   false,
			VersionIndex: 0,
			Section:      0x3,
			Value:        0x400240,
			Size:         0x0,
		},
		Symbol{
			Name:         "",
			Info:         0x3,
			Other:        0x0,
			HasVersion:   false,
			VersionIndex: 0,
			Section:      0x4,
			Value:        0x400268,
			Size:         0x0,
		},
		Symbol{
			Name:         "",
			Info:         0x3,
			Other:        0x0,
			HasVersion:   false,
			VersionIndex: 0,
			Section:      0x5,
			Value:        0x400288,
			Size:         0x0,
		},
		Symbol{
			Name:         "",
			Info:         0x3,
			Other:        0x0,
			HasVersion:   false,
			VersionIndex: 0,
			Section:      0x6,
			Value:        0x4002E8,
			Size:         0x0,
		},
		Symbol{
			Name:         "",
			Info:         0x3,
			Other:        0x0,
			HasVersion:   false,
			VersionIndex: 0,
			Section:      0x7,
			Value:        0x400326,
			Size:         0x0,
		},
		Symbol{
			Name:         "",
			Info:         0x3,
			Other:        0x0,
			HasVersion:   false,
			VersionIndex: 0,
			Section:      0x8,
			Value:        0x400330,
			Size:         0x0,
		},
		Symbol{
			Name:         "",
			Info:         0x3,
			Other:        0x0,
			HasVersion:   false,
			VersionIndex: 0,
			Section:      0x9,
			Value:        0x400350,
			Size:         0x0,
		},
		Symbol{
			Name:         "",
			Info:         0x3,
			Other:        0x0,
			HasVersion:   false,
			VersionIndex: 0,
			Section:      0xA,
			Value:        0x400368,
			Size:         0x0,
		},
		Symbol{
			Name:         "",
			Info:         0x3,
			Other:        0x0,
			HasVersion:   false,
			VersionIndex: 0,
			Section:      0xB,
			Value:        0x400398,
			Size:         0x0,
		},
		Symbol{
			Name:         "",
			Info:         0x3,
			Other:        0x0,
			HasVersion:   false,
			VersionIndex: 0,
			Section:      0xC,
			Value:        0x4003B0,
			Size:         0x0,
		},
		Symbol{
			Name:         "",
			Info:         0x3,
			Other:        0x0,
			HasVersion:   false,
			VersionIndex: 0,
			Section:      0xD,
			Value:        0x4003E0,
			Size:         0x0,
		},
		Symbol{
			Name:         "",
			Info:         0x3,
			Other:        0x0,
			HasVersion:   false,
			VersionIndex: 0,
			Section:      0xE,
			Value:        0x400594,
			Size:         0x0,
		},
		Symbol{
			Name:         "",
			Info:         0x3,
			Other:        0x0,
			HasVersion:   false,
			VersionIndex: 0,
			Section:      0xF,
			Value:        0x4005A4,
			Size:         0x0,
		},
		Symbol{
			Name:         "",
			Info:         0x3,
			Other:        0x0,
			HasVersion:   false,
			VersionIndex: 0,
			Section:      0x10,
			Value:        0x4005B8,
			Size:         0x0,
		},
		Symbol{
			Name:         "",
			Info:         0x3,
			Other:        0x0,
			HasVersion:   false,
			VersionIndex: 0,
			Section:      0x11,
			Value:        0x4005E0,
			Size:         0x0,
		},
		Symbol{
			Name:         "",
			Info:         0x3,
			Other:        0x0,
			HasVersion:   false,
			VersionIndex: 0,
			Section:      0x12,
			Value:        0x600688,
			Size:         0x0,
		},
		Symbol{
			Name:         "",
			Info:         0x3,
			Other:        0x0,
			HasVersion:   false,
			VersionIndex: 0,
			Section:      0x13,
			Value:        0x600698,
			Size:         0x0,
		},
		Symbol{
			Name:         "",
			Info:         0x3,
			Other:        0x0,
			HasVersion:   false,
			VersionIndex: 0,
			Section:      0x14,
			Value:        0x6006A8,
			Size:         0x0,
		},
		Symbol{
			Name:         "",
			Info:         0x3,
			Other:        0x0,
			HasVersion:   false,
			VersionIndex: 0,
			Section:      0x15,
			Value:        0x6006B0,
			Size:         0x0,
		},
		Symbol{
			Name:         "",
			Info:         0x3,
			Other:        0x0,
			HasVersion:   false,
			VersionIndex: 0,
			Section:      0x16,
			Value:        0x600850,
			Size:         0x0,
		},
		Symbol{
			Name:         "",
			Info:         0x3,
			Other:        0x0,
			HasVersion:   false,
			VersionIndex: 0,
			Section:      0x17,
			Value:        0x600858,
			Size:         0x0,
		},
		Symbol{
			Name:         "",
			Info:         0x3,
			Other:        0x0,
			HasVersion:   false,
			VersionIndex: 0,
			Section:      0x18,
			Value:        0x600880,
			Size:         0x0,
		},
		Symbol{
			Name:         "",
			Info:         0x3,
			Other:        0x0,
			HasVersion:   false,
			VersionIndex: 0,
			Section:      0x19,
			Value:        0x600898,
			Size:         0x0,
		},
		Symbol{
			Name:         "",
			Info:         0x3,
			Other:        0x0,
			HasVersion:   false,
			VersionIndex: 0,
			Section:      0x1A,
			Value:        0x0,
			Size:         0x0,
		},
		Symbol{
			Name:         "",
			Info:         0x3,
			Other:        0x0,
			HasVersion:   false,
			VersionIndex: 0,
			Section:      0x1B,
			Value:        0x0,
			Size:         0x0,
		},
		Symbol{
			Name:         "",
			Info:         0x3,
			Other:        0x0,
			HasVersion:   false,
			VersionIndex: 0,
			Section:      0x1C,
			Value:        0x0,
			Size:         0x0,
		},
		Symbol{
			Name:         "",
			Info:         0x3,
			Other:        0x0,
			HasVersion:   false,
			VersionIndex: 0,
			Section:      0x1D,
			Value:        0x0,
			Size:         0x0,
		},
		Symbol{
			Name:         "",
			Info:         0x3,
			Other:        0x0,
			HasVersion:   false,
			VersionIndex: 0,
			Section:      0x1E,
			Value:        0x0,
			Size:         0x0,
		},
		Symbol{
			Name:         "",
			Info:         0x3,
			Other:        0x0,
			HasVersion:   false,
			VersionIndex: 0,
			Section:      0x1F,
			Value:        0x0,
			Size:         0x0,
		},
		Symbol{
			Name:         "",
			Info:         0x3,
			Other:        0x0,
			HasVersion:   false,
			VersionIndex: 0,
			Section:      0x20,
			Value:        0x0,
			Size:         0x0,
		},
		Symbol{
			Name:         "",
			Info:         0x3,
			Other:        0x0,
			HasVersion:   false,
			VersionIndex: 0,
			Section:      0x21,
			Value:        0x0,
			Size:         0x0,
		},
		Symbol{
			Name:         "init.c",
			Info:         0x4,
			Other:        0x0,
			HasVersion:   false,
			VersionIndex: 0,
			Section:      0xFFF1,
			Value:        0x0,
			Size:         0x0,
		},
		Symbol{
			Name:         "initfini.c",
			Info:         0x4,
			Other:        0x0,
			HasVersion:   false,
			VersionIndex: 0,
			Section:      0xFFF1,
			Value:        0x0,
			Size:         0x0,
		},
		Symbol{
			Name:         "call_gmon_start",
			Info:         0x2,
			Other:        0x0,
			HasVersion:   false,
			VersionIndex: 0,
			Section:      0xD,
			Value:        0x40040C,
			Size:         0x0,
		},
		Symbol{
			Name:         "crtstuff.c",
			Info:         0x4,
			Other:        0x0,
			HasVersion:   false,
			VersionIndex: 0,
			Section:      0xFFF1,
			Value:        0x0,
			Size:         0x0,
		},
		Symbol{
			Name:         "__CTOR_LIST__",
			Info:         0x1,
			Other:        0x0,
			HasVersion:   false,
			VersionIndex: 0,
			Section:      0x12,
			Value:        0x600688,
			Size:         0x0,
		},
		Symbol{
			Name:         "__DTOR_LIST__",
			Info:         0x1,
			Other:        0x0,
			HasVersion:   false,
			VersionIndex: 0,
			Section:      0x13,
			Value:        0x600698,
			Size:         0x0,
		},
		Symbol{
			Name:         "__JCR_LIST__",
			Info:         0x1,
			Other:        0x0,
			HasVersion:   false,
			VersionIndex: 0,
			Section:      0x14,
			Value:        0x6006A8,
			Size:         0x0,
		},
		Symbol{
			Name:         "__do_global_dtors_aux",
			Info:         0x2,
			Other:        0x0,
			HasVersion:   false,
			VersionIndex: 0,
			Section:      0xD,
			Value:        0x400430,
			Size:         0x0,
		},
		Symbol{
			Name:         "completed.6183",
			Info:         0x1,
			Other:        0x0,
			HasVersion:   false,
			VersionIndex: 0,
			Section:      0x19,
			Value:        0x600898,
			Size:         0x1,
		},
		Symbol{
			Name:         "p.6181",
			Info:         0x1,
			Other:        0x0,
			HasVersion:   false,
			VersionIndex: 0,
			Section:      0x18,
			Value:        0x600890,
			Size:         0x0,
		},
		Symbol{
			Name:         "frame_dummy",
			Info:         0x2,
			Other:        0x0,
			HasVersion:   false,
			VersionIndex: 0,
			Section:      0xD,
			Value:        0x400470,
			Size:         0x0,
		},
		Symbol{
			Name:         "crtstuff.c",
			Info:         0x4,
			Other:        0x0,
			HasVersion:   false,
			VersionIndex: 0,
			Section:      0xFFF1,
			Value:        0x0,
			Size:         0x0,
		},
		Symbol{
			Name:         "__CTOR_END__",
			Info:         0x1,
			Other:        0x0,
			HasVersion:   false,
			VersionIndex: 0,
			Section:      0x12,
			Value:        0x600690,
			Size:         0x0,
		},
		Symbol{
			Name:         "__DTOR_END__",
			Info:         0x1,
			Other:        0x0,
			HasVersion:   false,
			VersionIndex: 0,
			Section:      0x13,
			Value:        0x6006A0,
			Size:         0x0,
		},
		Symbol{
			Name:         "__FRAME_END__",
			Info:         0x1,
			Other:        0x0,
			HasVersion:   false,
			VersionIndex: 0,
			Section:      0x11,
			Value:        0x400680,
			Size:         0x0,
		},
		Symbol{
			Name:         "__JCR_END__",
			Info:         0x1,
			Other:        0x0,
			HasVersion:   false,
			VersionIndex: 0,
			Section:      0x14,
			Value:        0x6006A8,
			Size:         0x0,
		},
		Symbol{
			Name:         "__do_global_ctors_aux",
			Info:         0x2,
			Other:        0x0,
			HasVersion:   false,
			VersionIndex: 0,
			Section:      0xD,
			Value:        0x400560,
			Size:         0x0,
		},
		Symbol{
			Name:         "initfini.c",
			Info:         0x4,
			Other:        0x0,
			HasVersion:   false,
			VersionIndex: 0,
			Section:      0xFFF1,
			Value:        0x0,
			Size:         0x0,
		},
		Symbol{
			Name:         "hello.c",
			Info:         0x4,
			Other:        0x0,
			HasVersion:   false,
			VersionIndex: 0,
			Section:      0xFFF1,
			Value:        0x0,
			Size:         0x0,
		},
		Symbol{
			Name:         "_GLOBAL_OFFSET_TABLE_",
			Info:         0x1,
			Other:        0x2,
			HasVersion:   false,
			VersionIndex: 0,
			Section:      0x17,
			Value:        0x600858,
			Size:         0x0,
		},
		Symbol{
			Name:         "__init_array_end",
			Info:         0x0,
			Other:        0x2,
			HasVersion:   false,
			VersionIndex: 0,
			Section:      0x12,
			Value:        0x600684,
			Size:         0x0,
		},
		Symbol{
			Name:         "__init_array_start",
			Info:         0x0,
			Other:        0x2,
			HasVersion:   false,
			VersionIndex: 0,
			Section:      0x12,
			Value:        0x600684,
			Size:         0x0,
		},
		Symbol{
			Name:         "_DYNAMIC",
			Info:         0x1,
			Other:        0x2,
			HasVersion:   false,
			VersionIndex: 0,
			Section:      0x15,
			Value:        0x6006B0,
			Size:         0x0,
		},
		Symbol{
			Name:         "data_start",
			Info:         0x20,
			Other:        0x0,
			HasVersion:   false,
			VersionIndex: 0,
			Section:      0x18,
			Value:        0x600880,
			Size:         0x0,
		},
		Symbol{
			Name:         "__libc_csu_fini",
			Info:         0x12,
			Other:        0x0,
			HasVersion:   false,
			VersionIndex: 0,
			Section:      0xD,
			Value:        0x4004C0,
			Size:         0x2,
		},
		Symbol{
			Name:         "_start",
			Info:         0x12,
			Other:        0x0,
			HasVersion:   false,
			VersionIndex: 0,
			Section:      0xD,
			Value:        0x4003E0,
			Size:         0x0,
		},
		Symbol{
			Name:         "__gmon_start__",
			Info:         0x20,
			Other:        0x0,
			HasVersion:   false,
			VersionIndex: 0,
			Section:      0x0,
			Value:        0x0,
			Size:         0x0,
		},
		Symbol{
			Name:         "_Jv_RegisterClasses",
			Info:         0x20,
			Other:        0x0,
			HasVersion:   false,
			VersionIndex: 0,
			Section:      0x0,
			Value:        0x0,
			Size:         0x0,
		},
		Symbol{
			Name:         "puts@@GLIBC_2.2.5",
			Info:         0x12,
			Other:        0x0,
			HasVersion:   false,
			VersionIndex: 0,
			Section:      0x0,
			Value:        0x0,
			Size:         0x18C,
		},
		Symbol{
			Name:         "_fini",
			Info:         0x12,
			Other:        0x0,
			HasVersion:   false,
			VersionIndex: 0,
			Section:      0xE,
			Value:        0x400594,
			Size:         0x0,
		},
		Symbol{
			Name:         "__libc_start_main@@GLIBC_2.2.5",
			Info:         0x12,
			Other:        0x0,
			HasVersion:   false,
			VersionIndex: 0,
			Section:      0x0,
			Value:        0x0,
			Size:         0x1C2,
		},
		Symbol{
			Name:         "_IO_stdin_used",
			Info:         0x11,
			Other:        0x0,
			HasVersion:   false,
			VersionIndex: 0,
			Section:      0xF,
			Value:        0x4005A4,
			Size:         0x4,
		},
		Symbol{
			Name:         "__data_start",
			Info:         0x10,
			Other:        0x0,
			HasVersion:   false,
			VersionIndex: 0,
			Section:      0x18,
			Value:        0x600880,
			Size:         0x0,
		},
		Symbol{
			Name:         "__dso_handle",
			Info:         0x11,
			Other:        0x2,
			HasVersion:   false,
			VersionIndex: 0,
			Section:      0x18,
			Value:        0x600888,
			Size:         0x0,
		},
		Symbol{
			Name:         "__libc_csu_init",
			Info:         0x12,
			Other:        0x0,
			HasVersion:   false,
			VersionIndex: 0,
			Section:      0xD,
			Value:        0x4004D0,
			Size:         0x89,
		},
		Symbol{
			Name:         "__bss_start",
			Info:         0x10,
			Other:        0x0,
			HasVersion:   false,
			VersionIndex: 0,
			Section:      0xFFF1,
			Value:        0x600898,
			Size:         0x0,
		},
		Symbol{
			Name:         "_end",
			Info:         0x10,
			Other:        0x0,
			HasVersion:   false,
			VersionIndex: 0,
			Section:      0xFFF1,
			Value:        0x6008A0,
			Size:         0x0,
		},
		Symbol{
			Name:         "_edata",
			Info:         0x10,
			Other:        0x0,
			HasVersion:   false,
			VersionIndex: 0,
			Section:      0xFFF1,
			Value:        0x600898,
			Size:         0x0,
		},
		Symbol{
			Name:         "main",
			Info:         0x12,
			Other:        0x0,
			HasVersion:   false,
			VersionIndex: 0,
			Section:      0xD,
			Value:        0x400498,
			Size:         0x1B,
		},
		Symbol{
			Name:         "_init",
			Info:         0x12,
			Other:        0x0,
			HasVersion:   false,
			VersionIndex: 0,
			Section:      0xB,
			Value:        0x400398,
			Size:         0x0,
		},
	},
	"testdata/go-relocation-test-clang-x86.obj": {
		Symbol{
			Name:         "go-relocation-test-clang.c",
			Info:         0x4,
			Other:        0x0,
			HasVersion:   false,
			VersionIndex: 0,
			Section:      0xFFF1,
			Value:        0x0,
			Size:         0x0,
		},
		Symbol{
			Name:         ".Linfo_string0",
			Info:         0x0,
			Other:        0x0,
			HasVersion:   false,
			VersionIndex: 0,
			Section:      0xC,
			Value:        0x0,
			Size:         0x0,
		},
		Symbol{
			Name:         ".Linfo_string1",
			Info:         0x0,
			Other:        0x0,
			HasVersion:   false,
			VersionIndex: 0,
			Section:      0xC,
			Value:        0x2C,
			Size:         0x0,
		},
		Symbol{
			Name:         ".Linfo_string2",
			Info:         0x0,
			Other:        0x0,
			HasVersion:   false,
			VersionIndex: 0,
			Section:      0xC,
			Value:        0x47,
			Size:         0x0,
		},
		Symbol{
			Name:         ".Linfo_string3",
			Info:         0x0,
			Other:        0x0,
			HasVersion:   false,
			VersionIndex: 0,
			Section:      0xC,
			Value:        0x4C,
			Size:         0x0,
		},
		Symbol{
			Name:         ".Linfo_string4",
			Info:         0x0,
			Other:        0x0,
			HasVersion:   false,
			VersionIndex: 0,
			Section:      0xC,
			Value:        0x4E,
			Size:         0x0,
		},
		Symbol{
			Name:         "",
			Info:         0x3,
			Other:        0x0,
			HasVersion:   false,
			VersionIndex: 0,
			Section:      0x1,
			Value:        0x0,
			Size:         0x0,
		},
		Symbol{
			Name:         "",
			Info:         0x3,
			Other:        0x0,
			HasVersion:   false,
			VersionIndex: 0,
			Section:      0x2,
			Value:        0x0,
			Size:         0x0,
		},
		Symbol{
			Name:         "",
			Info:         0x3,
			Other:        0x0,
			HasVersion:   false,
			VersionIndex: 0,
			Section:      0x3,
			Value:        0x0,
			Size:         0x0,
		},
		Symbol{
			Name:         "",
			Info:         0x3,
			Other:        0x0,
			HasVersion:   false,
			VersionIndex: 0,
			Section:      0x4,
			Value:        0x0,
			Size:         0x0,
		},
		Symbol{
			Name:         "",
			Info:         0x3,
			Other:        0x0,
			HasVersion:   false,
			VersionIndex: 0,
			Section:      0x6,
			Value:        0x0,
			Size:         0x0,
		},
		Symbol{
			Name:         "",
			Info:         0x3,
			Other:        0x0,
			HasVersion:   false,
			VersionIndex: 0,
			Section:      0x7,
			Value:        0x0,
			Size:         0x0,
		},
		Symbol{
			Name:         "",
			Info:         0x3,
			Other:        0x0,
			HasVersion:   false,
			VersionIndex: 0,
			Section:      0x8,
			Value:        0x0,
			Size:         0x0,
		},
		Symbol{
			Name:         "",
			Info:         0x3,
			Other:        0x0,
			HasVersion:   false,
			VersionIndex: 0,
			Section:      0xA,
			Value:        0x0,
			Size:         0x0,
		},
		Symbol{
			Name:         "",
			Info:         0x3,
			Other:        0x0,
			HasVersion:   false,
			VersionIndex: 0,
			Section:      0xC,
			Value:        0x0,
			Size:         0x0,
		},
		Symbol{
			Name:         "",
			Info:         0x3,
			Other:        0x0,
			HasVersion:   false,
			VersionIndex: 0,
			Section:      0xD,
			Value:        0x0,
			Size:         0x0,
		},
		Symbol{
			Name:         "",
			Info:         0x3,
			Other:        0x0,
			HasVersion:   false,
			VersionIndex: 0,
			Section:      0xE,
			Value:        0x0,
			Size:         0x0,
		},
		Symbol{
			Name:         "",
			Info:         0x3,
			Other:        0x0,
			HasVersion:   false,
			VersionIndex: 0,
			Section:      0xF,
			Value:        0x0,
			Size:         0x0,
		},
		Symbol{
			Name:         "",
			Info:         0x3,
			Other:        0x0,
			HasVersion:   false,
			VersionIndex: 0,
			Section:      0x10,
			Value:        0x0,
			Size:         0x0,
		},
		Symbol{
			Name:         "v",
			Info:         0x11,
			Other:        0x0,
			HasVersion:   false,
			VersionIndex: 0,
			Section:      0xFFF2,
			Value:        0x4,
			Size:         0x4,
		},
	},
	"testdata/hello-world-core.gz": {},
}

var dynamicSymbolsGolden = map[string][]Symbol{
	"testdata/gcc-amd64-linux-exec": {
		Symbol{
			Name:         "__gmon_start__",
			Info:         0x20,
			Other:        0x0,
			HasVersion:   true,
			VersionIndex: 0x0,
			Section:      0x0,
			Value:        0x0,
			Size:         0x0,
		},
		Symbol{
			Name:         "puts",
			Info:         0x12,
			Other:        0x0,
			HasVersion:   true,
			VersionIndex: 0x2,
			Section:      0x0,
			Value:        0x0,
			Size:         0x18C,
			Version:      "GLIBC_2.2.5",
			Library:      "libc.so.6",
		},
		Symbol{
			Name:         "__libc_start_main",
			Info:         0x12,
			Other:        0x0,
			HasVersion:   true,
			VersionIndex: 0x2,
			Section:      0x0,
			Value:        0x0,
			Size:         0x1C2,
			Version:      "GLIBC_2.2.5",
			Library:      "libc.so.6",
		},
	},
	"testdata/go-relocation-test-clang-x86.obj": {},
	"testdata/hello-world-core.gz":              {},
	"testdata/libtiffxx.so_": {
		Symbol{
			Name:         "_ZNSo3putEc",
			Info:         0x12,
			Other:        0x0,
			HasVersion:   true,
			VersionIndex: 0x3,
			Section:      0x0,
			Value:        0x0,
			Size:         0x0,
			Version:      "GLIBCXX_3.4",
			Library:      "libstdc++.so.6",
		},
		Symbol{
			Name:         "strchr",
			Info:         0x12,
			Other:        0x0,
			HasVersion:   true,
			VersionIndex: 0x4,
			Section:      0x0,
			Value:        0x0,
			Size:         0x0,
			Version:      "GLIBC_2.2.5",
			Library:      "libc.so.6",
		},
		Symbol{
			Name:         "__cxa_finalize",
			Info:         0x22,
			Other:        0x0,
			HasVersion:   true,
			VersionIndex: 0x4,
			Section:      0x0,
			Value:        0x0,
			Size:         0x0,
			Version:      "GLIBC_2.2.5",
			Library:      "libc.so.6",
		},
		Symbol{
			Name:         "_ZNSo5tellpEv",
			Info:         0x12,
			Other:        0x0,
			HasVersion:   true,
			VersionIndex: 0x3,
			Section:      0x0,
			Value:        0x0,
			Size:         0x0,
			Version:      "GLIBCXX_3.4",
			Library:      "libstdc++.so.6",
		},
		Symbol{
			Name:         "_ZNSo5seekpElSt12_Ios_Seekdir",
			Info:         0x12,
			Other:        0x0,
			HasVersion:   true,
			VersionIndex: 0x3,
			Section:      0x0,
			Value:        0x0,
			Size:         0x0,
			Version:      "GLIBCXX_3.4",
			Library:      "libstdc++.so.6",
		},
		Symbol{
			Name:         "_Znwm",
			Info:         0x12,
			Other:        0x0,
			HasVersion:   true,
			VersionIndex: 0x3,
			Section:      0x0,
			Value:        0x0,
			Size:         0x0,
			Version:      "GLIBCXX_3.4",
			Library:      "libstdc++.so.6",
		},
		Symbol{
			Name:         "_ZdlPvm",
			Info:         0x12,
			Other:        0x0,
			HasVersion:   true,
			VersionIndex: 0x5,
			Section:      0x0,
			Value:        0x0,
			Size:         0x0,
			Version:      "CXXABI_1.3.9",
			Library:      "libstdc++.so.6",
		},
		Symbol{
			Name:         "__stack_chk_fail",
			Info:         0x12,
			Other:        0x0,
			HasVersion:   true,
			VersionIndex: 0x6,
			Section:      0x0,
			Value:        0x0,
			Size:         0x0,
			Version:      "GLIBC_2.4",
			Library:      "libc.so.6",
		},
		Symbol{
			Name:         "_ZSt16__ostream_insertIcSt11char_traitsIcEERSt13basic_ostreamIT_T0_ES6_PKS3_l",
			Info:         0x12,
			Other:        0x0,
			HasVersion:   true,
			VersionIndex: 0x7,
			Section:      0x0,
			Value:        0x0,
			Size:         0x0,
			Version:      "GLIBCXX_3.4.9",
			Library:      "libstdc++.so.6",
		},
		Symbol{
			Name:         "_ZNSo5seekpESt4fposI11__mbstate_tE",
			Info:         0x12,
			Other:        0x0,
			HasVersion:   true,
			VersionIndex: 0x3,
			Section:      0x0,
			Value:        0x0,
			Size:         0x0,
			Version:      "GLIBCXX_3.4",
			Library:      "libstdc++.so.6",
		},
		Symbol{
			Name:         "_ZNSi4readEPcl",
			Info:         0x12,
			Other:        0x0,
			HasVersion:   true,
			VersionIndex: 0x3,
			Section:      0x0,
			Value:        0x0,
			Size:         0x0,
			Version:      "GLIBCXX_3.4",
			Library:      "libstdc++.so.6",
		},
		Symbol{
			Name:         "_ZNSi5seekgESt4fposI11__mbstate_tE",
			Info:         0x12,
			Other:        0x0,
			HasVersion:   true,
			VersionIndex: 0x3,
			Section:      0x0,
			Value:        0x0,
			Size:         0x0,
			Version:      "GLIBCXX_3.4",
			Library:      "libstdc++.so.6",
		},
		Symbol{
			Name:         "_ZNSo5writeEPKcl",
			Info:         0x12,
			Other:        0x0,
			HasVersion:   true,
			VersionIndex: 0x3,
			Section:      0x0,
			Value:        0x0,
			Size:         0x0,
			Version:      "GLIBCXX_3.4",
			Library:      "libstdc++.so.6",
		},
		Symbol{
			Name:         "_ZNSi5seekgElSt12_Ios_Seekdir",
			Info:         0x12,
			Other:        0x0,
			HasVersion:   true,
			VersionIndex: 0x3,
			Section:      0x0,
			Value:        0x0,
			Size:         0x0,
			Version:      "GLIBCXX_3.4",
			Library:      "libstdc++.so.6",
		},
		Symbol{
			Name:         "_ZSt21ios_base_library_initv",
			Info:         0x12,
			Other:        0x0,
			HasVersion:   true,
			VersionIndex: 0x8,
			Section:      0x0,
			Value:        0x0,
			Size:         0x0,
			Version:      "GLIBCXX_3.4.32",
			Library:      "libstdc++.so.6",
		},
		Symbol{
			Name:         "TIFFClientOpen",
			Info:         0x12,
			Other:        0x0,
			HasVersion:   true,
			VersionIndex: 0x9,
			Section:      0x0,
			Value:        0x0,
			Size:         0x0,
			Version:      "LIBTIFF_4.0",
			Library:      "libtiff.so.6",
		},
		Symbol{
			Name:         "_ZNSt9basic_iosIcSt11char_traitsIcEE5clearESt12_Ios_Iostate",
			Info:         0x12,
			Other:        0x0,
			HasVersion:   true,
			VersionIndex: 0x3,
			Section:      0x0,
			Value:        0x0,
			Size:         0x0,
			Version:      "GLIBCXX_3.4",
			Library:      "libstdc++.so.6",
		},
		Symbol{
			Name:         "_ZNSi5tellgEv",
			Info:         0x12,
			Other:        0x0,
			HasVersion:   true,
			VersionIndex: 0x3,
			Section:      0x0,
			Value:        0x0,
			Size:         0x0,
			Version:      "GLIBCXX_3.4",
			Library:      "libstdc++.so.6",
		},
		Symbol{
			Name:         "_ITM_deregisterTMCloneTable",
			Info:         0x20,
			Other:        0x0,
			HasVersion:   true,
			VersionIndex: 0x1,
			Section:      0x0,
			Value:        0x0,
			Size:         0x0,
		},
		Symbol{
			Name:         "__gmon_start__",
			Info:         0x20,
			Other:        0x0,
			HasVersion:   true,
			VersionIndex: 0x1,
			Section:      0x0,
			Value:        0x0,
			Size:         0x0,
		},
		Symbol{
			Name:         "_ITM_registerTMCloneTable",
			Info:         0x20,
			Other:        0x0,
			HasVersion:   true,
			VersionIndex: 0x1,
			Section:      0x0,
			Value:        0x0,
			Size:         0x0,
		},
		Symbol{
			Name:         "LIBTIFFXX_4.0",
			Info:         0x11,
			Other:        0x0,
			HasVersion:   true,
			VersionIndex: 0x2,
			Section:      0xFFF1,
			Value:        0x0,
			Size:         0x0,
			Version:      "LIBTIFFXX_4.0",
			Library:      "",
		},
		Symbol{
			Name:         "_Z14TIFFStreamOpenPKcPSo",
			Info:         0x12,
			Other:        0x0,
			HasVersion:   true,
			VersionIndex: 0x2,
			Section:      0xF,
			Value:        0x1860,
			Size:         0xB8,
			Version:      "LIBTIFFXX_4.0",
			Library:      "",
		},
		Symbol{
			Name:         "_Z14TIFFStreamOpenPKcPSi",
			Info:         0x12,
			Other:        0x0,
			HasVersion:   true,
			VersionIndex: 0x2,
			Section:      0xF,
			Value:        0x1920,
			Size:         0x13,
			Version:      "LIBTIFFXX_4.0",
			Library:      "",
		},
	},
}

"""



```