Response:
The user wants to understand the functionality of the provided Go code snippet, which is part of the `cmd/link` package responsible for linking Go programs.

Here's a breakdown of the thought process to analyze the code:

1. **Identify the Core Function:** The code appears to be the final stage of the linking process, taking the linked binary and performing post-processing steps. Keywords like "updateFunc", "dsymutil", "strip", "codesign", and "response file" point to operations happening *after* the main linking.

2. **Break Down Key Sections:**  Divide the code into logical blocks based on the operations being performed. The main function seems to handle several distinct tasks:
    * Updating the output file (potential for rewriting).
    * Handling DWARF debugging information (`combineDwarf`).
    * Rewriting the Mach-O UUID (on macOS).
    * FIPS related actions.
    * Code signing (on macOS).
    * Passing long arguments via response files.
    * Checking linker flag support.
    * Loading object files (`ldobj`).
    * Resolving symbols.
    * Handling host objects.
    * Reading ELF symbol data and notes.
    * Handling shared libraries.
    * Managing sections.
    * Defining internal symbols.
    * Calculating offsets.
    * Determining the entry point.
    * Generating a call graph.
    * Rounding values.
    * Reading bytes.
    * Performing a postorder traversal of libraries.
    * Getting the ELF symbol for a relocation.
    * Adding GOT symbols.
    * Capturing host objects.
    * Finding external linker tools.

3. **Analyze Each Section's Purpose:**
    * **`updateMachoOutFile`:**  This function suggests a mechanism to modify the generated executable, specifically for Mach-O files (macOS). The `updateFunc` argument indicates a callback for the actual modification.
    * **`combineDwarf` block:** This section clearly deals with generating and integrating DWARF debugging information using `dsymutil`. It also removes STAB symbols using `strip`.
    * **UUID Rewriting:**  Specifically for Darwin (macOS), it updates the Mach-O UUID.
    * **FIPS:**  The `hostlinkfips` function suggests handling FIPS compliance.
    * **Code Signing:** `machoCodeSign` indicates code signing for macOS.
    * **`passLongArgsInResponseFile`:** This is an optimization for dealing with a large number of arguments to the external linker, placing them in a file instead of directly on the command line.
    * **`linkerFlagSupported`:** This function tests if the external linker supports a given flag, likely used to determine if response files are viable.
    * **`ldobj`:** This function is responsible for loading object files, identifying their format (Go object, ELF, Mach-O, PE, XCOFF), and processing them accordingly. It distinguishes between Go objects and host objects.
    * **`symbolsAreUnresolved`:** Checks if specific symbols remain unresolved.
    * **`hostObject`:** Loads a single host object file.
    * **`readelfsymboldata`, `readwithpad`, `readnote`:**  Functions for parsing information from ELF files.
    * **`ldshlibsyms`:**  Loads symbols from shared libraries.
    * **`addsection`:**  Adds a section to a segment.
    * **`defineInternal`, `xdefine`:**  Define internal symbols.
    * **`datoff`:** Calculates the offset of an address within a data or text segment.
    * **`Entryvalue`:** Determines the program's entry point.
    * **`callgraph`:** Generates a call graph if the `-C` flag is set.
    * **`Rnd`:** Rounds a value.
    * **`bgetc`:** Reads a single byte.
    * **`postorder`, `dfs`:** Functions for performing a topological sort of libraries to detect import cycles.
    * **`ElfSymForReloc`:** Gets the ELF symbol index for a relocation.
    * **`AddGotSym`:** Adds an entry to the Global Offset Table (GOT).
    * **`captureHostObj`:**  Saves host object files for debugging.
    * **`findExtLinkTool`:**  Locates external tools like `strip` and `dsymutil`.

4. **Infer Go Functionality:** Based on the identified functions, the overall functionality is the final stage of linking, including:
    * **Generating debugging information (DWARF).**
    * **Stripping unnecessary symbols.**
    * **Handling platform-specific requirements (UUID rewriting, code signing on macOS).**
    * **Interacting with external linkers and tools.**
    * **Managing shared libraries.**
    * **Optimizing command-line arguments.**
    * **Loading and processing object files from different formats.**

5. **Provide Go Code Examples (where applicable):** Focus on the more complex or interesting functionalities like `updateMachoOutFile` and `passLongArgsInResponseFile`. For simpler functions, a brief explanation might suffice.

6. **Infer Input and Output (where applicable):**  For functions like `updateMachoOutFile`, the input is the linked executable, and the output is a modified executable. For `passLongArgsInResponseFile`, the input is a long list of arguments, and the output is a modified list with a response file.

7. **Explain Command-Line Parameters:** Focus on parameters that directly influence the functionality within the snippet, like those related to DWARF generation or output file names.

8. **Identify Potential Pitfalls:** Consider common mistakes users might make, such as incorrect usage of flags or misunderstandings about the interaction with external tools.

9. **Summarize Functionality:** Concisely describe the overall purpose of the code snippet in the context of the Go linker.

**Self-Correction/Refinement:** Initially, I might have focused too much on the individual helper functions. It's important to step back and see the bigger picture – the overall flow of the final linking stage. Also, ensuring the Go code examples are relevant and illustrative of the function's purpose is crucial. Double-checking the descriptions of command-line parameters for accuracy and completeness is also important.
这是 `go/src/cmd/link/internal/ld/lib.go` 文件的一部分，它是 Go 链接器（`link` 命令）实现的核心组成部分。这部分代码主要负责链接过程的最后阶段，即在所有对象文件被加载和符号解析完成后，对最终生成的可执行文件进行后处理和优化。

以下是这段代码的主要功能点：

1. **更新 Mach-O 输出文件 (macOS)：**
   - `updateMachoOutFile` 函数提供了一种机制来修改已生成的 Mach-O 格式的可执行文件。它接受一个描述操作的字符串和一个 `updateFunc` 函数作为参数。
   - `updateFunc` 接收链接上下文 (`*Link`)，可执行文件的 `os.File` 和 `macho.File` 表示，以及输出文件名。它执行特定的修改操作，例如合并 DWARF 信息或重写 UUID。
   - 在修改完成后，旧的输出文件会被删除，修改后的文件会被重命名为原始输出文件名。

2. **合并 DWARF 调试信息 (`combineDwarf`):**
   - 如果 `combineDwarf` 为真，则会尝试将 DWARF 调试信息合并到可执行文件中。
   - 它首先使用 `ctxt.findExtLinkTool("dsymutil")` 找到 `dsymutil` 工具的路径，该工具用于生成 DWARF 符号文件。
   - 然后，它使用 `dsymutil` 为输出文件生成一个 DWARF 符号文件 (`go.dwarf`)。
   - 接着，它使用 `ctxt.findExtLinkTool("strip")` 找到 `strip` 工具的路径，并从可执行文件中移除 STAB 符号。移除 STAB 符号是为了提高构建的可重现性，因为它们可能包含临时文件路径。
   - 最后，如果 `dsymutil` 成功生成了 DWARF 文件，它会再次调用 `updateMachoOutFile`，并使用 `machoCombineDwarf` 函数将 DWARF 信息合并到可执行文件中。

3. **重写 Mach-O UUID (macOS)：**
   - 如果在合并 DWARF 后 UUID 没有被更新，并且存在构建信息 (`len(buildinfo) > 0`)，则会调用 `updateMachoOutFile`，并使用 `machoRewriteUuid` 函数来重写可执行文件的 UUID。这通常用于确保可执行文件的唯一性。

4. **处理 FIPS (`hostlinkfips`):**
   - 调用 `hostlinkfips` 函数，传入链接上下文、输出文件名和 FIPS 对象文件路径 (`*flagFipso`)。这部分代码很可能用于处理符合 FIPS 规范的构建。

5. **代码签名 (macOS)：**
   - 如果 `ctxt.NeedCodeSign()` 返回真（通常在 macOS 上），则会调用 `machoCodeSign` 函数对可执行文件进行代码签名。

6. **通过响应文件传递长参数 (`passLongArgsInResponseFile`):**
   - 此函数用于处理传递给外部链接器的参数过长的情况，这可能会超过操作系统的命令行长度限制。
   - 它首先检查所有参数的总长度是否超过了系统限制 (`sys.ExecArgLengthLimit`)。
   - 如果超过限制，它会创建一个临时响应文件，将所有参数写入该文件，然后将对外部链接器的调用修改为使用 `@` 加上响应文件路径。
   - 它还会检查外部链接器是否支持响应文件，通过调用 `linkerFlagSupported` 并传入一个包含响应文件语法的标志 (`@"+response"`) 来实现。

7. **检查链接器标志是否支持 (`linkerFlagSupported`):**
   - 此函数用于测试特定的链接器标志是否被外部链接器支持。
   - 它创建一个简单的 C 源文件 (`trivial.c`) 并尝试使用指定的链接器和标志进行编译。
   - 通过检查编译是否成功以及输出中是否包含 "unrecognized" 或 "unknown" 字符串来判断标志是否被支持。

8. **裁剪链接器参数 (`trimLinkerArgv`):**
   - 此函数用于创建一个新的链接器参数列表，其中排除了某些与测试链接器选项无关的标志。这主要是为 `linkerFlagSupported` 函数提供更精确的测试环境。

9. **获取特定架构的链接器参数 (`hostlinkArchArgs`):**
   - 根据目标架构 (`arch`) 返回传递给外部链接器的特定参数，例如 `-m32` 或 `-m64`。

10. **加载对象文件 (`ldobj`):**
    - 此函数负责加载输入的对象文件。它会检查对象文件的魔数和头部信息来确定文件格式（ELF, Mach-O, PE, XCOFF, Go 对象文件）。
    - 如果是主机对象文件（由非 Go 编译器编译），则会返回 `Hostobj` 指针。
    - 如果是 Go 对象文件，则会加载包信息、符号信息等，并返回 `nil`。
    - 对于无法识别格式的对象文件，会将其标记为未知格式。

11. **检查符号是否未解析 (`symbolsAreUnresolved`):**
    - 扫描加载器中未解析的符号列表，并检查其中是否有与 `want` 列表中名称匹配的符号。

12. **加载主机对象文件 (`hostObject`):**
    - 用于加载单个主机对象文件，例如 `crt?.o`。

13. **检查指纹 (`checkFingerprint`):**
    - 检查导入库的指纹是否与预期的一致，以确保导入和被导入的包具有一致的符号索引视图。

14. **读取 ELF 符号数据 (`readelfsymboldata`):**
    - 从 ELF 文件的指定符号的段中读取数据。

15. **读取带填充的数据 (`readwithpad`):**
    - 从 `io.Reader` 中读取指定大小的数据，并进行填充。

16. **读取 ELF Note (`readnote`):**
    - 从 ELF 文件的 Note 段中读取指定名称和类型的 Note。

17. **查找共享库 (`findshlib`):**
    - 在指定的库目录中查找共享库。

18. **加载共享库符号 (`ldshlibsyms`):**
    - 加载共享库的符号信息，包括 ABI 哈希和依赖关系。

19. **添加段 (`addsection`):**
    - 向段列表中添加一个新的段。

20. **定义内部符号 (`defineInternal`, `xdefine`):**
    - 定义 Go 运行时内部使用的符号。

21. **计算数据偏移 (`datoff`):**
    - 根据地址计算数据在文件中的偏移量。

22. **获取入口地址 (`Entryvalue`):**
    - 获取程序的入口地址，可以从命令行参数或指定的符号中获取。

23. **生成调用图 (`callgraph`):**
    - 如果启用了 `-C` 标志，则生成函数调用图。

24. **四舍五入 (`Rnd`):**
    - 将值 `v` 向上舍入到 `r` 的倍数。

25. **读取字节 (`bgetc`):**
    - 从 `bio.Reader` 中读取一个字节。

26. **后序遍历 (`postorder`, `dfs`):**
    - 对库列表进行后序遍历，用于检测导入循环。

27. **获取用于重定位的 ELF 符号 (`ElfSymForReloc`):**
    - 获取用于重定位的 ELF 符号索引。

28. **添加 GOT 符号 (`AddGotSym`):**
    - 向全局偏移表 (GOT) 中添加符号。

29. **捕获主机对象 (`captureHostObj`):**
    - 将主机对象文件的内容保存到指定目录，用于调试。

30. **查找外部链接工具 (`findExtLinkTool`):**
    - 使用外部链接器 (`CC`) 的 `--print-prog-name` 选项查找指定的工具（如 `strip`, `dsymutil`）的路径。

**推断 Go 语言功能的实现：**

这段代码是 Go 链接器实现的一部分，它负责将编译后的 Go 代码和可能存在的 C/C++ 代码（通过 cgo）链接成最终的可执行文件。它涉及到以下 Go 语言功能的实现：

- **`go build` 过程的链接阶段:**  这段代码是 `go build` 命令在生成可执行文件时的核心环节。
- **与外部链接器交互:** Go 链接器需要与系统底层的链接器（例如 `ld` 或 clang 的链接器）交互，以链接 C/C++ 代码或处理一些平台特定的链接任务。
- **可执行文件格式处理:** 代码处理多种可执行文件格式，包括 ELF (Linux, FreeBSD 等), Mach-O (macOS, iOS), PE (Windows), 和 XCOFF (AIX)。
- **调试信息处理:**  DWARF 调试信息的生成和合并是编译过程中的重要部分，用于支持程序的调试。
- **代码签名 (macOS):**  macOS 系统需要对可执行文件进行代码签名以确保安全性。
- **共享库支持:**  代码支持链接共享库。
- **命令行参数处理:**  代码解析和使用了各种命令行参数来控制链接过程。

**Go 代码示例：**

以下是一个简化的示例，展示了 `updateMachoOutFile` 函数的使用场景，假设 `machoCombineDwarf` 和 `machoRewriteUuid` 是已实现的函数：

```go
// 假设 ctxt 是 *ld.Link 类型的实例， flagOutfile 是输出文件名

import (
	"os"
	"path/filepath"

	"debug/macho"
	"cmd/link/internal/ld"
)

func postProcessExecutable(ctxt *ld.Link, outfile string) error {
	ld.UpdateMachoOutFile(ctxt, "combining dwarf", func(ctxt *ld.Link, exef *os.File, exem *macho.File, outexe string) error {
		// 假设 machoCombineDwarf 实现了合并 DWARF 信息的逻辑
		return machoCombineDwarf(ctxt, exef, exem, "/path/to/go.dwarf", outexe)
	})

	ld.UpdateMachoOutFile(ctxt, "rewriting uuid", func(ctxt *ld.Link, exef *os.File, exem *macho.File, outexe string) error {
		// 假设 machoRewriteUuid 实现了重写 UUID 的逻辑
		return machoRewriteUuid(ctxt, exef, exem, outexe)
	})
	return nil
}

// 假设在链接过程的某个阶段调用此函数
// err := postProcessExecutable(ctxt, *flagOutfile)
// if err != nil {
// 	ld.Exitf("post-processing failed: %v", err)
// }
```

**假设的输入与输出：**

对于 `updateMachoOutFile` 函数：

- **输入:**
    - `ctxt`: 链接上下文，包含链接器的状态信息。
    - `op`: 字符串，描述执行的操作，例如 "combining dwarf"。
    - `updateFunc`: 一个函数，接受 `*ld.Link`, `*os.File`, `*macho.File`, `string` 作为参数，并返回 `error`。
    - `*flagOutfile`: 指向输出文件名的指针，例如 `"myprogram"`.
- **输出:**
    - 如果 `updateFunc` 执行成功，则原始输出文件被替换为修改后的文件。

对于 `passLongArgsInResponseFile` 函数：

- **输入:**
    - `ctxt`: 链接上下文。
    - `argv`: 字符串切片，表示传递给外部链接器的参数，可能很长。
    - `altLinker`: 可选的备用链接器名称。
- **输出:**
    - 如果参数长度超过限制且链接器支持响应文件，则返回一个包含链接器命令和响应文件路径的新的字符串切片。
    - 否则，返回原始的 `argv`。

**命令行参数的具体处理：**

这段代码中涉及的命令行参数主要通过 `flag` 包进行处理（虽然具体的 flag 定义不在提供的代码段中，但可以推断出）。一些关键的命令行参数包括：

- `flagOutfile`: 指定输出文件的名称。
- `flagTmpdir`: 指定临时文件的目录。
- `combineDwarf`: 布尔值，指示是否合并 DWARF 调试信息。
- `flagFipso`:  指定 FIPS 对象文件的路径。
- `flagCaptureHostObjs`: 指定用于捕获主机对象的目录。

`passLongArgsInResponseFile` 函数会检查参数长度，如果超过限制，它会创建一个名为 "response" 的文件在 `flagTmpdir` 指定的目录下，并将参数写入该文件。然后，它将传递给外部链接器的参数列表修改为包含 `@` 加上响应文件路径。

**使用者易犯错的点：**

这段代码主要是链接器的内部实现，普通 Go 开发者通常不会直接操作这些函数。然而，在构建系统或高级构建脚本中，可能会遇到与这些功能相关的错误：

- **依赖外部工具：** 合并 DWARF 信息依赖于 `dsymutil` 和 `strip` 工具，如果这些工具不在系统路径中或版本不兼容，可能会导致链接失败。
- **响应文件支持：**  并非所有的外部链接器都支持响应文件。如果使用了过长的参数，并且目标链接器不支持响应文件，链接过程可能会失败。
- **FIPS 配置：**  正确配置 FIPS 相关的参数和依赖项可能比较复杂，容易出错。

**归纳一下它的功能：**

这段 `lib.go` 的代码片段是 Go 链接器在链接过程的最后阶段执行的关键步骤。它负责对生成的可执行文件进行后处理，包括合并调试信息、移除符号、处理平台特定的需求（如 UUID 重写和代码签名）、以及优化与外部链接器的交互。其核心目标是生成最终可分发和执行的二进制文件，并确保其符合目标平台的规范和要求。

### 提示词
```
这是路径为go/src/cmd/link/internal/ld/lib.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```go
Args[0], err)
		}
		if err := updateFunc(ctxt, exef, exem, rewrittenOutput); err != nil {
			Exitf("%s: %s failed: %v", os.Args[0], op, err)
		}
		os.Remove(*flagOutfile)
		if err := os.Rename(rewrittenOutput, *flagOutfile); err != nil {
			Exitf("%s: %v", os.Args[0], err)
		}
	}

	uuidUpdated := false
	if combineDwarf {
		// Find "dsymutils" and "strip" tools using CC --print-prog-name.
		dsymutilCmd := ctxt.findExtLinkTool("dsymutil")
		stripCmd := ctxt.findExtLinkTool("strip")

		dsym := filepath.Join(*flagTmpdir, "go.dwarf")
		cmd := exec.Command(dsymutilCmd, "-f", *flagOutfile, "-o", dsym)
		// dsymutil may not clean up its temp directory at exit.
		// Set DSYMUTIL_REPRODUCER_PATH to work around. see issue 59026.
		// dsymutil (Apple LLVM version 16.0.0) deletes the directory
		// even if it is not empty. We still need our tmpdir, so give a
		// subdirectory to dsymutil.
		dsymDir := filepath.Join(*flagTmpdir, "dsymutil")
		err := os.MkdirAll(dsymDir, 0777)
		if err != nil {
			Exitf("fail to create temp dir: %v", err)
		}
		cmd.Env = append(os.Environ(), "DSYMUTIL_REPRODUCER_PATH="+dsymDir)
		if ctxt.Debugvlog != 0 {
			ctxt.Logf("host link dsymutil:")
			for _, v := range cmd.Args {
				ctxt.Logf(" %q", v)
			}
			ctxt.Logf("\n")
		}
		if out, err := cmd.CombinedOutput(); err != nil {
			Exitf("%s: running dsymutil failed: %v\n%s\n%s", os.Args[0], err, cmd, out)
		}
		// Remove STAB (symbolic debugging) symbols after we are done with them (by dsymutil).
		// They contain temporary file paths and make the build not reproducible.
		var stripArgs = []string{"-S"}
		if debug_s {
			// We are generating a binary with symbol table suppressed.
			// Suppress local symbols. We need to keep dynamically exported
			// and referenced symbols so the dynamic linker can resolve them.
			stripArgs = append(stripArgs, "-x")
		}
		stripArgs = append(stripArgs, *flagOutfile)
		if ctxt.Debugvlog != 0 {
			ctxt.Logf("host link strip: %q", stripCmd)
			for _, v := range stripArgs {
				ctxt.Logf(" %q", v)
			}
			ctxt.Logf("\n")
		}
		cmd = exec.Command(stripCmd, stripArgs...)
		if out, err := cmd.CombinedOutput(); err != nil {
			Exitf("%s: running strip failed: %v\n%s\n%s", os.Args[0], err, cmd, out)
		}
		// Skip combining if `dsymutil` didn't generate a file. See #11994.
		if _, err := os.Stat(dsym); err == nil {
			updateMachoOutFile("combining dwarf",
				func(ctxt *Link, exef *os.File, exem *macho.File, outexe string) error {
					return machoCombineDwarf(ctxt, exef, exem, dsym, outexe)
				})
			uuidUpdated = true
		}
	}
	if ctxt.IsDarwin() && !uuidUpdated && len(buildinfo) > 0 {
		updateMachoOutFile("rewriting uuid",
			func(ctxt *Link, exef *os.File, exem *macho.File, outexe string) error {
				return machoRewriteUuid(ctxt, exef, exem, outexe)
			})
	}
	hostlinkfips(ctxt, *flagOutfile, *flagFipso)
	if ctxt.NeedCodeSign() {
		err := machoCodeSign(ctxt, *flagOutfile)
		if err != nil {
			Exitf("%s: code signing failed: %v", os.Args[0], err)
		}
	}
}

// passLongArgsInResponseFile writes the arguments into a file if they
// are very long.
func (ctxt *Link) passLongArgsInResponseFile(argv []string, altLinker string) []string {
	c := 0
	for _, arg := range argv {
		c += len(arg)
	}

	if c < sys.ExecArgLengthLimit {
		return argv
	}

	// Only use response files if they are supported.
	response := filepath.Join(*flagTmpdir, "response")
	if err := os.WriteFile(response, nil, 0644); err != nil {
		log.Fatalf("failed while testing response file: %v", err)
	}
	if !linkerFlagSupported(ctxt.Arch, argv[0], altLinker, "@"+response) {
		if ctxt.Debugvlog != 0 {
			ctxt.Logf("not using response file because linker does not support one")
		}
		return argv
	}

	var buf bytes.Buffer
	for _, arg := range argv[1:] {
		// The external linker response file supports quoted strings.
		fmt.Fprintf(&buf, "%q\n", arg)
	}
	if err := os.WriteFile(response, buf.Bytes(), 0644); err != nil {
		log.Fatalf("failed while writing response file: %v", err)
	}
	if ctxt.Debugvlog != 0 {
		ctxt.Logf("response file %s contents:\n%s", response, buf.Bytes())
	}
	return []string{
		argv[0],
		"@" + response,
	}
}

var createTrivialCOnce sync.Once

func linkerFlagSupported(arch *sys.Arch, linker, altLinker, flag string) bool {
	createTrivialCOnce.Do(func() {
		src := filepath.Join(*flagTmpdir, "trivial.c")
		if err := os.WriteFile(src, []byte("int main() { return 0; }"), 0666); err != nil {
			Errorf("WriteFile trivial.c failed: %v", err)
		}
	})

	flags := hostlinkArchArgs(arch)

	moreFlags := trimLinkerArgv(append(ldflag, flagExtldflags...))
	flags = append(flags, moreFlags...)

	if altLinker != "" {
		flags = append(flags, "-fuse-ld="+altLinker)
	}
	trivialPath := filepath.Join(*flagTmpdir, "trivial.c")
	outPath := filepath.Join(*flagTmpdir, "a.out")
	flags = append(flags, "-o", outPath, flag, trivialPath)

	cmd := exec.Command(linker, flags...)
	cmd.Env = append([]string{"LC_ALL=C"}, os.Environ()...)
	out, err := cmd.CombinedOutput()
	// GCC says "unrecognized command line option ‘-no-pie’"
	// clang says "unknown argument: '-no-pie'"
	return err == nil && !bytes.Contains(out, []byte("unrecognized")) && !bytes.Contains(out, []byte("unknown"))
}

// trimLinkerArgv returns a new copy of argv that does not include flags
// that are not relevant for testing whether some linker option works.
func trimLinkerArgv(argv []string) []string {
	flagsWithNextArgSkip := []string{
		"-F",
		"-l",
		"-L",
		"-framework",
		"-Wl,-framework",
		"-Wl,-rpath",
		"-Wl,-undefined",
	}
	flagsWithNextArgKeep := []string{
		"-arch",
		"-isysroot",
		"--sysroot",
		"-target",
	}
	prefixesToKeep := []string{
		"-f",
		"-m",
		"-p",
		"-Wl,",
		"-arch",
		"-isysroot",
		"--sysroot",
		"-target",
	}

	var flags []string
	keep := false
	skip := false
	for _, f := range argv {
		if keep {
			flags = append(flags, f)
			keep = false
		} else if skip {
			skip = false
		} else if f == "" || f[0] != '-' {
		} else if slices.Contains(flagsWithNextArgSkip, f) {
			skip = true
		} else if slices.Contains(flagsWithNextArgKeep, f) {
			flags = append(flags, f)
			keep = true
		} else {
			for _, p := range prefixesToKeep {
				if strings.HasPrefix(f, p) {
					flags = append(flags, f)
					break
				}
			}
		}
	}
	return flags
}

// hostlinkArchArgs returns arguments to pass to the external linker
// based on the architecture.
func hostlinkArchArgs(arch *sys.Arch) []string {
	switch arch.Family {
	case sys.I386:
		return []string{"-m32"}
	case sys.AMD64:
		if buildcfg.GOOS == "darwin" {
			return []string{"-arch", "x86_64", "-m64"}
		}
		return []string{"-m64"}
	case sys.S390X:
		return []string{"-m64"}
	case sys.ARM:
		return []string{"-marm"}
	case sys.ARM64:
		if buildcfg.GOOS == "darwin" {
			return []string{"-arch", "arm64"}
		}
	case sys.Loong64:
		return []string{"-mabi=lp64d"}
	case sys.MIPS64:
		return []string{"-mabi=64"}
	case sys.MIPS:
		return []string{"-mabi=32"}
	case sys.PPC64:
		if buildcfg.GOOS == "aix" {
			return []string{"-maix64"}
		} else {
			return []string{"-m64"}
		}

	}
	return nil
}

var wantHdr = objabi.HeaderString()

// ldobj loads an input object. If it is a host object (an object
// compiled by a non-Go compiler) it returns the Hostobj pointer. If
// it is a Go object, it returns nil.
func ldobj(ctxt *Link, f *bio.Reader, lib *sym.Library, length int64, pn string, file string) *Hostobj {
	pkg := objabi.PathToPrefix(lib.Pkg)

	eof := f.Offset() + length
	start := f.Offset()
	c1 := bgetc(f)
	c2 := bgetc(f)
	c3 := bgetc(f)
	c4 := bgetc(f)
	f.MustSeek(start, 0)

	unit := &sym.CompilationUnit{Lib: lib}
	lib.Units = append(lib.Units, unit)

	magic := uint32(c1)<<24 | uint32(c2)<<16 | uint32(c3)<<8 | uint32(c4)
	if magic == 0x7f454c46 { // \x7F E L F
		ldelf := func(ctxt *Link, f *bio.Reader, pkg string, length int64, pn string) {
			textp, flags, err := loadelf.Load(ctxt.loader, ctxt.Arch, ctxt.IncVersion(), f, pkg, length, pn, ehdr.Flags)
			if err != nil {
				Errorf("%v", err)
				return
			}
			ehdr.Flags = flags
			ctxt.Textp = append(ctxt.Textp, textp...)
		}
		return ldhostobj(ldelf, ctxt.HeadType, f, pkg, length, pn, file)
	}

	if magic&^1 == 0xfeedface || magic&^0x01000000 == 0xcefaedfe {
		ldmacho := func(ctxt *Link, f *bio.Reader, pkg string, length int64, pn string) {
			textp, err := loadmacho.Load(ctxt.loader, ctxt.Arch, ctxt.IncVersion(), f, pkg, length, pn)
			if err != nil {
				Errorf("%v", err)
				return
			}
			ctxt.Textp = append(ctxt.Textp, textp...)
		}
		return ldhostobj(ldmacho, ctxt.HeadType, f, pkg, length, pn, file)
	}

	switch c1<<8 | c2 {
	case 0x4c01, // 386
		0x6486, // amd64
		0xc401, // arm
		0x64aa: // arm64
		ldpe := func(ctxt *Link, f *bio.Reader, pkg string, length int64, pn string) {
			ls, err := loadpe.Load(ctxt.loader, ctxt.Arch, ctxt.IncVersion(), f, pkg, length, pn)
			if err != nil {
				Errorf("%v", err)
				return
			}
			if len(ls.Resources) != 0 {
				setpersrc(ctxt, ls.Resources)
			}
			if ls.PData != 0 {
				sehp.pdata = append(sehp.pdata, ls.PData)
			}
			if ls.XData != 0 {
				sehp.xdata = append(sehp.xdata, ls.XData)
			}
			ctxt.Textp = append(ctxt.Textp, ls.Textp...)
		}
		return ldhostobj(ldpe, ctxt.HeadType, f, pkg, length, pn, file)
	}

	if c1 == 0x01 && (c2 == 0xD7 || c2 == 0xF7) {
		ldxcoff := func(ctxt *Link, f *bio.Reader, pkg string, length int64, pn string) {
			textp, err := loadxcoff.Load(ctxt.loader, ctxt.Arch, ctxt.IncVersion(), f, pkg, length, pn)
			if err != nil {
				Errorf("%v", err)
				return
			}
			ctxt.Textp = append(ctxt.Textp, textp...)
		}
		return ldhostobj(ldxcoff, ctxt.HeadType, f, pkg, length, pn, file)
	}

	if c1 != 'g' || c2 != 'o' || c3 != ' ' || c4 != 'o' {
		// An unrecognized object is just passed to the external linker.
		// If we try to read symbols from this object, we will
		// report an error at that time.
		unknownObjFormat = true
		return ldhostobj(nil, ctxt.HeadType, f, pkg, length, pn, file)
	}

	/* check the header */
	line, err := f.ReadString('\n')
	if err != nil {
		Errorf("truncated object file: %s: %v", pn, err)
		return nil
	}

	if !strings.HasPrefix(line, "go object ") {
		if strings.HasSuffix(pn, ".go") {
			Exitf("%s: uncompiled .go source file", pn)
			return nil
		}

		if line == ctxt.Arch.Name {
			// old header format: just $GOOS
			Errorf("%s: stale object file", pn)
			return nil
		}

		Errorf("%s: not an object file: @%d %q", pn, start, line)
		return nil
	}

	// First, check that the basic GOOS, GOARCH, and Version match.
	if line != wantHdr {
		Errorf("%s: linked object header mismatch:\nhave %q\nwant %q\n", pn, line, wantHdr)
	}

	// Skip over exports and other info -- ends with \n!\n.
	//
	// Note: It's possible for "\n!\n" to appear within the binary
	// package export data format. To avoid truncating the package
	// definition prematurely (issue 21703), we keep track of
	// how many "$$" delimiters we've seen.

	import0 := f.Offset()

	c1 = '\n' // the last line ended in \n
	c2 = bgetc(f)
	c3 = bgetc(f)
	markers := 0
	for {
		if c1 == '\n' {
			if markers%2 == 0 && c2 == '!' && c3 == '\n' {
				break
			}
			if c2 == '$' && c3 == '$' {
				markers++
			}
		}

		c1 = c2
		c2 = c3
		c3 = bgetc(f)
		if c3 == -1 {
			Errorf("truncated object file: %s", pn)
			return nil
		}
	}

	import1 := f.Offset()

	f.MustSeek(import0, 0)
	ldpkg(ctxt, f, lib, import1-import0-2, pn) // -2 for !\n
	f.MustSeek(import1, 0)

	fingerprint := ctxt.loader.Preload(ctxt.IncVersion(), f, lib, unit, eof-f.Offset())
	if !fingerprint.IsZero() { // Assembly objects don't have fingerprints. Ignore them.
		// Check fingerprint, to ensure the importing and imported packages
		// have consistent view of symbol indices.
		// Normally the go command should ensure this. But in case something
		// goes wrong, it could lead to obscure bugs like run-time crash.
		// Check it here to be sure.
		if lib.Fingerprint.IsZero() { // Not yet imported. Update its fingerprint.
			lib.Fingerprint = fingerprint
		}
		checkFingerprint(lib, fingerprint, lib.Srcref, lib.Fingerprint)
	}

	addImports(ctxt, lib, pn)
	return nil
}

// symbolsAreUnresolved scans through the loader's list of unresolved
// symbols and checks to see whether any of them match the names of the
// symbols in 'want'. Return value is a list of bools, with list[K] set
// to true if there is an unresolved reference to the symbol in want[K].
func symbolsAreUnresolved(ctxt *Link, want []string) []bool {
	returnAllUndefs := -1
	undefs, _ := ctxt.loader.UndefinedRelocTargets(returnAllUndefs)
	seen := make(map[loader.Sym]struct{})
	rval := make([]bool, len(want))
	wantm := make(map[string]int)
	for k, w := range want {
		wantm[w] = k
	}
	count := 0
	for _, s := range undefs {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		if k, ok := wantm[ctxt.loader.SymName(s)]; ok {
			rval[k] = true
			count++
			if count == len(want) {
				return rval
			}
		}
	}
	return rval
}

// hostObject reads a single host object file (compare to "hostArchive").
// This is used as part of internal linking when we need to pull in
// files such as "crt?.o".
func hostObject(ctxt *Link, objname string, path string) {
	if ctxt.Debugvlog > 1 {
		ctxt.Logf("hostObject(%s)\n", path)
	}
	objlib := sym.Library{
		Pkg: objname,
	}
	f, err := bio.Open(path)
	if err != nil {
		Exitf("cannot open host object %q file %s: %v", objname, path, err)
	}
	defer f.Close()
	h := ldobj(ctxt, f, &objlib, 0, path, path)
	if h.ld == nil {
		Exitf("unrecognized object file format in %s", path)
	}
	h.file = path
	h.length = f.MustSeek(0, 2)
	f.MustSeek(h.off, 0)
	h.ld(ctxt, f, h.pkg, h.length, h.pn)
	if *flagCaptureHostObjs != "" {
		captureHostObj(h)
	}
}

func checkFingerprint(lib *sym.Library, libfp goobj.FingerprintType, src string, srcfp goobj.FingerprintType) {
	if libfp != srcfp {
		Exitf("fingerprint mismatch: %s has %x, import from %s expecting %x", lib, libfp, src, srcfp)
	}
}

func readelfsymboldata(ctxt *Link, f *elf.File, sym *elf.Symbol) []byte {
	data := make([]byte, sym.Size)
	sect := f.Sections[sym.Section]
	if sect.Type != elf.SHT_PROGBITS && sect.Type != elf.SHT_NOTE {
		Errorf("reading %s from non-data section", sym.Name)
	}
	n, err := sect.ReadAt(data, int64(sym.Value-sect.Addr))
	if uint64(n) != sym.Size {
		Errorf("reading contents of %s: %v", sym.Name, err)
	}
	return data
}

func readwithpad(r io.Reader, sz int32) ([]byte, error) {
	data := make([]byte, Rnd(int64(sz), 4))
	_, err := io.ReadFull(r, data)
	if err != nil {
		return nil, err
	}
	data = data[:sz]
	return data, nil
}

func readnote(f *elf.File, name []byte, typ int32) ([]byte, error) {
	for _, sect := range f.Sections {
		if sect.Type != elf.SHT_NOTE {
			continue
		}
		r := sect.Open()
		for {
			var namesize, descsize, noteType int32
			err := binary.Read(r, f.ByteOrder, &namesize)
			if err != nil {
				if err == io.EOF {
					break
				}
				return nil, fmt.Errorf("read namesize failed: %v", err)
			}
			err = binary.Read(r, f.ByteOrder, &descsize)
			if err != nil {
				return nil, fmt.Errorf("read descsize failed: %v", err)
			}
			err = binary.Read(r, f.ByteOrder, &noteType)
			if err != nil {
				return nil, fmt.Errorf("read type failed: %v", err)
			}
			noteName, err := readwithpad(r, namesize)
			if err != nil {
				return nil, fmt.Errorf("read name failed: %v", err)
			}
			desc, err := readwithpad(r, descsize)
			if err != nil {
				return nil, fmt.Errorf("read desc failed: %v", err)
			}
			if string(name) == string(noteName) && typ == noteType {
				return desc, nil
			}
		}
	}
	return nil, nil
}

func findshlib(ctxt *Link, shlib string) string {
	if filepath.IsAbs(shlib) {
		return shlib
	}
	for _, libdir := range ctxt.Libdir {
		libpath := filepath.Join(libdir, shlib)
		if _, err := os.Stat(libpath); err == nil {
			return libpath
		}
	}
	Errorf("cannot find shared library: %s", shlib)
	return ""
}

func ldshlibsyms(ctxt *Link, shlib string) {
	var libpath string
	if filepath.IsAbs(shlib) {
		libpath = shlib
		shlib = filepath.Base(shlib)
	} else {
		libpath = findshlib(ctxt, shlib)
		if libpath == "" {
			return
		}
	}
	for _, processedlib := range ctxt.Shlibs {
		if processedlib.Path == libpath {
			return
		}
	}
	if ctxt.Debugvlog > 1 {
		ctxt.Logf("ldshlibsyms: found library with name %s at %s\n", shlib, libpath)
	}

	f, err := elf.Open(libpath)
	if err != nil {
		Errorf("cannot open shared library: %s", libpath)
		return
	}
	// Keep the file open as decodetypeGcprog needs to read from it.
	// TODO: fix. Maybe mmap the file.
	//defer f.Close()

	hash, err := readnote(f, ELF_NOTE_GO_NAME, ELF_NOTE_GOABIHASH_TAG)
	if err != nil {
		Errorf("cannot read ABI hash from shared library %s: %v", libpath, err)
		return
	}

	depsbytes, err := readnote(f, ELF_NOTE_GO_NAME, ELF_NOTE_GODEPS_TAG)
	if err != nil {
		Errorf("cannot read dep list from shared library %s: %v", libpath, err)
		return
	}
	var deps []string
	for _, dep := range strings.Split(string(depsbytes), "\n") {
		if dep == "" {
			continue
		}
		if !filepath.IsAbs(dep) {
			// If the dep can be interpreted as a path relative to the shlib
			// in which it was found, do that. Otherwise, we will leave it
			// to be resolved by libdir lookup.
			abs := filepath.Join(filepath.Dir(libpath), dep)
			if _, err := os.Stat(abs); err == nil {
				dep = abs
			}
		}
		deps = append(deps, dep)
	}

	syms, err := f.DynamicSymbols()
	if err != nil {
		Errorf("cannot read symbols from shared library: %s", libpath)
		return
	}

	symAddr := map[string]uint64{}
	for _, elfsym := range syms {
		if elf.ST_TYPE(elfsym.Info) == elf.STT_NOTYPE || elf.ST_TYPE(elfsym.Info) == elf.STT_SECTION {
			continue
		}

		// Symbols whose names start with "type:" are compiler generated,
		// so make functions with that prefix internal.
		ver := 0
		symname := elfsym.Name // (unmangled) symbol name
		if elf.ST_TYPE(elfsym.Info) == elf.STT_FUNC && strings.HasPrefix(elfsym.Name, "type:") {
			ver = abiInternalVer
		} else if buildcfg.Experiment.RegabiWrappers && elf.ST_TYPE(elfsym.Info) == elf.STT_FUNC {
			// Demangle the ABI name. Keep in sync with symtab.go:mangleABIName.
			if strings.HasSuffix(elfsym.Name, ".abiinternal") {
				ver = sym.SymVerABIInternal
				symname = strings.TrimSuffix(elfsym.Name, ".abiinternal")
			} else if strings.HasSuffix(elfsym.Name, ".abi0") {
				ver = 0
				symname = strings.TrimSuffix(elfsym.Name, ".abi0")
			}
		}

		l := ctxt.loader
		s := l.LookupOrCreateSym(symname, ver)

		// Because loadlib above loads all .a files before loading
		// any shared libraries, any non-dynimport symbols we find
		// that duplicate symbols already loaded should be ignored
		// (the symbols from the .a files "win").
		if l.SymType(s) != 0 && l.SymType(s) != sym.SDYNIMPORT {
			continue
		}
		su := l.MakeSymbolUpdater(s)
		su.SetType(sym.SDYNIMPORT)
		l.SetSymElfType(s, elf.ST_TYPE(elfsym.Info))
		su.SetSize(int64(elfsym.Size))
		if elfsym.Section != elf.SHN_UNDEF {
			// Set .File for the library that actually defines the symbol.
			l.SetSymPkg(s, libpath)

			// The decodetype_* functions in decodetype.go need access to
			// the type data.
			sname := l.SymName(s)
			if strings.HasPrefix(sname, "type:") && !strings.HasPrefix(sname, "type:.") {
				su.SetData(readelfsymboldata(ctxt, f, &elfsym))
			}
		}

		if symname != elfsym.Name {
			l.SetSymExtname(s, elfsym.Name)
		}
		symAddr[elfsym.Name] = elfsym.Value
	}

	// Load relocations.
	// We only really need these for grokking the links between type descriptors
	// when dynamic linking.
	relocTarget := map[uint64]string{}
	addends := false
	sect := f.SectionByType(elf.SHT_REL)
	if sect == nil {
		sect = f.SectionByType(elf.SHT_RELA)
		if sect == nil {
			log.Fatalf("can't find SHT_REL or SHT_RELA section of %s", shlib)
		}
		addends = true
	}
	// TODO: Multiple SHT_RELA/SHT_REL sections?
	data, err := sect.Data()
	if err != nil {
		log.Fatalf("can't read relocation section of %s: %v", shlib, err)
	}
	bo := f.ByteOrder
	for len(data) > 0 {
		var off, idx uint64
		var addend int64
		switch f.Class {
		case elf.ELFCLASS64:
			off = bo.Uint64(data)
			info := bo.Uint64(data[8:])
			data = data[16:]
			if addends {
				addend = int64(bo.Uint64(data))
				data = data[8:]
			}

			idx = info >> 32
			typ := info & 0xffff
			// buildmode=shared is only supported for amd64,arm64,loong64,s390x,ppc64le.
			// (List found by looking at the translation of R_ADDR by ../$ARCH/asm.go:elfreloc1)
			switch typ {
			case uint64(elf.R_X86_64_64):
			case uint64(elf.R_AARCH64_ABS64):
			case uint64(elf.R_LARCH_64):
			case uint64(elf.R_390_64):
			case uint64(elf.R_PPC64_ADDR64):
			default:
				continue
			}
		case elf.ELFCLASS32:
			off = uint64(bo.Uint32(data))
			info := bo.Uint32(data[4:])
			data = data[8:]
			if addends {
				addend = int64(int32(bo.Uint32(data)))
				data = data[4:]
			}

			idx = uint64(info >> 8)
			typ := info & 0xff
			// buildmode=shared is only supported for 386,arm.
			switch typ {
			case uint32(elf.R_386_32):
			case uint32(elf.R_ARM_ABS32):
			default:
				continue
			}
		default:
			log.Fatalf("unknown bit size %s", f.Class)
		}
		if addend != 0 {
			continue
		}
		relocTarget[off] = syms[idx-1].Name
	}

	ctxt.Shlibs = append(ctxt.Shlibs, Shlib{Path: libpath, Hash: hash, Deps: deps, File: f, symAddr: symAddr, relocTarget: relocTarget})
}

func addsection(ldr *loader.Loader, arch *sys.Arch, seg *sym.Segment, name string, rwx int) *sym.Section {
	sect := ldr.NewSection()
	sect.Rwx = uint8(rwx)
	sect.Name = name
	sect.Seg = seg
	sect.Align = int32(arch.PtrSize) // everything is at least pointer-aligned
	seg.Sections = append(seg.Sections, sect)
	return sect
}

func usage() {
	fmt.Fprintf(os.Stderr, "usage: link [options] main.o\n")
	objabi.Flagprint(os.Stderr)
	Exit(2)
}

type SymbolType int8 // TODO: after genasmsym is gone, maybe rename to plan9typeChar or something

const (
	// see also https://9p.io/magic/man2html/1/nm
	TextSym      SymbolType = 'T'
	DataSym      SymbolType = 'D'
	BSSSym       SymbolType = 'B'
	UndefinedSym SymbolType = 'U'
	TLSSym       SymbolType = 't'
	FrameSym     SymbolType = 'm'
	ParamSym     SymbolType = 'p'
	AutoSym      SymbolType = 'a'

	// Deleted auto (not a real sym, just placeholder for type)
	DeletedAutoSym = 'x'
)

// defineInternal defines a symbol used internally by the go runtime.
func (ctxt *Link) defineInternal(p string, t sym.SymKind) loader.Sym {
	s := ctxt.loader.CreateSymForUpdate(p, 0)
	s.SetType(t)
	s.SetSpecial(true)
	s.SetLocal(true)
	return s.Sym()
}

func (ctxt *Link) xdefine(p string, t sym.SymKind, v int64) loader.Sym {
	s := ctxt.defineInternal(p, t)
	ctxt.loader.SetSymValue(s, v)
	return s
}

func datoff(ldr *loader.Loader, s loader.Sym, addr int64) int64 {
	if uint64(addr) >= Segdata.Vaddr {
		return int64(uint64(addr) - Segdata.Vaddr + Segdata.Fileoff)
	}
	if uint64(addr) >= Segtext.Vaddr {
		return int64(uint64(addr) - Segtext.Vaddr + Segtext.Fileoff)
	}
	ldr.Errorf(s, "invalid datoff %#x", addr)
	return 0
}

func Entryvalue(ctxt *Link) int64 {
	a := *flagEntrySymbol
	if a[0] >= '0' && a[0] <= '9' {
		return atolwhex(a)
	}
	ldr := ctxt.loader
	s := ldr.Lookup(a, 0)
	if s == 0 {
		Errorf("missing entry symbol %q", a)
		return 0
	}
	st := ldr.SymType(s)
	if st == 0 {
		return *FlagTextAddr
	}
	if !ctxt.IsAIX() && !st.IsText() {
		ldr.Errorf(s, "entry not text")
	}
	return ldr.SymValue(s)
}

func (ctxt *Link) callgraph() {
	if !*FlagC {
		return
	}

	ldr := ctxt.loader
	for _, s := range ctxt.Textp {
		relocs := ldr.Relocs(s)
		for i := 0; i < relocs.Count(); i++ {
			r := relocs.At(i)
			rs := r.Sym()
			if rs == 0 {
				continue
			}
			if r.Type().IsDirectCall() && ldr.SymType(rs).IsText() {
				ctxt.Logf("%s calls %s\n", ldr.SymName(s), ldr.SymName(rs))
			}
		}
	}
}

func Rnd(v int64, r int64) int64 {
	if r <= 0 {
		return v
	}
	v += r - 1
	c := v % r
	if c < 0 {
		c += r
	}
	v -= c
	return v
}

func bgetc(r *bio.Reader) int {
	c, err := r.ReadByte()
	if err != nil {
		if err != io.EOF {
			log.Fatalf("reading input: %v", err)
		}
		return -1
	}
	return int(c)
}

type markKind uint8 // for postorder traversal
const (
	_ markKind = iota
	visiting
	visited
)

func postorder(libs []*sym.Library) []*sym.Library {
	order := make([]*sym.Library, 0, len(libs)) // hold the result
	mark := make(map[*sym.Library]markKind, len(libs))
	for _, lib := range libs {
		dfs(lib, mark, &order)
	}
	return order
}

func dfs(lib *sym.Library, mark map[*sym.Library]markKind, order *[]*sym.Library) {
	if mark[lib] == visited {
		return
	}
	if mark[lib] == visiting {
		panic("found import cycle while visiting " + lib.Pkg)
	}
	mark[lib] = visiting
	for _, i := range lib.Imports {
		dfs(i, mark, order)
	}
	mark[lib] = visited
	*order = append(*order, lib)
}

func ElfSymForReloc(ctxt *Link, s loader.Sym) int32 {
	// If putelfsym created a local version of this symbol, use that in all
	// relocations.
	les := ctxt.loader.SymLocalElfSym(s)
	if les != 0 {
		return les
	} else {
		return ctxt.loader.SymElfSym(s)
	}
}

func AddGotSym(target *Target, ldr *loader.Loader, syms *ArchSyms, s loader.Sym, elfRelocTyp uint32) {
	if ldr.SymGot(s) >= 0 {
		return
	}

	Adddynsym(ldr, target, syms, s)
	got := ldr.MakeSymbolUpdater(syms.GOT)
	ldr.SetGot(s, int32(got.Size()))
	got.AddUint(target.Arch, 0)

	if target.IsElf() {
		if target.Arch.PtrSize == 8 {
			rela := ldr.MakeSymbolUpdater(syms.Rela)
			rela.AddAddrPlus(target.Arch, got.Sym(), int64(ldr.SymGot(s)))
			rela.AddUint64(target.Arch, elf.R_INFO(uint32(ldr.SymDynid(s)), elfRelocTyp))
			rela.AddUint64(target.Arch, 0)
		} else {
			rel := ldr.MakeSymbolUpdater(syms.Rel)
			rel.AddAddrPlus(target.Arch, got.Sym(), int64(ldr.SymGot(s)))
			rel.AddUint32(target.Arch, elf.R_INFO32(uint32(ldr.SymDynid(s)), elfRelocTyp))
		}
	} else if target.IsDarwin() {
		leg := ldr.MakeSymbolUpdater(syms.LinkEditGOT)
		leg.AddUint32(target.Arch, uint32(ldr.SymDynid(s)))
		if target.IsPIE() && target.IsInternal() {
			// Mach-O relocations are a royal pain to lay out.
			// They use a compact stateful bytecode representation.
			// Here we record what are needed and encode them later.
			MachoAddBind(int64(ldr.SymGot(s)), s)
		}
	} else {
		ldr.Errorf(s, "addgotsym: unsupported binary format")
	}
}

var hostobjcounter int

// captureHostObj writes out the content of a host object (pulled from
// an archive or loaded from a *.o file directly) to a directory
// specified via the linker's "-capturehostobjs" debugging flag. This
// is intended to make it easier for a developer to inspect the actual
// object feeding into "CGO internal" link step.
func captureHostObj(h *Hostobj) {
	// Form paths for info file and obj file.
	ofile := fmt.Sprintf("captured-obj-%d.o", hostobjcounter)
	ifile := fmt.Sprintf("captured-obj-%d.txt", hostobjcounter)
	hostobjcounter++
	opath := filepath.Join(*flagCaptureHostObjs, ofile)
	ipath := filepath.Join(*flagCaptureHostObjs, ifile)

	// Write the info file.
	info := fmt.Sprintf("pkg: %s\npn: %s\nfile: %s\noff: %d\nlen: %d\n",
		h.pkg, h.pn, h.file, h.off, h.length)
	if err := os.WriteFile(ipath, []byte(info), 0666); err != nil {
		log.Fatalf("error writing captured host obj info %s: %v", ipath, err)
	}

	readObjData := func() []byte {
		inf, err := os.Open(h.file)
		if err != nil {
			log.Fatalf("capturing host obj: open failed on %s: %v", h.pn, err)
		}
		defer inf.Close()
		res := make([]byte, h.length)
		if n, err := inf.ReadAt(res, h.off); err != nil || n != int(h.length) {
			log.Fatalf("capturing host obj: readat failed on %s: %v", h.pn, err)
		}
		return res
	}

	// Write the object file.
	if err := os.WriteFile(opath, readObjData(), 0666); err != nil {
		log.Fatalf("error writing captured host object %s: %v", opath, err)
	}

	fmt.Fprintf(os.Stderr, "link: info: captured host object %s to %s\n",
		h.file, opath)
}

// findExtLinkTool invokes the external linker CC with --print-prog-name
// passing the name of the tool we're interested in, such as "strip",
// "ar", or "dsymutil", and returns the path passed back from the command.
func (ctxt *Link) findExtLinkTool(toolname string) string {
	var cc []string
	cc = append(cc, ctxt.extld()...)
	cc = append(cc, hostlinkArchArgs(ctxt.Arch)...)
	cc = append(cc, "--print-prog-name", toolname)
	out, err := exec.Command(cc[0], cc[1:]...).CombinedOutput()
	if err != nil {
		Exitf("%s: finding %s failed: %v\n%s", os.Args[0], toolname, err, out)
	}
	cmdpath := strings.TrimRight(string(out), "\r\n")
	return cmdpath
}
```