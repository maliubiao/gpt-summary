Response:
The user wants a summary of the functionality of the provided Go code snippet, which is part of the Go linker. Since this is the last part of a three-part series, I need to synthesize the information from the previous parts to create a complete summary.

**Part 1 likely covered:**
- Core linking process, including loading object files (`ldobj`), handling Go object files, and potentially host objects.
- Setup and initialization of the linker context (`Link` struct).
- Handling of command-line flags related to input files and output paths.

**Part 2 likely covered:**
- Symbol resolution and management.
- Handling of different object file formats (ELF, Mach-O, PE, XCOFF).
- Generation of output sections and segments.

**This Part 3 focuses on:**
- Post-processing of the linked output.
- Interaction with external tools like `dsymutil` and `strip`.
- Handling of response files for long argument lists.
- Support for shared libraries.
- Utility functions related to file operations and symbol manipulation.

**Plan for the summary:**
1. Summarize the main actions in this specific code block, focusing on post-processing.
2. Connect these actions to the overall linking process.
3. Mention the role of external tools and how this code interacts with them.
4. Briefly discuss the response file mechanism.
5. Summarize the shared library loading functionality.
6. Include key data structures and functions mentioned in this part.
这是Go语言链接器 `cmd/link` 的一部分，主要负责链接过程的**最后阶段**，对已经生成的可执行文件进行各种**后处理**和**优化**。

**功能归纳：**

这部分代码主要负责以下功能：

1. **可执行文件的最终化处理:**  对链接生成的可执行文件进行一系列操作，使其成为最终可部署的版本。

2. **DWARF 调试信息的处理 (如果 `combineDwarf` 为真):**
   - **生成 DWARF 文件:** 使用 `dsymutil` 工具从可执行文件中提取调试信息，生成独立的 DWARF 文件（通常用于 macOS）。
   - **移除 STAB 符号:** 调用 `strip` 工具移除可执行文件中的 STAB 符号，这些符号包含临时文件路径，影响构建的可重现性。
   - **合并 DWARF 信息:**  如果 `dsymutil` 成功生成了 DWARF 文件，调用 `machoCombineDwarf` 将 DWARF 信息合并回可执行文件 (针对 Mach-O 格式)。

3. **更新 Mach-O 文件的 UUID (如果适用):** 如果是 Darwin 系统且 DWARF 信息未更新，则调用 `machoRewriteUuid` 更新可执行文件中的 UUID。

4. **FIPS 合规性处理:** 调用 `hostlinkfips` 函数执行与 FIPS (Federal Information Processing Standard) 合规性相关的处理。

5. **代码签名 (如果 `ctxt.NeedCodeSign()` 为真):**  如果需要进行代码签名，则调用 `machoCodeSign` 对可执行文件进行签名 (针对 macOS)。

6. **处理过长的命令行参数:**  `passLongArgsInResponseFile` 函数用于处理外部链接器命令行参数过长的情况。它会将参数写入一个 response 文件，然后将 response 文件的路径作为参数传递给链接器。

7. **判断链接器是否支持特定 Flag:** `linkerFlagSupported` 函数通过编译一个简单的 C 程序来测试外部链接器是否支持特定的 flag。

8. **修剪链接器参数列表:** `trimLinkerArgv` 函数用于移除与测试链接器选项无关的参数。

9. **获取主机链接器的架构相关参数:** `hostlinkArchArgs` 函数根据目标架构返回传递给外部链接器的参数（例如 `-m32`，`-m64` 等）。

10. **加载目标文件 (`ldobj`):**  `ldobj` 函数负责加载输入的目标文件。它可以处理 Go 编译产生的对象文件以及主机编译器（如 GCC 或 clang）编译产生的对象文件。对于主机对象文件，会根据其文件头（magic number）判断其类型（ELF, Mach-O, PE, XCOFF），并调用相应的加载函数（`ldelf`, `ldmacho`, `ldpe`, `ldxcoff`）。对于 Go 对象文件，它会检查文件头、导入信息，并加载符号信息。

11. **检查未解析符号:** `symbolsAreUnresolved` 函数检查是否存在未解析的符号。

12. **加载单个主机目标文件:** `hostObject` 函数用于加载单个主机目标文件。

13. **检查指纹信息:** `checkFingerprint` 函数用于比较库的指纹信息，确保导入和被导入的包具有一致的符号索引视图。

14. **读取 ELF 符号数据:** `readelfsymboldata` 函数从 ELF 文件中读取指定符号的数据。

15. **读取并填充数据:** `readwithpad` 函数从 `io.Reader` 读取指定大小的数据，并进行填充。

16. **读取 ELF 注释段:** `readnote` 函数用于读取 ELF 文件中的特定名称和类型的注释段。

17. **查找共享库:** `findshlib` 函数在指定的库目录中查找共享库。

18. **加载共享库符号:** `ldshlibsyms` 函数加载共享库的符号信息，包括动态符号和重定位信息。

19. **添加节 (Section):** `addsection` 函数在指定的段 (Segment) 中添加一个新的节。

20. **输出使用帮助:** `usage` 函数打印链接器的使用方法。

21. **定义内部符号:** `defineInternal` 和 `xdefine` 函数用于定义链接器内部使用的符号。

22. **计算数据偏移量:** `datoff` 函数计算给定地址在数据段或代码段中的文件偏移量。

23. **获取入口地址:** `Entryvalue` 函数获取程序的入口地址。

24. **生成调用图:** `callgraph` 函数（如果 `-C` flag 被设置）输出函数调用关系。

25. **向上取整:** `Rnd` 函数将数值向上取整到指定的倍数。

26. **从 bio.Reader 读取一个字节:** `bgetc` 函数从 `bio.Reader` 中读取一个字节。

27. **后序遍历库依赖:** `postorder` 和 `dfs` 函数用于对库的依赖关系进行后序遍历，以确定链接顺序。

28. **获取用于重定位的 ELF 符号索引:** `ElfSymForReloc` 函数获取用于 ELF 重定位的符号索引。

29. **添加 GOT 表项:** `AddGotSym` 函数为指定的符号在 GOT (Global Offset Table) 中添加表项。

30. **捕获主机目标文件:** `captureHostObj` 函数将主机目标文件的内容保存到指定目录，用于调试。

31. **查找外部链接工具:** `findExtLinkTool` 函数通过调用外部链接器来查找指定的工具（如 `strip`, `dsymutil`）。

**与其他部分的关系:**

- **第 1 部分:** 主要负责链接的初始化、输入文件的读取和初步处理。这部分代码在第一部分处理完成后执行，是对已加载的目标文件进行最终处理和优化的阶段。
- **第 2 部分:** 主要负责符号解析、重定位等核心链接过程。这部分代码依赖于第二部分生成的链接结果，并对其进行进一步的加工。

**Go 代码示例 (DWARF 处理):**

```go
// 假设 flagOutfile 指向生成的可执行文件 "output_binary"
// 假设 flagTmpdir 指向临时目录 "/tmp/link_temp"

combineDwarf := true // 假设启用了 DWARF 合并

if combineDwarf {
    // 模拟 ctxt.findExtLinkTool 的返回值
    dsymutilCmd := "/usr/bin/dsymutil"
    stripCmd := "/usr/bin/strip"

    dsym := filepath.Join(*flagTmpdir, "go.dwarf")
    cmd := exec.Command(dsymutilCmd, "-f", *flagOutfile, "-o", dsym)
    // ... 执行 dsymutil 命令 ...

    // ... 执行 strip 命令 ...

    // 模拟 machoCombineDwarf 函数
    machoCombineDwarfFunc := func(ctxt *Link, exef *os.File, exem *macho.File, dsymPath string, outexe string) error {
        fmt.Printf("Combining DWARF from %s into %s\n", dsymPath, outexe)
        return nil
    }

    updateMachoOutFile("combining dwarf",
        func(ctxt *Link, exef *os.File, exem *macho.File, outexe string) error {
            return machoCombineDwarfFunc(ctxt, exef, exem, dsym, outexe)
        })
}
```

**假设的输入与输出:**

- **输入:**  `*flagOutfile` 指向一个已经链接生成但尚未进行 DWARF 处理的可执行文件 "output_binary"。
- **输出:**
    - 如果 `combineDwarf` 为真，则可能在 `/tmp/link_temp` 目录下生成 "go.dwarf" 文件。
    - 最终的 "output_binary" 文件经过 `strip` 处理，移除了 STAB 符号，并且可能合并了 DWARF 信息。

**命令行参数处理:**

这部分代码涉及对以下命令行参数的处理 (通过全局变量 `flagOutfile` 和 `flagTmpdir` 访问):

- `flagOutfile`:  指定输出可执行文件的路径。代码会使用此参数来定位需要进行后处理的文件。
- `flagTmpdir`:  指定临时目录，用于存放 DWARF 文件等临时文件。

**易犯错的点 (使用者角度):**

虽然这段代码主要是链接器内部的实现，但开发者在使用 `go build` 等命令时，如果使用了不正确的链接器 flag 或环境变量，可能会间接导致这里的功能出错，例如：

- **依赖于外部工具 (`dsymutil`, `strip`) 的可用性:**  如果这些工具在系统路径中找不到，链接过程会失败。
- **不正确的 DWARF 相关 flag:**  如果使用了与目标平台不兼容的 DWARF 处理 flag，可能会导致链接错误或生成的调试信息不正确。

总而言之，这部分 `lib.go` 代码是 Go 语言链接器在完成核心链接任务后，对生成的可执行文件进行最终润色和适配的关键环节，确保生成的可执行文件能够正确运行并具备必要的调试信息和安全性。

### 提示词
```
这是路径为go/src/cmd/link/internal/ld/lib.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第3部分，共3部分，请归纳一下它的功能
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