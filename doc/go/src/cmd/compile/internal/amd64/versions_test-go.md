Response: Let's break down the thought process for analyzing the provided Go code.

**1. Understanding the Goal:**

The first step is to understand the *purpose* of the code. The comment at the beginning is crucial: "Test to make sure that when building for GOAMD64=v1, we don't use any >v1 instructions."  This immediately tells us the core functionality is testing instruction set restrictions based on the `GOAMD64` environment variable.

**2. Identifying Key Functions and Test Cases:**

Next, I scan the code for functions that are clearly tests (starting with `Test...`). This quickly highlights:

* `TestGoAMD64v1`: This is the main driver, seemingly designed to enforce the `GOAMD64=v1` constraint.
* `TestPopCnt`, `TestAndNot`, `TestBLSI`, `TestBLSMSK`, `TestBLSR`, `TestTrailingZeros`, `TestRound`, `TestFMA`: These seem to be individual tests for specific instructions or functionalities.

**3. Analyzing `TestGoAMD64v1` in Detail:**

This is the most complex test, so I break it down step-by-step:

* **Skips:** The initial `if` statements check for platform (amd64, Linux/Darwin), `GOAMD64` level, and a recursive call flag (`TESTGOAMD64V1`). This suggests the test involves running itself.
* **Binary Creation:**  It creates a temporary executable, which is a modified copy of the current running binary. This is a key insight.
* **`clobber` Function:** This function is called to "clobber" the binary. The loop iterating through `featureToOpcodes` and `runtimeFeatures` suggests this clobbering involves disabling certain CPU features and their associated opcodes.
* **Execution:** The modified binary is executed with specific environment variables: `TESTGOAMD64V1=yes` (to prevent infinite recursion) and `GODEBUG` with disabled CPU features.
* **Output Verification:** The test checks if the output of the executed binary is "PASS" (potentially with a coverage line).

**4. Analyzing the `clobber` Function:**

This is central to `TestGoAMD64v1`.

* **Disassembly:** It uses `objdump` (either the Go tool version or the system version) to get assembly code. This confirms the interaction with low-level instructions.
* **Opcode Identification:** It uses regular expressions to find instruction addresses and opcodes in the disassembly.
* **Instruction Replacement:**  For opcodes in the `opcodes` map, it replaces the corresponding bytes in the binary with `0xcc` (the `INT3` instruction, which causes a fault).
* **ELF/Mach-O Handling:**  It handles both ELF and Mach-O executable formats to find the physical addresses corresponding to the virtual addresses of the instructions.

**5. Analyzing the Individual Instruction Tests:**

These are simpler:

* They test specific bit manipulation functions (`bits.OnesCount64`, `&^`, bitwise operations, `bits.TrailingZeros`) and floating-point functions (`math.RoundToEven`, `math.FMA`).
* They provide simple test cases with input and expected output values.

**6. Inferring Go Language Features:**

Based on the tests, I can infer the Go language features being tested:

* **Instruction Set Architecture (ISA) Control:** The `TestGoAMD64v1` test clearly demonstrates Go's ability to control the allowed instruction set through the `GOAMD64` environment variable. This is a key compiler optimization feature.
* **Bit Manipulation Intrinsics:** The `TestPopCnt`, `TestAndNot`, `TestBLSI`, etc., test functions in the `bits` package, which often map directly to specific CPU instructions for efficiency.
* **Floating-Point Operations:** `TestRound` and `TestFMA` test the `math` package's functions for rounding and fused multiply-add, which can leverage specialized hardware instructions.

**7. Constructing Go Code Examples:**

Based on the identified features, I create simple Go code examples to illustrate their usage.

**8. Identifying Command-Line Parameter Handling:**

The `TestGoAMD64v1` test itself uses environment variables (`GOAMD64`, `TESTGOAMD64V1`, `GODEBUG`). The `clobber` function uses `objdump`, which is a command-line tool. I document how these are used within the test context.

**9. Identifying Potential Pitfalls:**

I consider common errors a user might make based on the test's logic:

* **Incorrect `GOAMD64` Setting:** Setting `GOAMD64` incorrectly would lead to the compiler potentially using instructions not supported by the target architecture.
* **Dependencies on External Tools:** The `clobber` function relies on `objdump`, which might not be available or might be a different version with varying output formats.

**Self-Correction/Refinement During the Process:**

* **Initial Focus on Individual Tests:** I might initially focus too much on the simpler instruction tests. Realizing that `TestGoAMD64v1` is the core driver shifts the focus.
* **Understanding `clobber`:**  It takes some careful reading to understand the purpose and mechanics of the `clobber` function. The use of `objdump` and binary patching is a key insight.
* **Connecting Tests to Features:**  Explicitly linking the individual tests to the broader Go language features (like ISA control and bit manipulation intrinsics) provides a higher-level understanding.

By following this systematic approach, I can effectively analyze the Go code, understand its purpose, identify key functionalities, and provide informative answers to the questions.
这段代码是 Go 语言标准库中 `cmd/compile/internal/amd64` 包的一部分，专门用于测试 AMD64 架构下不同 CPU 指令集版本（通过 `GOAMD64` 环境变量控制）的编译行为。

**它的主要功能是：**

1. **测试 `GOAMD64=v1` 编译模式的正确性。**  它确保在指定 `GOAMD64=v1` 时，编译器不会生成高于 v1 版本的 CPU 指令。
2. **通过修改可执行文件的方式模拟禁用特定 CPU 特性。**  它通过 `clobber` 函数将目标二进制文件中对应于更高版本指令的机器码替换成会导致程序崩溃的指令 (INT3)。
3. **测试特定 CPU 指令是否被正确使用。**  例如 `TestPopCnt` 测试 `bits.OnesCount64` 和 `bits.OnesCount32` 是否使用了 `POPCNT` 指令（如果可用）。

**更详细的功能分解：**

* **`TestGoAMD64v1(t *testing.T)`:**
    * **跳过条件:**  如果不是 AMD64 架构、非 Linux/Darwin 平台、已经设置了 `GOAMD64=v2` 或更高版本、或者当前是递归调用自身，则跳过测试。
    * **创建临时可执行文件:**  创建一个当前运行程序的可执行副本。
    * **禁用高级指令:**  调用 `clobber` 函数，根据 `featureToOpcodes` 和 `runtimeFeatures` 映射关系，将二进制文件中对应于高于 v1 版本特性的指令替换成 `INT3` 指令。
    * **执行修改后的二进制文件:**  运行修改后的二进制文件，并设置 `TESTGOAMD64V1=yes` 避免无限递归，同时通过 `GODEBUG` 环境变量禁用对应的 CPU 特性。
    * **验证输出:**  检查修改后的程序是否正常执行并输出 "PASS"。如果使用了被禁用的指令，程序会因为 `INT3` 指令而崩溃。

* **`clobber(t *testing.T, src string, dst *os.File, opcodes map[string]bool)`:**
    * **反汇编:** 使用 `objdump` 工具（可能是 `go tool objdump` 或系统自带的 `objdump`）反汇编源可执行文件。
    * **查找目标指令:**  解析反汇编输出，找到 `opcodes` 列表中指定的指令的地址。
    * **定位物理地址:**  根据 ELF 或 Mach-O 格式解析源文件的段信息，将指令的虚拟地址转换为文件中的物理地址。
    * **替换指令:** 将目标文件中对应物理地址的字节替换为 `0xcc`，即 `INT3` 指令的机器码。

* **`setOf(keys ...string) map[string]bool`:**  一个辅助函数，用于创建一个包含指定键的集合（map）。

* **`runtimeFeatures`:** 一个包含了当前 Go 版本在 AMD64 架构下支持的 CPU 特性的集合。

* **`featureToOpcodes`:** 一个映射，将 CPU 特性名称（例如 "popcnt", "bmi1"）映射到该特性相关的汇编指令助记符列表。

* **`TestPopCnt(t *testing.T)`，`TestAndNot(t *testing.T)`，`TestBLSI(t *testing.T)`，`TestBLSMSK(t *testing.T)`，`TestBLSR(t *testing.T)`，`TestTrailingZeros(t *testing.T)`，`TestRound(t *testing.T)`，`TestFMA(t *testing.T)`:** 这些是独立的测试函数，用于验证特定的位操作或数学函数是否使用了预期的 CPU 指令。

**它可以推理出这是 Go 语言编译器针对 AMD64 架构指令集版本控制功能的实现。**

**Go 代码举例说明：**

假设我们有一个简单的 Go 程序 `main.go`：

```go
package main

import (
	"fmt"
	"math/bits"
)

func main() {
	x := uint64(0b00001111)
	count := bits.OnesCount64(x)
	fmt.Println(count)
	fmt.Println("PASS")
}
```

**测试场景：**

1. **编译并运行 `GOAMD64=v1` 的程序：**
   ```bash
   GOAMD64=v1 go build -o main_v1 main.go
   ./main_v1
   ```
   **预期输出：**
   ```
   4
   PASS
   ```
   由于 `GOAMD64=v1`，编译器应该生成不包含高于 v1 指令的代码。`bits.OnesCount64` 的实现可能使用循环或查找表，而不是 `POPCNT` 指令。

2. **编译并运行 `GOAMD64=v2` 的程序：**
   ```bash
   GOAMD64=v2 go build -o main_v2 main.go
   ./main_v2
   ```
   **预期输出：**
   ```
   4
   PASS
   ```
   由于 `GOAMD64=v2`，编译器可能会使用 `POPCNT` 指令优化 `bits.OnesCount64` 的实现。

**代码推理与假设的输入与输出（以 `TestGoAMD64v1` 为例）：**

**假设输入：**

* 当前运行的 Go 程序编译时没有指定 `GOAMD64`，或者指定了 `GOAMD64=v2` 或更高。
* 运行测试的操作系统是 Linux。

**执行流程：**

1. `TestGoAMD64v1` 函数被调用。
2. 由于 `runtime.GOARCH == "amd64"` 且 `runtime.GOOS == "linux"`，并且假设 `build.Default.ToolTags` 中不包含 "amd64.v2"，测试继续。
3. 创建一个临时文件，例如 `/tmp/TestGoAMD64v1123`。
4. `clobber` 函数被调用，源文件是当前运行的测试二进制文件，目标文件是 `/tmp/TestGoAMD64v1123`，`opcodes` 包含了高于 v1 版本的指令，例如 `popcntq`。
5. `clobber` 函数会：
   * 使用 `objdump` 反汇编当前测试二进制文件。
   * 在反汇编输出中找到 `popcntq` 指令的地址和机器码。
   * 将 `/tmp/TestGoAMD64v1123` 中对应这些指令的字节替换为 `0xcc`。
6. 修改后的临时文件 `/tmp/TestGoAMD64v1123` 被执行，环境变量 `TESTGOAMD64V1=yes` 和 `GODEBUG=cpu.popcnt=off,...` 被设置。
7. 由于 `popcnt` 特性被禁用，即使二进制文件中可能存在 `POPCNT` 指令（但已被 `clobber` 替换），运行时也不会尝试使用它。
8. 如果原始的测试二进制文件在没有 `POPCNT` 指令的情况下也能正常工作（例如，`bits.OnesCount64` 有其他实现），则修改后的程序会输出 "PASS"。

**假设输出（`TestGoAMD64v1`）：**

如果一切正常，`TestGoAMD64v1` 函数会成功执行，不会调用 `t.Fatalf`，并且修改后的程序会输出 "PASS"。

**命令行参数的具体处理（以 `clobber` 函数为例）：**

`clobber` 函数内部使用了 `objdump` 命令行工具。它通过 `testenv.Command` 创建 `exec.Cmd` 对象来执行 `objdump`。

* **`cmd := testenv.Command(t, "objdump", "-d", src)`**  （在没有使用 `go tool objdump` 的情况下）
    * `"objdump"`:  要执行的命令名称。
    * `"-d"`: `objdump` 的选项，表示反汇编代码段。
    * `src`:  要反汇编的可执行文件的路径。

`objdump` 的输出被管道连接到 Go 代码中，并使用正则表达式解析反汇编结果。

**使用者易犯错的点：**

1. **环境依赖:**  `clobber` 函数依赖于 `objdump` 工具的存在，如果在没有 `objdump` 的系统上运行测试，会出错。测试代码中也考虑了这种情况，会跳过测试 (`t.Skipf`)。
2. **`GOAMD64` 设置不当:**  开发者在手动编译程序时，如果设置了错误的 `GOAMD64` 值，可能会导致程序在不支持该指令集的 CPU 上崩溃或行为异常。这个测试的目的就是为了防止编译器在 `GOAMD64=v1` 的情况下生成高于 v1 的指令。
3. **理解 `GODEBUG` 的作用:**  在 `TestGoAMD64v1` 中，`GODEBUG` 环境变量用于在运行时禁用特定的 CPU 特性。如果开发者不理解 `GODEBUG` 的作用，可能会对测试的行为感到困惑。例如，即使程序被编译为可以使用 `POPCNT`，但如果设置了 `GODEBUG=cpu.popcnt=off`，运行时也不会使用它。

**例子说明 `GOAMD64` 设置不当的潜在错误：**

假设你的程序使用了 `bits.OnesCount64`，并且你在一个支持 `POPCNT` 指令的机器上编译了程序，没有设置 `GOAMD64` 或设置了 `GOAMD64=v2`。编译器很可能会生成使用 `POPCNT` 指令的代码。

现在，如果你将这个编译好的程序复制到一台不支持 `POPCNT` 指令的旧机器上运行，程序就会因为执行了非法的指令而崩溃。这就是为什么通过 `GOAMD64` 控制目标指令集版本非常重要的原因。

### 提示词
```
这是路径为go/src/cmd/compile/internal/amd64/versions_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```go
// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// When using GOEXPERIMENT=boringcrypto, the test program links in the boringcrypto syso,
// which does not respect GOAMD64, so we skip the test if boringcrypto is enabled.
//go:build !boringcrypto

package amd64_test

import (
	"bufio"
	"debug/elf"
	"debug/macho"
	"errors"
	"fmt"
	"go/build"
	"internal/testenv"
	"io"
	"math"
	"math/bits"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// Test to make sure that when building for GOAMD64=v1, we don't
// use any >v1 instructions.
func TestGoAMD64v1(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skip("amd64-only test")
	}
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("test only works on elf or macho platforms")
	}
	for _, tag := range build.Default.ToolTags {
		if tag == "amd64.v2" {
			t.Skip("compiling for GOAMD64=v2 or higher")
		}
	}
	if os.Getenv("TESTGOAMD64V1") != "" {
		t.Skip("recursive call")
	}

	// Make a binary which will be a modified version of the
	// currently running binary.
	dst, err := os.CreateTemp("", "TestGoAMD64v1")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(dst.Name())
	dst.Chmod(0500) // make executable

	// Clobber all the non-v1 opcodes.
	opcodes := map[string]bool{}
	var features []string
	for feature, opcodeList := range featureToOpcodes {
		if runtimeFeatures[feature] {
			features = append(features, fmt.Sprintf("cpu.%s=off", feature))
		}
		for _, op := range opcodeList {
			opcodes[op] = true
		}
	}
	clobber(t, os.Args[0], dst, opcodes)
	if err = dst.Close(); err != nil {
		t.Fatalf("can't close binary: %v", err)
	}

	// Run the resulting binary.
	cmd := testenv.Command(t, dst.Name())
	testenv.CleanCmdEnv(cmd)
	cmd.Env = append(cmd.Env, "TESTGOAMD64V1=yes")
	cmd.Env = append(cmd.Env, fmt.Sprintf("GODEBUG=%s", strings.Join(features, ",")))
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("couldn't execute test: %s\n%s", err, out)
	}
	// Expect to see output of the form "PASS\n", unless the test binary
	// was compiled for coverage (in which case there will be an extra line).
	success := false
	lines := strings.Split(string(out), "\n")
	if len(lines) == 2 {
		success = lines[0] == "PASS" && lines[1] == ""
	} else if len(lines) == 3 {
		success = lines[0] == "PASS" &&
			strings.HasPrefix(lines[1], "coverage") && lines[2] == ""
	}
	if !success {
		t.Fatalf("test reported error: %s lines=%+v", string(out), lines)
	}
}

// Clobber copies the binary src to dst, replacing all the instructions in opcodes with
// faulting instructions.
func clobber(t *testing.T, src string, dst *os.File, opcodes map[string]bool) {
	// Run objdump to get disassembly.
	var re *regexp.Regexp
	var disasm io.Reader
	if false {
		// TODO: go tool objdump doesn't disassemble the bmi1 instructions
		// in question correctly. See issue 48584.
		cmd := testenv.Command(t, "go", "tool", "objdump", src)
		var err error
		disasm, err = cmd.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := cmd.Wait(); err != nil {
				t.Error(err)
			}
		})
		re = regexp.MustCompile(`^[^:]*:[-\d]+\s+0x([\da-f]+)\s+([\da-f]+)\s+([A-Z]+)`)
	} else {
		// TODO: we're depending on platform-native objdump here. Hence the Skipf
		// below if it doesn't run for some reason.
		cmd := testenv.Command(t, "objdump", "-d", src)
		var err error
		disasm, err = cmd.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		if err := cmd.Start(); err != nil {
			if errors.Is(err, exec.ErrNotFound) {
				t.Skipf("can't run test due to missing objdump: %s", err)
			}
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := cmd.Wait(); err != nil {
				t.Error(err)
			}
		})
		re = regexp.MustCompile(`^\s*([\da-f]+):\s*((?:[\da-f][\da-f] )+)\s*([a-z\d]+)`)
	}

	// Find all the instruction addresses we need to edit.
	virtualEdits := map[uint64]bool{}
	scanner := bufio.NewScanner(disasm)
	for scanner.Scan() {
		line := scanner.Text()
		parts := re.FindStringSubmatch(line)
		if len(parts) == 0 {
			continue
		}
		addr, err := strconv.ParseUint(parts[1], 16, 64)
		if err != nil {
			continue // not a hex address
		}
		opcode := strings.ToLower(parts[3])
		if !opcodes[opcode] {
			continue
		}
		t.Logf("clobbering instruction %s", line)
		n := (len(parts[2]) - strings.Count(parts[2], " ")) / 2 // number of bytes in instruction encoding
		for i := 0; i < n; i++ {
			// Only really need to make the first byte faulting, but might
			// as well make all the bytes faulting.
			virtualEdits[addr+uint64(i)] = true
		}
	}

	// Figure out where in the binary the edits must be done.
	physicalEdits := map[uint64]bool{}
	if e, err := elf.Open(src); err == nil {
		for _, sec := range e.Sections {
			vaddr := sec.Addr
			paddr := sec.Offset
			size := sec.Size
			for a := range virtualEdits {
				if a >= vaddr && a < vaddr+size {
					physicalEdits[paddr+(a-vaddr)] = true
				}
			}
		}
	} else if m, err2 := macho.Open(src); err2 == nil {
		for _, sec := range m.Sections {
			vaddr := sec.Addr
			paddr := uint64(sec.Offset)
			size := sec.Size
			for a := range virtualEdits {
				if a >= vaddr && a < vaddr+size {
					physicalEdits[paddr+(a-vaddr)] = true
				}
			}
		}
	} else {
		t.Log(err)
		t.Log(err2)
		t.Fatal("executable format not elf or macho")
	}
	if len(virtualEdits) != len(physicalEdits) {
		t.Fatal("couldn't find an instruction in text sections")
	}

	// Copy source to destination, making edits along the way.
	f, err := os.Open(src)
	if err != nil {
		t.Fatal(err)
	}
	r := bufio.NewReader(f)
	w := bufio.NewWriter(dst)
	a := uint64(0)
	done := 0
	for {
		b, err := r.ReadByte()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal("can't read")
		}
		if physicalEdits[a] {
			b = 0xcc // INT3 opcode
			done++
		}
		err = w.WriteByte(b)
		if err != nil {
			t.Fatal("can't write")
		}
		a++
	}
	if done != len(physicalEdits) {
		t.Fatal("physical edits remaining")
	}
	w.Flush()
	f.Close()
}

func setOf(keys ...string) map[string]bool {
	m := make(map[string]bool, len(keys))
	for _, key := range keys {
		m[key] = true
	}
	return m
}

var runtimeFeatures = setOf(
	"adx", "aes", "avx", "avx2", "bmi1", "bmi2", "erms", "fma",
	"pclmulqdq", "popcnt", "rdtscp", "sse3", "sse41", "sse42", "ssse3",
)

var featureToOpcodes = map[string][]string{
	// Note: we include *q, *l, and plain opcodes here.
	// go tool objdump doesn't include a [QL] on popcnt instructions, until CL 351889
	// native objdump doesn't include [QL] on linux.
	"popcnt": {"popcntq", "popcntl", "popcnt"},
	"bmi1": {
		"andnq", "andnl", "andn",
		"blsiq", "blsil", "blsi",
		"blsmskq", "blsmskl", "blsmsk",
		"blsrq", "blsrl", "blsr",
		"tzcntq", "tzcntl", "tzcnt",
	},
	"bmi2": {
		"sarxq", "sarxl", "sarx",
		"shlxq", "shlxl", "shlx",
		"shrxq", "shrxl", "shrx",
	},
	"sse41": {
		"roundsd",
		"pinsrq", "pinsrl", "pinsrd", "pinsrb", "pinsr",
		"pextrq", "pextrl", "pextrd", "pextrb", "pextr",
		"pminsb", "pminsd", "pminuw", "pminud", // Note: ub and sw are ok.
		"pmaxsb", "pmaxsd", "pmaxuw", "pmaxud",
		"pmovzxbw", "pmovzxbd", "pmovzxbq", "pmovzxwd", "pmovzxwq", "pmovzxdq",
		"pmovsxbw", "pmovsxbd", "pmovsxbq", "pmovsxwd", "pmovsxwq", "pmovsxdq",
		"pblendvb",
	},
	"fma":   {"vfmadd231sd"},
	"movbe": {"movbeqq", "movbeq", "movbell", "movbel", "movbe"},
	"lzcnt": {"lzcntq", "lzcntl", "lzcnt"},
}

// Test to use POPCNT instruction, if available
func TestPopCnt(t *testing.T) {
	for _, tt := range []struct {
		x    uint64
		want int
	}{
		{0b00001111, 4},
		{0b00001110, 3},
		{0b00001100, 2},
		{0b00000000, 0},
	} {
		if got := bits.OnesCount64(tt.x); got != tt.want {
			t.Errorf("OnesCount64(%#x) = %d, want %d", tt.x, got, tt.want)
		}
		if got := bits.OnesCount32(uint32(tt.x)); got != tt.want {
			t.Errorf("OnesCount32(%#x) = %d, want %d", tt.x, got, tt.want)
		}
	}
}

// Test to use ANDN, if available
func TestAndNot(t *testing.T) {
	for _, tt := range []struct {
		x, y, want uint64
	}{
		{0b00001111, 0b00000011, 0b1100},
		{0b00001111, 0b00001100, 0b0011},
		{0b00000000, 0b00000000, 0b0000},
	} {
		if got := tt.x &^ tt.y; got != tt.want {
			t.Errorf("%#x &^ %#x = %#x, want %#x", tt.x, tt.y, got, tt.want)
		}
		if got := uint32(tt.x) &^ uint32(tt.y); got != uint32(tt.want) {
			t.Errorf("%#x &^ %#x = %#x, want %#x", tt.x, tt.y, got, tt.want)
		}
	}
}

// Test to use BLSI, if available
func TestBLSI(t *testing.T) {
	for _, tt := range []struct {
		x, want uint64
	}{
		{0b00001111, 0b001},
		{0b00001110, 0b010},
		{0b00001100, 0b100},
		{0b11000110, 0b010},
		{0b00000000, 0b000},
	} {
		if got := tt.x & -tt.x; got != tt.want {
			t.Errorf("%#x & (-%#x) = %#x, want %#x", tt.x, tt.x, got, tt.want)
		}
		if got := uint32(tt.x) & -uint32(tt.x); got != uint32(tt.want) {
			t.Errorf("%#x & (-%#x) = %#x, want %#x", tt.x, tt.x, got, tt.want)
		}
	}
}

// Test to use BLSMSK, if available
func TestBLSMSK(t *testing.T) {
	for _, tt := range []struct {
		x, want uint64
	}{
		{0b00001111, 0b001},
		{0b00001110, 0b011},
		{0b00001100, 0b111},
		{0b11000110, 0b011},
		{0b00000000, 1<<64 - 1},
	} {
		if got := tt.x ^ (tt.x - 1); got != tt.want {
			t.Errorf("%#x ^ (%#x-1) = %#x, want %#x", tt.x, tt.x, got, tt.want)
		}
		if got := uint32(tt.x) ^ (uint32(tt.x) - 1); got != uint32(tt.want) {
			t.Errorf("%#x ^ (%#x-1) = %#x, want %#x", tt.x, tt.x, got, uint32(tt.want))
		}
	}
}

// Test to use BLSR, if available
func TestBLSR(t *testing.T) {
	for _, tt := range []struct {
		x, want uint64
	}{
		{0b00001111, 0b00001110},
		{0b00001110, 0b00001100},
		{0b00001100, 0b00001000},
		{0b11000110, 0b11000100},
		{0b00000000, 0b00000000},
	} {
		if got := tt.x & (tt.x - 1); got != tt.want {
			t.Errorf("%#x & (%#x-1) = %#x, want %#x", tt.x, tt.x, got, tt.want)
		}
		if got := uint32(tt.x) & (uint32(tt.x) - 1); got != uint32(tt.want) {
			t.Errorf("%#x & (%#x-1) = %#x, want %#x", tt.x, tt.x, got, tt.want)
		}
	}
}

func TestTrailingZeros(t *testing.T) {
	for _, tt := range []struct {
		x    uint64
		want int
	}{
		{0b00001111, 0},
		{0b00001110, 1},
		{0b00001100, 2},
		{0b00001000, 3},
		{0b00000000, 64},
	} {
		if got := bits.TrailingZeros64(tt.x); got != tt.want {
			t.Errorf("TrailingZeros64(%#x) = %d, want %d", tt.x, got, tt.want)
		}
		want := tt.want
		if want == 64 {
			want = 32
		}
		if got := bits.TrailingZeros32(uint32(tt.x)); got != want {
			t.Errorf("TrailingZeros64(%#x) = %d, want %d", tt.x, got, want)
		}
	}
}

func TestRound(t *testing.T) {
	for _, tt := range []struct {
		x, want float64
	}{
		{1.4, 1},
		{1.5, 2},
		{1.6, 2},
		{2.4, 2},
		{2.5, 2},
		{2.6, 3},
	} {
		if got := math.RoundToEven(tt.x); got != tt.want {
			t.Errorf("RoundToEven(%f) = %f, want %f", tt.x, got, tt.want)
		}
	}
}

func TestFMA(t *testing.T) {
	for _, tt := range []struct {
		x, y, z, want float64
	}{
		{2, 3, 4, 10},
		{3, 4, 5, 17},
	} {
		if got := math.FMA(tt.x, tt.y, tt.z); got != tt.want {
			t.Errorf("FMA(%f,%f,%f) = %f, want %f", tt.x, tt.y, tt.z, got, tt.want)
		}
	}
}
```