Response: Let's break down the thought process for analyzing this Go code snippet.

**1. Initial Understanding: Context and Purpose**

The file path `go/src/cmd/asm/internal/asm/operand_test.go` immediately tells us this is part of the Go assembler (`cmd/asm`), specifically within the `internal/asm` package, and further focusing on `operand` parsing. The `_test.go` suffix indicates this is a test file. Therefore, its primary purpose is to test the functionality of operand parsing within the Go assembler.

**2. Core Functionality Identification: Test Functions**

The presence of functions like `TestAMD64OperandParser`, `TestARMOperandParser`, etc., strongly suggests that the code is testing operand parsing for different CPU architectures. Each of these functions sets up a parser for a specific architecture and then calls helper functions to perform the actual testing.

**3. Deeper Dive: Helper Functions (`testOperandParser`, `testBadOperandParser`, `tryParse`, `newParser`, `setArch`)**

* **`testOperandParser`**: This function takes a `Parser` and a slice of `operandTest` structs. It iterates through these tests, tokenizes the input string, uses the parser to parse the operand, and then compares the output of the parser with the expected output. This clearly tests *successful* parsing of operands.

* **`testBadOperandParser`**: Similar to `testOperandParser`, but it uses `badOperandTest` structs. Crucially, it uses `tryParse` to catch expected errors during parsing. This tests *unsuccessful* parsing and verifies the correct error messages are produced.

* **`tryParse`**: This is a common Go testing pattern for catching panics and treating them as errors. It sets a `panicOnError` flag, defers a function that recovers from panics, and then executes the `parse` function. If a panic occurs (and it's an `error`), it's captured; otherwise, a fatal error is raised, indicating an unexpected panic.

* **`newParser`**: This function simplifies the creation of a `Parser` for a given architecture. It calls `setArch` and then `NewParser`.

* **`setArch`**: This function is responsible for setting up the necessary environment for a specific architecture. It sets `buildcfg.GOOS` and `buildcfg.GOARCH`, retrieves the `arch.Arch` object, and creates an `obj.Link` context. This suggests the operand parsing is architecture-dependent.

**4. Data Structures: `operandTest`, `badOperandTest`**

These structs are straightforward. `operandTest` holds an input string and its expected output after parsing. `badOperandTest` holds an input string and the expected error message when parsing fails.

**5. Specific Test Cases: `amd64OperandTests`, `armOperandTests`, etc.**

Examining these slices reveals numerous examples of valid and invalid operand syntax for various architectures. This provides concrete insight into the supported operand formats. We can see things like registers (AX, R0), immediate values ($10), memory addresses (16(SP), (BX)(CX*4)), and function symbols (`runtime·abort(SB)`).

**6. Identifying a Specific Go Feature: Operand Parsing in Assembly**

Based on the context, the package name (`asm`), the function names (`operand`, `funcAddress`), and the test cases, it becomes clear that this code implements and tests the parsing of operands within the Go assembler. Operands are the arguments to assembly instructions, specifying data or memory locations.

**7. Code Example Construction (Illustrative)**

To illustrate how this works, we can create a simplified example of using the parser:

```go
package main

import (
	"fmt"
	"go/src/cmd/asm/internal/asm"
	"go/src/cmd/asm/internal/lex"
	"go/src/cmd/internal/obj"
)

func main() {
	architecture, ctxt := asm.SetArch("amd64") // Or any other architecture
	parser := asm.NewParser(ctxt, architecture, nil)

	input := "16(SP)"
	parser.Start(lex.Tokenize(input))
	addr := obj.Addr{}
	err := parser.Operand(&addr)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	fmt.Printf("Parsed operand: %+v\n", addr) // Output might vary based on obj.Addr structure
}
```

This example shows the basic steps: setting up the architecture, creating a parser, tokenizing the input, and then calling the `Operand` method to parse the operand.

**8. Command-Line Arguments (Inference)**

While this specific file doesn't handle command-line arguments directly, it's part of the larger Go assembler. The assembler itself (`go tool asm`) *does* take command-line arguments, such as the input assembly file, output object file, and potentially architecture flags. We can infer this based on the context.

**9. Common Mistakes (Based on Error Messages)**

The `amd64BadOperandTests` and similar slices provide good clues about common mistakes. For example, incorrect syntax for register lists (missing hyphens, commas instead of hyphens) is a recurring theme. The ABI selector error also highlights a potential misuse related to ABI specifications.

**10. Iterative Refinement**

The process isn't strictly linear. You might jump back and forth between looking at test functions, helper functions, and data structures to build a complete picture. If something is unclear, you might look for related files or documentation within the Go source code.

This structured approach, starting with the high-level purpose and gradually digging deeper into the code's components and test cases, allows for a comprehensive understanding of the functionality and its context within the Go assembler.
The code snippet you provided is a part of the Go assembler's test suite, specifically for testing the parsing of operands in assembly instructions. Here's a breakdown of its functionality:

**Core Functionality: Testing Operand Parsing**

The primary function of this code is to verify that the Go assembler's operand parser correctly interprets various operand syntaxes for different CPU architectures. It achieves this through a series of unit tests.

**Key Components and Their Functions:**

1. **`setArch(goarch string) (*arch.Arch, *obj.Link)`:**
   - **Function:**  Sets up the architecture-specific environment required for parsing.
   - **Input:** Takes a string representing the target architecture (e.g., "amd64", "arm").
   - **Output:** Returns a pointer to an `arch.Arch` struct (containing architecture details) and a pointer to an `obj.Link` struct (representing the linking context).
   - **Details:** It sets the `GOOS` and `GOARCH` environment variables (important for the `obj` package) and uses `arch.Set` to get the architecture-specific information. It then creates a new linking context using `obj.Linknew`.

2. **`newParser(goarch string) *Parser`:**
   - **Function:** Creates a new assembler parser for a given architecture.
   - **Input:** Takes the target architecture string.
   - **Output:** Returns a pointer to a `Parser` struct.
   - **Details:** It calls `setArch` to get the necessary architecture and context and then uses `NewParser` (presumably from the `cmd/asm/internal/asm` package) to create the parser.

3. **`tryParse(t *testing.T, parse func()) (err error)`:**
   - **Function:** A helper function to execute a parsing function and gracefully handle panics that are expected during error testing.
   - **Input:** Takes a `testing.T` pointer (for reporting test failures) and a function `parse` which encapsulates the parsing logic to be tested.
   - **Output:** Returns an `error` if a panic occurred during parsing (and it was an `error` type), otherwise returns `nil`.
   - **Details:** It sets a global `panicOnError` flag, uses `defer` and `recover` to catch panics. If a panic occurs and it's of type `error`, it's returned; otherwise, it's considered an unexpected panic and the test fails using `t.Fatal`.

4. **`testBadOperandParser(t *testing.T, parser *Parser, tests []badOperandTest)`:**
   - **Function:** Tests the parser's ability to correctly identify and report errors for invalid operand syntax.
   - **Input:** Takes a `testing.T` pointer, a `Parser` instance, and a slice of `badOperandTest` structs.
   - **Details:** It iterates through the `badOperandTest` cases. For each case:
     - It calls `tryParse` with a function that tokenizes the input string using `lex.Tokenize` and attempts to parse the operand using `parser.operand(&addr)`.
     - It then checks if an error was returned by `tryParse`.
     - If no error was returned (but expected), it reports a failure.
     - If an error was returned, it checks if the error message contains the expected error string.

5. **`testOperandParser(t *testing.T, parser *Parser, tests []operandTest)`:**
   - **Function:** Tests the parser's ability to correctly parse valid operand syntax.
   - **Input:** Takes a `testing.T` pointer, a `Parser` instance, and a slice of `operandTest` structs.
   - **Details:** It iterates through the `operandTest` cases. For each case:
     - It tokenizes the input string.
     - It calls `parser.operand(&addr)` to parse the operand, storing the result in an `obj.Addr` struct.
     - It converts the parsed `obj.Addr` back to a string representation using `obj.Dconv` (or `obj.DconvWithABIDetail` if ABI details are allowed).
     - It compares the resulting string with the expected output string. If they don't match, it reports a test failure.

6. **`Test<Architecture>OperandParser(t *testing.T)` functions (e.g., `TestAMD64OperandParser`):**
   - **Function:** Specific test functions for each supported architecture.
   - **Details:** Each of these functions:
     - Creates a new parser for the corresponding architecture using `newParser`.
     - Calls `testOperandParser` with a slice of valid operand test cases (e.g., `amd64OperandTests`).
     - Calls `testBadOperandParser` with a slice of invalid operand test cases (e.g., `amd64BadOperandTests`).
     - Some architectures have additional tests for runtime-specific operand syntax (e.g., `amd64RuntimeOperandTests`).

7. **`TestFuncAddress(t *testing.T)`:**
   - **Function:** Tests the `parser.funcAddress()` method, which is likely used to identify and extract information about function addresses in assembly code.
   - **Details:** It iterates through operand tests for different architectures. For each test case that looks like a function symbol (ends with "(SB)") and isn't a static symbol, it calls `parser.funcAddress()` and checks if it correctly identifies the function name.

8. **`operandTest` and `badOperandTest` structs:**
   - **Function:** Define the structure of the test cases.
   - **`operandTest`:** Contains an `input` string representing an operand and the `output` string representing the expected parsed representation.
   - **`badOperandTest`:** Contains an `input` string representing an invalid operand and the `error` string representing the expected error message.

9. **Example Test Case Slices (e.g., `amd64OperandTests`, `armOperandTests`):**
   - **Function:** These slices contain numerous examples of valid and invalid operand syntaxes for each architecture. They cover various forms of registers, immediate values, memory addressing modes, and function symbols.

**Inference of Go Language Feature:**

This code directly tests the **operand parsing** functionality within the Go assembler. Operand parsing is a crucial part of any assembler, responsible for understanding the arguments provided to assembly instructions. These arguments specify registers, memory locations, immediate values, or labels that the instruction will operate on.

**Go Code Example Illustrating Operand Parsing (Conceptual):**

While you can't directly invoke the internal assembler's operand parser from a regular Go program, you can understand its purpose through a conceptual example:

```go
package main

import (
	"fmt"
	"go/src/cmd/asm/internal/asm" // Hypothetical import
	"go/src/cmd/asm/internal/lex" // Hypothetical import
)

func main() {
	// Imagine we have an assembler parser for amd64
	// (In reality, you'd get this from the assembler's compilation process)
	parser := &asm.Parser{ /* ... initialized for amd64 ... */ }

	// Example assembly instruction with operands
	instruction := "MOVQ $10, AX"

	// Hypothetically, we'd tokenize the instruction
	tokens := lex.Tokenize(instruction) // Assume this splits the instruction into parts

	// And then parse the operands
	var sourceOperand, destinationOperand asm.Operand // Hypothetical Operand type

	// Assume the parser has logic to identify operands based on the instruction format
	// and parse them
	// parser.parseOperand(tokens[1], &sourceOperand) // Parse "$10"
	// parser.parseOperand(tokens[2], &destinationOperand) // Parse "AX"

	// fmt.Printf("Source Operand: %+v\n", sourceOperand)
	// fmt.Printf("Destination Operand: %+v\n", destinationOperand)

	fmt.Println("This example is conceptual and cannot be run directly.")
}
```

**Explanation of the Conceptual Example:**

- The example shows an assembly instruction `MOVQ $10, AX`.
- The operand parser's job is to take the parts of this instruction (like `$10` and `AX`) and understand what they represent (an immediate value of 10 and the AX register, respectively).
- The parsed information would then be used by the assembler to generate the corresponding machine code.

**Command-Line Argument Handling (Indirectly Related):**

This specific test file doesn't directly handle command-line arguments. However, the larger `go tool asm` command (the Go assembler) does. When you use the assembler, you typically provide arguments like:

```bash
go tool asm -o output.o input.s
```

- `-o output.o`: Specifies the output object file name.
- `input.s`: Specifies the input assembly source file.

The assembler itself would parse these arguments to determine the input file, output file, and potentially architecture-specific options. The operand parsing logic tested in this file is a component used *within* the assembler after it has processed the command-line arguments and loaded the assembly source code.

**Common Mistakes Users Might Make (Based on Test Cases):**

Looking at the `amd64BadOperandTests` and similar slices, we can infer common mistakes:

- **Incorrect Register List Syntax:**
  - `"[4"`: Missing closing bracket or incorrect register.
  - `"[]"`: Empty register list.
  - `"[f-x]"`: Invalid register names within the range.
  - `"[X0]"`: Missing the hyphen in a range.
  - `"[X0-X1-X2]"`: Extra hyphen in a range.
  - `"[X0,X3]"`: Using commas instead of hyphens for ranges.

- **Incorrect ABI Selector Syntax:** (Introduced in later Go versions for supporting multiple ABIs)
  - `"$foo<bletch>"`: Malformed ABI selector.
  - `"$foo<ABI0>"`: Using ABI selectors outside of runtime compilation context (this might be a deliberate restriction).

- **General Syntax Errors:** The tests implicitly cover other general syntax errors in operand definitions (e.g., incorrect use of parentheses, operators, etc.).

In summary, this code snippet is a critical part of ensuring the correctness of the Go assembler by rigorously testing its ability to understand the operands used in assembly language for various architectures. The tests highlight both valid and invalid syntax, helping to prevent errors during the assembly process.

Prompt: 
```
这是路径为go/src/cmd/asm/internal/asm/operand_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，

"""
// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package asm

import (
	"internal/buildcfg"
	"strings"
	"testing"

	"cmd/asm/internal/arch"
	"cmd/asm/internal/lex"
	"cmd/internal/obj"
)

// A simple in-out test: Do we print what we parse?

func setArch(goarch string) (*arch.Arch, *obj.Link) {
	buildcfg.GOOS = "linux" // obj can handle this OS for all architectures.
	buildcfg.GOARCH = goarch
	architecture := arch.Set(goarch, false)
	if architecture == nil {
		panic("asm: unrecognized architecture " + goarch)
	}
	ctxt := obj.Linknew(architecture.LinkArch)
	ctxt.Pkgpath = "pkg"
	return architecture, ctxt
}

func newParser(goarch string) *Parser {
	architecture, ctxt := setArch(goarch)
	return NewParser(ctxt, architecture, nil)
}

// tryParse executes parse func in panicOnError=true context.
// parse is expected to call any parsing methods that may panic.
// Returns error gathered from recover; nil if no parse errors occurred.
//
// For unexpected panics, calls t.Fatal.
func tryParse(t *testing.T, parse func()) (err error) {
	panicOnError = true
	defer func() {
		panicOnError = false

		e := recover()
		var ok bool
		if err, ok = e.(error); e != nil && !ok {
			t.Fatal(e)
		}
	}()

	parse()

	return nil
}

func testBadOperandParser(t *testing.T, parser *Parser, tests []badOperandTest) {
	for _, test := range tests {
		err := tryParse(t, func() {
			parser.start(lex.Tokenize(test.input))
			addr := obj.Addr{}
			parser.operand(&addr)
		})

		switch {
		case err == nil:
			t.Errorf("fail at %s: got no errors; expected %s\n", test.input, test.error)
		case !strings.Contains(err.Error(), test.error):
			t.Errorf("fail at %s: got %s; expected %s", test.input, err, test.error)
		}
	}
}

func testOperandParser(t *testing.T, parser *Parser, tests []operandTest) {
	for _, test := range tests {
		parser.start(lex.Tokenize(test.input))
		addr := obj.Addr{}
		parser.operand(&addr)
		var result string
		if parser.allowABI {
			result = obj.DconvWithABIDetail(&emptyProg, &addr)
		} else {
			result = obj.Dconv(&emptyProg, &addr)
		}
		if result != test.output {
			t.Errorf("fail at %s: got %s; expected %s\n", test.input, result, test.output)
		}
	}
}

func TestAMD64OperandParser(t *testing.T) {
	parser := newParser("amd64")
	testOperandParser(t, parser, amd64OperandTests)
	testBadOperandParser(t, parser, amd64BadOperandTests)
	parser.allowABI = true
	testOperandParser(t, parser, amd64RuntimeOperandTests)
	testBadOperandParser(t, parser, amd64BadOperandRuntimeTests)
}

func Test386OperandParser(t *testing.T) {
	parser := newParser("386")
	testOperandParser(t, parser, x86OperandTests)
}

func TestARMOperandParser(t *testing.T) {
	parser := newParser("arm")
	testOperandParser(t, parser, armOperandTests)
}
func TestARM64OperandParser(t *testing.T) {
	parser := newParser("arm64")
	testOperandParser(t, parser, arm64OperandTests)
}

func TestPPC64OperandParser(t *testing.T) {
	parser := newParser("ppc64")
	testOperandParser(t, parser, ppc64OperandTests)
}

func TestMIPSOperandParser(t *testing.T) {
	parser := newParser("mips")
	testOperandParser(t, parser, mipsOperandTests)
}

func TestMIPS64OperandParser(t *testing.T) {
	parser := newParser("mips64")
	testOperandParser(t, parser, mips64OperandTests)
}

func TestLOONG64OperandParser(t *testing.T) {
	parser := newParser("loong64")
	testOperandParser(t, parser, loong64OperandTests)
}

func TestS390XOperandParser(t *testing.T) {
	parser := newParser("s390x")
	testOperandParser(t, parser, s390xOperandTests)
}

func TestFuncAddress(t *testing.T) {
	type subtest struct {
		arch  string
		tests []operandTest
	}
	for _, sub := range []subtest{
		{"amd64", amd64OperandTests},
		{"386", x86OperandTests},
		{"arm", armOperandTests},
		{"arm64", arm64OperandTests},
		{"ppc64", ppc64OperandTests},
		{"mips", mipsOperandTests},
		{"mips64", mips64OperandTests},
		{"loong64", loong64OperandTests},
		{"s390x", s390xOperandTests},
	} {
		t.Run(sub.arch, func(t *testing.T) {
			parser := newParser(sub.arch)
			for _, test := range sub.tests {
				parser.start(lex.Tokenize(test.input))
				name, _, ok := parser.funcAddress()

				isFuncSym := strings.HasSuffix(test.input, "(SB)") &&
					// Ignore static symbols.
					!strings.Contains(test.input, "<>")

				wantName := ""
				if isFuncSym {
					// Strip $|* and (SB) and +Int.
					wantName = test.output[:len(test.output)-4]
					if strings.HasPrefix(wantName, "$") || strings.HasPrefix(wantName, "*") {
						wantName = wantName[1:]
					}
					if i := strings.Index(wantName, "+"); i >= 0 {
						wantName = wantName[:i]
					}
				}
				if ok != isFuncSym || name != wantName {
					t.Errorf("fail at %s as function address: got %s, %v; expected %s, %v", test.input, name, ok, wantName, isFuncSym)
				}
			}
		})
	}
}

type operandTest struct {
	input, output string
}

type badOperandTest struct {
	input, error string
}

// Examples collected by scanning all the assembly in the standard repo.

var amd64OperandTests = []operandTest{
	{"$(-1.0)", "$(-1.0)"},
	{"$(0.0)", "$(0.0)"},
	{"$(0x2000000+116)", "$33554548"},
	{"$(0x3F<<7)", "$8064"},
	{"$(112+8)", "$120"},
	{"$(1<<63)", "$-9223372036854775808"},
	{"$-1", "$-1"},
	{"$0", "$0"},
	{"$0-0", "$0"},
	{"$0-16", "$-16"},
	{"$0x000FFFFFFFFFFFFF", "$4503599627370495"},
	{"$0x01", "$1"},
	{"$0x02", "$2"},
	{"$0x04", "$4"},
	{"$0x3FE", "$1022"},
	{"$0x7fffffe00000", "$140737486258176"},
	{"$0xfffffffffffff001", "$-4095"},
	{"$1", "$1"},
	{"$1.0", "$(1.0)"},
	{"$10", "$10"},
	{"$1000", "$1000"},
	{"$1000000", "$1000000"},
	{"$1000000000", "$1000000000"},
	{"$__tsan_func_enter(SB)", "$__tsan_func_enter(SB)"},
	{"$main(SB)", "$main(SB)"},
	{"$masks<>(SB)", "$masks<>(SB)"},
	{"$setg_gcc<>(SB)", "$setg_gcc<>(SB)"},
	{"$shifts<>(SB)", "$shifts<>(SB)"},
	{"$~(1<<63)", "$9223372036854775807"},
	{"$~0x3F", "$-64"},
	{"$~15", "$-16"},
	{"(((8)&0xf)*4)(SP)", "32(SP)"},
	{"(((8-14)&0xf)*4)(SP)", "40(SP)"},
	{"(6+8)(AX)", "14(AX)"},
	{"(8*4)(BP)", "32(BP)"},
	{"(AX)", "(AX)"},
	{"(AX)(CX*8)", "(AX)(CX*8)"},
	{"(BP)(CX*4)", "(BP)(CX*4)"},
	{"(BP)(DX*4)", "(BP)(DX*4)"},
	{"(BP)(R8*4)", "(BP)(R8*4)"},
	{"(BX)", "(BX)"},
	{"(DI)", "(DI)"},
	{"(DI)(BX*1)", "(DI)(BX*1)"},
	{"(DX)", "(DX)"},
	{"(R9)", "(R9)"},
	{"(R9)(BX*8)", "(R9)(BX*8)"},
	{"(SI)", "(SI)"},
	{"(SI)(BX*1)", "(SI)(BX*1)"},
	{"(SI)(DX*1)", "(SI)(DX*1)"},
	{"(SP)", "(SP)"},
	{"(SP)(AX*4)", "(SP)(AX*4)"},
	{"32(SP)(BX*2)", "32(SP)(BX*2)"},
	{"32323(SP)(R8*4)", "32323(SP)(R8*4)"},
	{"+3(PC)", "3(PC)"},
	{"-1(DI)(BX*1)", "-1(DI)(BX*1)"},
	{"-3(PC)", "-3(PC)"},
	{"-64(SI)(BX*1)", "-64(SI)(BX*1)"},
	{"-96(SI)(BX*1)", "-96(SI)(BX*1)"},
	{"AL", "AL"},
	{"AX", "AX"},
	{"BP", "BP"},
	{"BX", "BX"},
	{"CX", "CX"},
	{"DI", "DI"},
	{"DX", "DX"},
	{"R10", "R10"},
	{"R10", "R10"},
	{"R11", "R11"},
	{"R12", "R12"},
	{"R13", "R13"},
	{"R14", "R14"},
	{"R15", "R15"},
	{"R8", "R8"},
	{"R9", "R9"},
	{"g", "R14"},
	{"SI", "SI"},
	{"SP", "SP"},
	{"X0", "X0"},
	{"X1", "X1"},
	{"X10", "X10"},
	{"X11", "X11"},
	{"X12", "X12"},
	{"X13", "X13"},
	{"X14", "X14"},
	{"X15", "X15"},
	{"X2", "X2"},
	{"X3", "X3"},
	{"X4", "X4"},
	{"X5", "X5"},
	{"X6", "X6"},
	{"X7", "X7"},
	{"X8", "X8"},
	{"X9", "X9"},
	{"_expand_key_128<>(SB)", "_expand_key_128<>(SB)"},
	{"_seek<>(SB)", "_seek<>(SB)"},
	{"a2+16(FP)", "a2+16(FP)"},
	{"addr2+24(FP)", "addr2+24(FP)"},
	{"asmcgocall<>(SB)", "asmcgocall<>(SB)"},
	{"b+24(FP)", "b+24(FP)"},
	{"b_len+32(FP)", "b_len+32(FP)"},
	{"racecall<>(SB)", "racecall<>(SB)"},
	{"rcv_name+20(FP)", "rcv_name+20(FP)"},
	{"retoffset+28(FP)", "retoffset+28(FP)"},
	{"runtime·_GetStdHandle(SB)", "runtime._GetStdHandle(SB)"},
	{"sync\u2215atomic·AddInt64(SB)", "sync/atomic.AddInt64(SB)"},
	{"timeout+20(FP)", "timeout+20(FP)"},
	{"ts+16(FP)", "ts+16(FP)"},
	{"x+24(FP)", "x+24(FP)"},
	{"x·y(SB)", "x.y(SB)"},
	{"x·y(SP)", "x.y(SP)"},
	{"x·y+8(SB)", "x.y+8(SB)"},
	{"x·y+8(SP)", "x.y+8(SP)"},
	{"y+56(FP)", "y+56(FP)"},
	{"·AddUint32(SB)", "pkg.AddUint32(SB)"},
	{"·callReflect(SB)", "pkg.callReflect(SB)"},
	{"[X0-X0]", "[X0-X0]"},
	{"[ Z9 - Z12 ]", "[Z9-Z12]"},
	{"[X0-AX]", "[X0-AX]"},
	{"[AX-X0]", "[AX-X0]"},
	{"[):[o-FP", ""}, // Issue 12469 - asm hung parsing the o-FP range on non ARM platforms.
}

var amd64RuntimeOperandTests = []operandTest{
	{"$bar<ABI0>(SB)", "$bar<ABI0>(SB)"},
	{"$foo<ABIInternal>(SB)", "$foo<ABIInternal>(SB)"},
}

var amd64BadOperandTests = []badOperandTest{
	{"[", "register list: expected ']', found EOF"},
	{"[4", "register list: bad low register in `[4`"},
	{"[]", "register list: bad low register in `[]`"},
	{"[f-x]", "register list: bad low register in `[f`"},
	{"[r10-r13]", "register list: bad low register in `[r10`"},
	{"[k3-k6]", "register list: bad low register in `[k3`"},
	{"[X0]", "register list: expected '-' after `[X0`, found ']'"},
	{"[X0-]", "register list: bad high register in `[X0-]`"},
	{"[X0-x]", "register list: bad high register in `[X0-x`"},
	{"[X0-X1-X2]", "register list: expected ']' after `[X0-X1`, found '-'"},
	{"[X0,X3]", "register list: expected '-' after `[X0`, found ','"},
	{"[X0,X1,X2,X3]", "register list: expected '-' after `[X0`, found ','"},
	{"$foo<ABI0>", "ABI selector only permitted when compiling runtime, reference was to \"foo\""},
}

var amd64BadOperandRuntimeTests = []badOperandTest{
	{"$foo<bletch>", "malformed ABI selector \"bletch\" in reference to \"foo\""},
}

var x86OperandTests = []operandTest{
	{"$(2.928932188134524e-01)", "$(0.29289321881345243)"},
	{"$-1", "$-1"},
	{"$0", "$0"},
	{"$0x00000000", "$0"},
	{"$runtime·badmcall(SB)", "$runtime.badmcall(SB)"},
	{"$setg_gcc<>(SB)", "$setg_gcc<>(SB)"},
	{"$~15", "$-16"},
	{"(-64*1024+104)(SP)", "-65432(SP)"},
	{"(0*4)(BP)", "(BP)"},
	{"(1*4)(DI)", "4(DI)"},
	{"(4*4)(BP)", "16(BP)"},
	{"(AX)", "(AX)"},
	{"(BP)(CX*4)", "(BP)(CX*4)"},
	{"(BP*8)", "0(BP*8)"},
	{"(BX)", "(BX)"},
	{"(SP)", "(SP)"},
	{"*AX", "AX"}, // TODO: Should make * illegal here; a simple alias for JMP AX.
	{"*runtime·_GetStdHandle(SB)", "*runtime._GetStdHandle(SB)"},
	{"-(4+12)(DI)", "-16(DI)"},
	{"-1(DI)(BX*1)", "-1(DI)(BX*1)"},
	{"-96(DI)(BX*1)", "-96(DI)(BX*1)"},
	{"0(AX)", "(AX)"},
	{"0(BP)", "(BP)"},
	{"0(BX)", "(BX)"},
	{"4(AX)", "4(AX)"},
	{"AL", "AL"},
	{"AX", "AX"},
	{"BP", "BP"},
	{"BX", "BX"},
	{"CX", "CX"},
	{"DI", "DI"},
	{"DX", "DX"},
	{"F0", "F0"},
	{"GS", "GS"},
	{"SI", "SI"},
	{"SP", "SP"},
	{"X0", "X0"},
	{"X1", "X1"},
	{"X2", "X2"},
	{"X3", "X3"},
	{"X4", "X4"},
	{"X5", "X5"},
	{"X6", "X6"},
	{"X7", "X7"},
	{"asmcgocall<>(SB)", "asmcgocall<>(SB)"},
	{"ax+4(FP)", "ax+4(FP)"},
	{"ptime-12(SP)", "ptime-12(SP)"},
	{"runtime·_NtWaitForSingleObject(SB)", "runtime._NtWaitForSingleObject(SB)"},
	{"s(FP)", "s(FP)"},
	{"sec+4(FP)", "sec+4(FP)"},
	{"shifts<>(SB)(CX*8)", "shifts<>(SB)(CX*8)"},
	{"x+4(FP)", "x+4(FP)"},
	{"·AddUint32(SB)", "pkg.AddUint32(SB)"},
	{"·reflectcall(SB)", "pkg.reflectcall(SB)"},
	{"[):[o-FP", ""}, // Issue 12469 - asm hung parsing the o-FP range on non ARM platforms.
}

var armOperandTests = []operandTest{
	{"$0", "$0"},
	{"$256", "$256"},
	{"(R0)", "(R0)"},
	{"(R11)", "(R11)"},
	{"(g)", "(g)"},
	{"-12(R4)", "-12(R4)"},
	{"0(PC)", "0(PC)"},
	{"1024", "1024"},
	{"12(R(1))", "12(R1)"},
	{"12(R13)", "12(R13)"},
	{"R0", "R0"},
	{"R0->(32-1)", "R0->31"},
	{"R0<<R1", "R0<<R1"},
	{"R0>>R(1)", "R0>>R1"},
	{"R0@>(32-1)", "R0@>31"},
	{"R1", "R1"},
	{"R11", "R11"},
	{"R12", "R12"},
	{"R13", "R13"},
	{"R14", "R14"},
	{"R15", "R15"},
	{"R1<<2(R3)", "R1<<2(R3)"},
	{"R(1)<<2(R(3))", "R1<<2(R3)"},
	{"R2", "R2"},
	{"R3", "R3"},
	{"R4", "R4"},
	{"R(4)", "R4"},
	{"R5", "R5"},
	{"R6", "R6"},
	{"R7", "R7"},
	{"R8", "R8"},
	{"[R0,R1,g,R15]", "[R0,R1,g,R15]"},
	{"[R0-R7]", "[R0,R1,R2,R3,R4,R5,R6,R7]"},
	{"[R(0)-R(7)]", "[R0,R1,R2,R3,R4,R5,R6,R7]"},
	{"[R0]", "[R0]"},
	{"[R1-R12]", "[R1,R2,R3,R4,R5,R6,R7,R8,R9,g,R11,R12]"},
	{"armCAS64(SB)", "armCAS64(SB)"},
	{"asmcgocall<>(SB)", "asmcgocall<>(SB)"},
	{"c+28(FP)", "c+28(FP)"},
	{"g", "g"},
	{"gosave<>(SB)", "gosave<>(SB)"},
	{"retlo+12(FP)", "retlo+12(FP)"},
	{"runtime·gogo(SB)", "runtime.gogo(SB)"},
	{"·AddUint32(SB)", "pkg.AddUint32(SB)"},
	{"(R1, R3)", "(R1, R3)"},
	{"[R0,R1,g,R15", ""}, // Issue 11764 - asm hung parsing ']' missing register lists.
	{"[):[o-FP", ""},     // Issue 12469 - there was no infinite loop for ARM; these are just sanity checks.
	{"[):[R0-FP", ""},
	{"(", ""}, // Issue 12466 - backed up before beginning of line.
}

var ppc64OperandTests = []operandTest{
	{"$((1<<63)-1)", "$9223372036854775807"},
	{"$(-64*1024)", "$-65536"},
	{"$(1024 * 8)", "$8192"},
	{"$-1", "$-1"},
	{"$-24(R4)", "$-24(R4)"},
	{"$0", "$0"},
	{"$0(R1)", "$(R1)"},
	{"$0.5", "$(0.5)"},
	{"$0x7000", "$28672"},
	{"$0x88888eef", "$2290650863"},
	{"$1", "$1"},
	{"$_main<>(SB)", "$_main<>(SB)"},
	{"$argframe(FP)", "$argframe(FP)"},
	{"$runtime·tlsg(SB)", "$runtime.tlsg(SB)"},
	{"$~3", "$-4"},
	{"(-288-3*8)(R1)", "-312(R1)"},
	{"(16)(R7)", "16(R7)"},
	{"(8)(g)", "8(g)"},
	{"(CTR)", "(CTR)"},
	{"(R0)", "(R0)"},
	{"(R3)", "(R3)"},
	{"(R4)", "(R4)"},
	{"(R5)", "(R5)"},
	{"(R5)(R6*1)", "(R5)(R6*1)"},
	{"(R5+R6)", "(R5)(R6)"},
	{"-1(R4)", "-1(R4)"},
	{"-1(R5)", "-1(R5)"},
	{"6(PC)", "6(PC)"},
	{"CR7", "CR7"},
	{"CTR", "CTR"},
	{"VS0", "VS0"},
	{"VS1", "VS1"},
	{"VS2", "VS2"},
	{"VS3", "VS3"},
	{"VS4", "VS4"},
	{"VS5", "VS5"},
	{"VS6", "VS6"},
	{"VS7", "VS7"},
	{"VS8", "VS8"},
	{"VS9", "VS9"},
	{"VS10", "VS10"},
	{"VS11", "VS11"},
	{"VS12", "VS12"},
	{"VS13", "VS13"},
	{"VS14", "VS14"},
	{"VS15", "VS15"},
	{"VS16", "VS16"},
	{"VS17", "VS17"},
	{"VS18", "VS18"},
	{"VS19", "VS19"},
	{"VS20", "VS20"},
	{"VS21", "VS21"},
	{"VS22", "VS22"},
	{"VS23", "VS23"},
	{"VS24", "VS24"},
	{"VS25", "VS25"},
	{"VS26", "VS26"},
	{"VS27", "VS27"},
	{"VS28", "VS28"},
	{"VS29", "VS29"},
	{"VS30", "VS30"},
	{"VS31", "VS31"},
	{"VS32", "VS32"},
	{"VS33", "VS33"},
	{"VS34", "VS34"},
	{"VS35", "VS35"},
	{"VS36", "VS36"},
	{"VS37", "VS37"},
	{"VS38", "VS38"},
	{"VS39", "VS39"},
	{"VS40", "VS40"},
	{"VS41", "VS41"},
	{"VS42", "VS42"},
	{"VS43", "VS43"},
	{"VS44", "VS44"},
	{"VS45", "VS45"},
	{"VS46", "VS46"},
	{"VS47", "VS47"},
	{"VS48", "VS48"},
	{"VS49", "VS49"},
	{"VS50", "VS50"},
	{"VS51", "VS51"},
	{"VS52", "VS52"},
	{"VS53", "VS53"},
	{"VS54", "VS54"},
	{"VS55", "VS55"},
	{"VS56", "VS56"},
	{"VS57", "VS57"},
	{"VS58", "VS58"},
	{"VS59", "VS59"},
	{"VS60", "VS60"},
	{"VS61", "VS61"},
	{"VS62", "VS62"},
	{"VS63", "VS63"},
	{"V0", "V0"},
	{"V1", "V1"},
	{"V2", "V2"},
	{"V3", "V3"},
	{"V4", "V4"},
	{"V5", "V5"},
	{"V6", "V6"},
	{"V7", "V7"},
	{"V8", "V8"},
	{"V9", "V9"},
	{"V10", "V10"},
	{"V11", "V11"},
	{"V12", "V12"},
	{"V13", "V13"},
	{"V14", "V14"},
	{"V15", "V15"},
	{"V16", "V16"},
	{"V17", "V17"},
	{"V18", "V18"},
	{"V19", "V19"},
	{"V20", "V20"},
	{"V21", "V21"},
	{"V22", "V22"},
	{"V23", "V23"},
	{"V24", "V24"},
	{"V25", "V25"},
	{"V26", "V26"},
	{"V27", "V27"},
	{"V28", "V28"},
	{"V29", "V29"},
	{"V30", "V30"},
	{"V31", "V31"},
	{"F14", "F14"},
	{"F15", "F15"},
	{"F16", "F16"},
	{"F17", "F17"},
	{"F18", "F18"},
	{"F19", "F19"},
	{"F20", "F20"},
	{"F21", "F21"},
	{"F22", "F22"},
	{"F23", "F23"},
	{"F24", "F24"},
	{"F25", "F25"},
	{"F26", "F26"},
	{"F27", "F27"},
	{"F28", "F28"},
	{"F29", "F29"},
	{"F30", "F30"},
	{"F31", "F31"},
	{"LR", "LR"},
	{"R0", "R0"},
	{"R1", "R1"},
	{"R11", "R11"},
	{"R12", "R12"},
	{"R13", "R13"},
	{"R14", "R14"},
	{"R15", "R15"},
	{"R16", "R16"},
	{"R17", "R17"},
	{"R18", "R18"},
	{"R19", "R19"},
	{"R2", "R2"},
	{"R20", "R20"},
	{"R21", "R21"},
	{"R22", "R22"},
	{"R23", "R23"},
	{"R24", "R24"},
	{"R25", "R25"},
	{"R26", "R26"},
	{"R27", "R27"},
	{"R28", "R28"},
	{"R29", "R29"},
	{"R3", "R3"},
	{"R31", "R31"},
	{"R4", "R4"},
	{"R5", "R5"},
	{"R6", "R6"},
	{"R7", "R7"},
	{"R8", "R8"},
	{"R9", "R9"},
	{"SPR(269)", "SPR(269)"},
	{"a(FP)", "a(FP)"},
	{"g", "g"},
	{"ret+8(FP)", "ret+8(FP)"},
	{"runtime·abort(SB)", "runtime.abort(SB)"},
	{"·AddUint32(SB)", "pkg.AddUint32(SB)"},
	{"·trunc(SB)", "pkg.trunc(SB)"},
	{"[):[o-FP", ""}, // Issue 12469 - asm hung parsing the o-FP range on non ARM platforms.
}

var arm64OperandTests = []operandTest{
	{"$0", "$0"},
	{"$0.5", "$(0.5)"},
	{"0(R26)", "(R26)"},
	{"0(RSP)", "(RSP)"},
	{"$1", "$1"},
	{"$-1", "$-1"},
	{"$1000", "$1000"},
	{"$1000000000", "$1000000000"},
	{"$0x7fff3c000", "$34358935552"},
	{"$1234", "$1234"},
	{"$~15", "$-16"},
	{"$16", "$16"},
	{"-16(RSP)", "-16(RSP)"},
	{"16(RSP)", "16(RSP)"},
	{"1(R1)", "1(R1)"},
	{"-1(R4)", "-1(R4)"},
	{"18740(R5)", "18740(R5)"},
	{"$2", "$2"},
	{"$-24(R4)", "$-24(R4)"},
	{"-24(RSP)", "-24(RSP)"},
	{"$24(RSP)", "$24(RSP)"},
	{"-32(RSP)", "-32(RSP)"},
	{"$48", "$48"},
	{"$(-64*1024)(R7)", "$-65536(R7)"},
	{"$(8-1)", "$7"},
	{"a+0(FP)", "a(FP)"},
	{"a1+8(FP)", "a1+8(FP)"},
	{"·AddInt32(SB)", `pkg.AddInt32(SB)`},
	{"runtime·divWVW(SB)", "runtime.divWVW(SB)"},
	{"$argframe+0(FP)", "$argframe(FP)"},
	{"$asmcgocall<>(SB)", "$asmcgocall<>(SB)"},
	{"EQ", "EQ"},
	{"F29", "F29"},
	{"F3", "F3"},
	{"F30", "F30"},
	{"g", "g"},
	{"LR", "R30"},
	{"(LR)", "(R30)"},
	{"R0", "R0"},
	{"R10", "R10"},
	{"R11", "R11"},
	{"R18_PLATFORM", "R18"},
	{"$4503601774854144.0", "$(4503601774854144.0)"},
	{"$runtime·badsystemstack(SB)", "$runtime.badsystemstack(SB)"},
	{"ZR", "ZR"},
	{"(ZR)", "(ZR)"},
	{"(R29, RSP)", "(R29, RSP)"},
	{"[):[o-FP", ""}, // Issue 12469 - asm hung parsing the o-FP range on non ARM platforms.
}

var mips64OperandTests = []operandTest{
	{"$((1<<63)-1)", "$9223372036854775807"},
	{"$(-64*1024)", "$-65536"},
	{"$(1024 * 8)", "$8192"},
	{"$-1", "$-1"},
	{"$-24(R4)", "$-24(R4)"},
	{"$0", "$0"},
	{"$0(R1)", "$(R1)"},
	{"$0.5", "$(0.5)"},
	{"$0x7000", "$28672"},
	{"$0x88888eef", "$2290650863"},
	{"$1", "$1"},
	{"$_main<>(SB)", "$_main<>(SB)"},
	{"$argframe(FP)", "$argframe(FP)"},
	{"$~3", "$-4"},
	{"(-288-3*8)(R1)", "-312(R1)"},
	{"(16)(R7)", "16(R7)"},
	{"(8)(g)", "8(g)"},
	{"(R0)", "(R0)"},
	{"(R3)", "(R3)"},
	{"(R4)", "(R4)"},
	{"(R5)", "(R5)"},
	{"-1(R4)", "-1(R4)"},
	{"-1(R5)", "-1(R5)"},
	{"6(PC)", "6(PC)"},
	{"F14", "F14"},
	{"F15", "F15"},
	{"F16", "F16"},
	{"F17", "F17"},
	{"F18", "F18"},
	{"F19", "F19"},
	{"F20", "F20"},
	{"F21", "F21"},
	{"F22", "F22"},
	{"F23", "F23"},
	{"F24", "F24"},
	{"F25", "F25"},
	{"F26", "F26"},
	{"F27", "F27"},
	{"F28", "F28"},
	{"F29", "F29"},
	{"F30", "F30"},
	{"F31", "F31"},
	{"R0", "R0"},
	{"R1", "R1"},
	{"R11", "R11"},
	{"R12", "R12"},
	{"R13", "R13"},
	{"R14", "R14"},
	{"R15", "R15"},
	{"R16", "R16"},
	{"R17", "R17"},
	{"R18", "R18"},
	{"R19", "R19"},
	{"R2", "R2"},
	{"R20", "R20"},
	{"R21", "R21"},
	{"R22", "R22"},
	{"R23", "R23"},
	{"R24", "R24"},
	{"R25", "R25"},
	{"R26", "R26"},
	{"R27", "R27"},
	{"R29", "R29"},
	{"R3", "R3"},
	{"R31", "R31"},
	{"R4", "R4"},
	{"R5", "R5"},
	{"R6", "R6"},
	{"R7", "R7"},
	{"R8", "R8"},
	{"R9", "R9"},
	{"LO", "LO"},
	{"a(FP)", "a(FP)"},
	{"g", "g"},
	{"RSB", "R28"},
	{"ret+8(FP)", "ret+8(FP)"},
	{"runtime·abort(SB)", "runtime.abort(SB)"},
	{"·AddUint32(SB)", "pkg.AddUint32(SB)"},
	{"·trunc(SB)", "pkg.trunc(SB)"},
	{"[):[o-FP", ""}, // Issue 12469 - asm hung parsing the o-FP range on non ARM platforms.
}

var mipsOperandTests = []operandTest{
	{"$((1<<63)-1)", "$9223372036854775807"},
	{"$(-64*1024)", "$-65536"},
	{"$(1024 * 8)", "$8192"},
	{"$-1", "$-1"},
	{"$-24(R4)", "$-24(R4)"},
	{"$0", "$0"},
	{"$0(R1)", "$(R1)"},
	{"$0.5", "$(0.5)"},
	{"$0x7000", "$28672"},
	{"$0x88888eef", "$2290650863"},
	{"$1", "$1"},
	{"$_main<>(SB)", "$_main<>(SB)"},
	{"$argframe(FP)", "$argframe(FP)"},
	{"$~3", "$-4"},
	{"(-288-3*8)(R1)", "-312(R1)"},
	{"(16)(R7)", "16(R7)"},
	{"(8)(g)", "8(g)"},
	{"(R0)", "(R0)"},
	{"(R3)", "(R3)"},
	{"(R4)", "(R4)"},
	{"(R5)", "(R5)"},
	{"-1(R4)", "-1(R4)"},
	{"-1(R5)", "-1(R5)"},
	{"6(PC)", "6(PC)"},
	{"F14", "F14"},
	{"F15", "F15"},
	{"F16", "F16"},
	{"F17", "F17"},
	{"F18", "F18"},
	{"F19", "F19"},
	{"F20", "F20"},
	{"F21", "F21"},
	{"F22", "F22"},
	{"F23", "F23"},
	{"F24", "F24"},
	{"F25", "F25"},
	{"F26", "F26"},
	{"F27", "F27"},
	{"F28", "F28"},
	{"F29", "F29"},
	{"F30", "F30"},
	{"F31", "F31"},
	{"R0", "R0"},
	{"R1", "R1"},
	{"R11", "R11"},
	{"R12", "R12"},
	{"R13", "R13"},
	{"R14", "R14"},
	{"R15", "R15"},
	{"R16", "R16"},
	{"R17", "R17"},
	{"R18", "R18"},
	{"R19", "R19"},
	{"R2", "R2"},
	{"R20", "R20"},
	{"R21", "R21"},
	{"R22", "R22"},
	{"R23", "R23"},
	{"R24", "R24"},
	{"R25", "R25"},
	{"R26", "R26"},
	{"R27", "R27"},
	{"R28", "R28"},
	{"R29", "R29"},
	{"R3", "R3"},
	{"R31", "R31"},
	{"R4", "R4"},
	{"R5", "R5"},
	{"R6", "R6"},
	{"R7", "R7"},
	{"R8", "R8"},
	{"R9", "R9"},
	{"LO", "LO"},
	{"a(FP)", "a(FP)"},
	{"g", "g"},
	{"ret+8(FP)", "ret+8(FP)"},
	{"runtime·abort(SB)", "runtime.abort(SB)"},
	{"·AddUint32(SB)", "pkg.AddUint32(SB)"},
	{"·trunc(SB)", "pkg.trunc(SB)"},
	{"[):[o-FP", ""}, // Issue 12469 - asm hung parsing the o-FP range on non ARM platforms.
}

var loong64OperandTests = []operandTest{
	{"$((1<<63)-1)", "$9223372036854775807"},
	{"$(-64*1024)", "$-65536"},
	{"$(1024 * 8)", "$8192"},
	{"$-1", "$-1"},
	{"$-24(R4)", "$-24(R4)"},
	{"$0", "$0"},
	{"$0(R1)", "$(R1)"},
	{"$0.5", "$(0.5)"},
	{"$0x7000", "$28672"},
	{"$0x88888eef", "$2290650863"},
	{"$1", "$1"},
	{"$_main<>(SB)", "$_main<>(SB)"},
	{"$argframe(FP)", "$argframe(FP)"},
	{"$~3", "$-4"},
	{"(-288-3*8)(R1)", "-312(R1)"},
	{"(16)(R7)", "16(R7)"},
	{"(8)(g)", "8(g)"},
	{"(R0)", "(R0)"},
	{"(R3)", "(R3)"},
	{"(R4)", "(R4)"},
	{"(R5)", "(R5)"},
	{"-1(R4)", "-1(R4)"},
	{"-1(R5)", "-1(R5)"},
	{"6(PC)", "6(PC)"},
	{"F14", "F14"},
	{"F15", "F15"},
	{"F16", "F16"},
	{"F17", "F17"},
	{"F18", "F18"},
	{"F19", "F19"},
	{"F20", "F20"},
	{"F21", "F21"},
	{"F22", "F22"},
	{"F23", "F23"},
	{"F24", "F24"},
	{"F25", "F25"},
	{"F26", "F26"},
	{"F27", "F27"},
	{"F28", "F28"},
	{"F29", "F29"},
	{"F30", "F30"},
	{"F31", "F31"},
	{"R0", "R0"},
	{"R1", "R1"},
	{"R11", "R11"},
	{"R12", "R12"},
	{"R13", "R13"},
	{"R14", "R14"},
	{"R15", "R15"},
	{"R16", "R16"},
	{"R17", "R17"},
	{"R18", "R18"},
	{"R19", "R19"},
	{"R2", "R2"},
	{"R20", "R20"},
	{"R21", "R21"},
	{"R23", "R23"},
	{"R24", "R24"},
	{"R25", "R25"},
	{"R26", "R26"},
	{"R27", "R27"},
	{"R28", "R28"},
	{"R29", "R29"},
	{"R3", "R3"},
	{"R30", "R30"},
	{"R31", "R31"},
	{"R4", "R4"},
	{"R5", "R5"},
	{"R6", "R6"},
	{"R7", "R7"},
	{"R8", "R8"},
	{"R9", "R9"},
	{"a(FP)", "a(FP)"},
	{"g", "g"},
	{"ret+8(FP)", "ret+8(FP)"},
	{"runtime·abort(SB)", "runtime.abort(SB)"},
	{"·AddUint32(SB)", "pkg.AddUint32(SB)"},
	{"·trunc(SB)", "pkg.trunc(SB)"},
	{"[):[o-FP", ""}, // Issue 12469 - asm hung parsing the o-FP range on non ARM platforms.
}

var s390xOperandTests = []operandTest{
	{"$((1<<63)-1)", "$9223372036854775807"},
	{"$(-64*1024)", "$-65536"},
	{"$(1024 * 8)", "$8192"},
	{"$-1", "$-1"},
	{"$-24(R4)", "$-24(R4)"},
	{"$0", "$0"},
	{"$0(R1)", "$(R1)"},
	{"$0.5", "$(0.5)"},
	{"$0x7000", "$28672"},
	{"$0x88888eef", "$2290650863"},
	{"$1", "$1"},
	{"$_main<>(SB)", "$_main<>(SB)"},
	{"$argframe(FP)", "$argframe(FP)"},
	{"$~3", "$-4"},
	{"(-288-3*8)(R1)", "-312(R1)"},
	{"(16)(R7)", "16(R7)"},
	{"(8)(g)", "8(g)"},
	{"(R0)", "(R0)"},
	{"(R3)", "(R3)"},
	{"(R4)", "(R4)"},
	{"(R5)", "(R5)"},
	{"-1(R4)", "-1(R4)"},
	{"-1(R5)", "-1(R5)"},
	{"6(PC)", "6(PC)"},
	{"R0", "R0"},
	{"R1", "R1"},
	{"R2", "R2"},
	{"R3", "R3"},
	{"R4", "R4"},
	{"R5", "R5"},
	{"R6", "R6"},
	{"R7", "R7"},
	{"R8", "R8"},
	{"R9", "R9"},
	{"R10", "R10"},
	{"R11", "R11"},
	{"R12", "R12"},
	// {"R13", "R13"}, R13 is g
	{"R14", "R14"},
	{"R15", "R15"},
	{"F0", "F0"},
	{"F1", "F1"},
	{"F2", "F2"},
	{"F3", "F3"},
	{"F4", "F4"},
	{"F5", "F5"},
	{"F6", "F6"},
	{"F7", "F7"},
	{"F8", "F8"},
	{"F9", "F9"},
	{"F10", "F10"},
	{"F11", "F11"},
	{"F12", "F12"},
	{"F13", "F13"},
	{"F14", "F14"},
	{"F15", "F15"},
	{"V0", "V0"},
	{"V1", "V1"},
	{"V2", "V2"},
	{"V3", "V3"},
	{"V4", "V4"},
	{"V5", "V5"},
	{"V6", "V6"},
	{"V7", "V7"},
	{"V8", "V8"},
	{"V9", "V9"},
	{"V10", "V10"},
	{"V11", "V11"},
	{"V12", "V12"},
	{"V13", "V13"},
	{"V14", "V14"},
	{"V15", "V15"},
	{"V16", "V16"},
	{"V17", "V17"},
	{"V18", "V18"},
	{"V19", "V19"},
	{"V20", "V20"},
	{"V21", "V21"},
	{"V22", "V22"},
	{"V23", "V23"},
	{"V24", "V24"},
	{"V25", "V25"},
	{"V26", "V26"},
	{"V27", "V27"},
	{"V28", "V28"},
	{"V29", "V29"},
	{"V30", "V30"},
	{"V31", "V31"},
	{"a(FP)", "a(FP)"},
	{"g", "g"},
	{"ret+8(FP)", "ret+8(FP)"},
	{"runtime·abort(SB)", "runtime.abort(SB)"},
	{"·AddUint32(SB)", "pkg.AddUint32(SB)"},
	{"·trunc(SB)", "pkg.trunc(SB)"},
	{"[):[o-FP", ""}, // Issue 12469 - asm hung parsing the o-FP range on non ARM platforms.
}

"""



```