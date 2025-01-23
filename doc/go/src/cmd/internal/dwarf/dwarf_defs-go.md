Response: Let's break down the thought process for analyzing this Go code snippet related to DWARF debugging information.

1. **Initial Understanding: What is DWARF?** The comments at the top clearly state that this code is derived from the DWARF standard. My first step is to recall what DWARF is. It's a debugging data format used by compilers and debuggers to provide information about the compiled program, like variable types, function locations, source file information, etc. This immediately tells me this code isn't directly involved in the *execution* of Go programs but rather in the *metadata* about them.

2. **Code Structure: Constants and Tables.**  Scanning the code, I see a series of `const` declarations with names like `DW_TAG_...`, `DW_CHILDREN_...`, `DW_AT_...`, `DW_FORM_...`, etc. The comments alongside these constants often refer to "Table X" from the DWARF specification. This strongly suggests that this file is a direct representation of various enumerations and tables defined within the DWARF standard.

3. **Purpose Identification: Defining DWARF Entities.**  The names of the constants give strong hints about their purpose. For example:
    * `DW_TAG_array_type`:  Clearly identifies a Debugging Information Entry (DIE) representing an array type.
    * `DW_AT_location`: Represents an attribute of a DIE that specifies the location of a variable or code.
    * `DW_FORM_addr`: Defines the format of an address attribute.
    * `DW_OP_addr`:  An operation code used in DWARF expressions.

    The pattern is clear: this file defines the numeric codes and symbolic names for various DWARF entities (tags, attributes, forms, opcodes, etc.).

4. **Functionality: Enabling DWARF Handling.** Knowing that this file defines the *vocabulary* of DWARF, I can infer its function:  It provides the necessary constants for Go programs (specifically tools like debuggers, profilers, or code analysis tools) to interpret and generate DWARF debugging information. Without these constants, the tools wouldn't know what the numeric values in the DWARF data mean.

5. **Go Feature Realization: Debugging and Reflection.** DWARF is fundamentally linked to debugging. It allows debuggers like `gdb` or Go's built-in debugger to understand the program's structure and state. It's also used, in a less direct way, by reflection mechanisms (though Go's reflection doesn't directly parse DWARF at runtime). However, the DWARF information is generated *during compilation*, so the `cmd/compile` package likely uses these constants.

6. **Go Code Example (Conceptual):** Since this file defines *constants*, it's used by other parts of the Go toolchain. A concrete example would involve code that reads or writes DWARF data. I'd imagine code that constructs a DWARF "entry" and needs to specify its "tag" using one of these constants.

   ```go
   // Hypothetical code within the Go compiler or a DWARF manipulation tool
   package main

   import "fmt"
   import "cmd/internal/dwarf" // Assuming this package exists

   func main() {
       // Creating a Debugging Information Entry (DIE) for a variable
       dieTag := dwarf.DW_TAG_variable
       fmt.Printf("Creating a DIE with tag: 0x%X (%s)\n", dieTag, getTagName(dieTag))

       // Adding an attribute for the variable's name
       nameAttr := dwarf.DW_AT_name
       nameValue := "myVariable"
       fmt.Printf("Adding attribute: 0x%X (%s) with value: %s\n", nameAttr, getAttributeName(nameAttr), nameValue)
   }

   // Helper functions (not in the original file, but demonstrate usage)
   func getTagName(tag uint8) string {
       // ... (implementation to map the constant to its string representation)
       switch tag {
       case dwarf.DW_TAG_variable:
           return "DW_TAG_variable"
       // ... other cases
       default:
           return "Unknown Tag"
       }
   }

   func getAttributeName(attr uint8) string {
       // ... (implementation to map the constant to its string representation)
       switch attr {
       case dwarf.DW_AT_name:
           return "DW_AT_name"
       // ... other cases
       default:
           return "Unknown Attribute"
       }
   }
   ```
   **Input/Output (Hypothetical):**  This code wouldn't take direct user input. Its "output" is the *generation* of DWARF data (not shown in the example, but implied). The `fmt.Printf` calls are for demonstration.

7. **Command-line Arguments:** This file itself doesn't handle command-line arguments. It's a data definition file. However, tools that *use* these constants (like the Go compiler) would certainly have command-line options that influence DWARF generation (e.g., `-gcflags="-N -l"` to disable optimizations, which impacts DWARF).

8. **Common Mistakes:**  Since this is just a definition file, users wouldn't directly interact with it. Potential errors would occur in *other* code that *uses* these constants. For example:
    * **Mismatched Constants:** Using a constant from an older DWARF version when interacting with DWARF data of a newer version.
    * **Incorrect Interpretation:**  Misunderstanding the meaning of a particular tag or attribute. The comments referencing the DWARF standard are crucial here.

This systematic approach – understanding the domain (DWARF), analyzing the code structure (constants), inferring purpose, connecting to Go features, and considering usage and potential errors – allows for a comprehensive understanding of this seemingly simple but fundamentally important Go file.
这个 Go 语言源文件 `dwarf_defs.go` 的主要功能是**定义了 DWARF 调试信息格式中使用的各种常量**。它直接映射了 DWARF 标准中的各种表格，为 Go 语言的工具链（特别是编译器和链接器）提供了操作和生成 DWARF 调试信息的必要符号定义。

更具体地说，这个文件定义了以下几种类型的 DWARF 常量：

* **DW_TAG_**: 定义了 DWARF 调试信息条目 (Debugging Information Entry, DIE) 的各种类型，例如 `DW_TAG_array_type` 表示数组类型，`DW_TAG_subprogram` 表示子程序（函数）。
* **DW_CHILDREN_**: 定义了 DIE 是否可以拥有子条目的属性。
* **DW_CLS_**:  定义了 DWARF 属性值的类型分类，这是 Go 语言内部对 DWARF 属性值类型的抽象。
* **DW_AT_**: 定义了 DWARF 调试信息条目的各种属性，例如 `DW_AT_name` 表示名称，`DW_AT_location` 表示位置。
* **DW_FORM_**: 定义了 DWARF 属性值的编码格式，例如 `DW_FORM_addr` 表示地址，`DW_FORM_string` 表示字符串。
* **DW_OP_**: 定义了 DWARF 表达式中使用的操作码，用于描述更复杂的地址计算或值获取方式。
* **DW_ATE_**: 定义了基本类型编码，例如 `DW_ATE_signed` 表示有符号整数，`DW_ATE_float` 表示浮点数。
* **其他 DW_**:  定义了 DWARF 标准中其他枚举类型的常量，例如数据串格式、字节序、访问级别、可见性、虚拟性、语言等等。

**它是什么 Go 语言功能的实现？**

这个文件本身并不是一个直接实现特定 Go 语言功能的代码。它更像是一个**数据定义文件**，为 Go 语言的调试和工具链提供了基础的 DWARF 元数据。它的存在是为了让 Go 语言的工具能够理解和生成符合 DWARF 标准的调试信息。

更准确地说，这个文件是 Go 语言**调试信息生成**功能的基石。Go 编译器在编译代码时，会生成 DWARF 调试信息，这些信息被用于调试器（如 `gdb` 或 `dlv`）来帮助开发者理解程序的运行状态。这个文件中的常量被编译器用来标记和描述程序中的各种元素（变量、函数、类型等）。

**Go 代码举例说明:**

虽然我们不能直接在用户代码中使用这些常量，但可以想象在 Go 编译器的内部，或者在处理 DWARF 信息的工具中，会使用这些常量。

例如，假设 Go 编译器要生成一个表示整型变量的 DWARF 条目，可能会有类似这样的操作（这只是一个概念性的例子，并非实际编译器代码）：

```go
package main

import (
	"fmt"
	"go/src/cmd/internal/dwarf" // 假设编译器内部使用了这个包
)

func main() {
	// 假设要创建一个表示 int 类型变量的 DWARF 条目
	die := &DebugInfoEntry{
		Tag: dwarf.DW_TAG_variable,
		Attributes: []DebugInfoAttribute{
			{
				Name:  dwarf.DW_AT_name,
				Form:  dwarf.DW_FORM_string,
				Value: "myInteger",
			},
			{
				Name:  dwarf.DW_AT_type,
				Form:  dwarf.DW_FORM_ref4, // 引用到表示 int 类型的 DIE
				Value: uint32(0x1234),   // 假设 int 类型 DIE 的偏移量是 0x1234
			},
			{
				Name:  dwarf.DW_AT_location,
				Form:  dwarf.DW_FORM_block1,
				Value: []byte{dwarf.DW_OP_addr, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00}, // 假设变量地址
			},
		},
	}

	fmt.Printf("Created DIE with tag: 0x%X\n", die.Tag)
	for _, attr := range die.Attributes {
		fmt.Printf("  Attribute: 0x%X, Form: 0x%X, Value: %+v\n", attr.Name, attr.Form, attr.Value)
	}
}

// 假设的 DebugInfoEntry 和 DebugInfoAttribute 结构体
type DebugInfoEntry struct {
	Tag        uint16
	Attributes []DebugInfoAttribute
	Children   []*DebugInfoEntry
}

type DebugInfoAttribute struct {
	Name  uint16
	Form  uint8
	Value interface{}
}
```

**假设的输入与输出:**

上面的例子并没有实际的输入，它只是在内存中构建 DWARF 数据结构。输出将会是打印出的 DWARF 条目的标签和属性信息。

**命令行参数的具体处理:**

这个 `dwarf_defs.go` 文件本身不处理命令行参数。然而，使用这些常量的工具，例如 Go 编译器 (`go build`)，会通过命令行参数来控制 DWARF 信息的生成。

例如，使用 `-gcflags` 选项可以向 Go 编译器传递参数来控制 DWARF 信息的详细程度：

* **`-gcflags "-N"`**: 禁用优化。禁用优化通常会生成更完整和准确的 DWARF 信息，因为变量不会被优化掉或重命名。
* **`-gcflags "-l"`**: 禁用内联。禁用内联可以帮助调试器更准确地定位代码执行位置。
* **`-gcflags "-dwarf=5"`**:  指定生成 DWARF 版本 5 的信息 (Go 1.20 及更高版本)。

**使用者易犯错的点:**

由于 `dwarf_defs.go` 主要是给工具使用的，普通 Go 开发者不会直接与其交互，因此不容易犯错。但是，如果有人尝试手动解析或生成 DWARF 信息，可能会犯以下错误：

1. **使用了错误的常量值：** DWARF 标准有多个版本，不同版本的常量值可能不同。如果使用了与目标 DWARF 信息版本不符的常量，会导致解析错误。例如，使用了 DWARF 3 的 `DW_TAG_namespace` 常量去解析一个 DWARF 2 的信息。

2. **误解了常量的含义：** DWARF 标准非常复杂，每个常量都有其特定的含义和用法。如果误解了某个常量的含义，可能会导致生成的 DWARF 信息不正确，或者解析 DWARF 信息时得到错误的结论。例如，混淆了 `DW_AT_location` 和 `DW_AT_data_member_location` 的用途。

3. **没有考虑到 DWARF 表达式的操作码：**  某些属性的值可能是一个 DWARF 表达式，由一系列操作码组成。如果只是简单地将这些字节解释为地址或其他值，而没有理解操作码的含义，就会得到错误的结果。

总而言之，`dwarf_defs.go` 是 Go 语言工具链中一个至关重要的文件，它提供了操作 DWARF 调试信息的基础词汇表，使得 Go 语言的调试功能得以实现。 普通开发者不需要直接关心这个文件，但理解它的作用有助于更深入地理解 Go 语言的编译和调试过程。

### 提示词
```
这是路径为go/src/cmd/internal/dwarf/dwarf_defs.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```go
// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dwarf

// Cut, pasted, tr-and-awk'ed from tables in
// http://dwarfstd.org/doc/Dwarf3.pdf

// Table 18
const (
	DW_TAG_array_type               = 0x01
	DW_TAG_class_type               = 0x02
	DW_TAG_entry_point              = 0x03
	DW_TAG_enumeration_type         = 0x04
	DW_TAG_formal_parameter         = 0x05
	DW_TAG_imported_declaration     = 0x08
	DW_TAG_label                    = 0x0a
	DW_TAG_lexical_block            = 0x0b
	DW_TAG_member                   = 0x0d
	DW_TAG_pointer_type             = 0x0f
	DW_TAG_reference_type           = 0x10
	DW_TAG_compile_unit             = 0x11
	DW_TAG_string_type              = 0x12
	DW_TAG_structure_type           = 0x13
	DW_TAG_subroutine_type          = 0x15
	DW_TAG_typedef                  = 0x16
	DW_TAG_union_type               = 0x17
	DW_TAG_unspecified_parameters   = 0x18
	DW_TAG_variant                  = 0x19
	DW_TAG_common_block             = 0x1a
	DW_TAG_common_inclusion         = 0x1b
	DW_TAG_inheritance              = 0x1c
	DW_TAG_inlined_subroutine       = 0x1d
	DW_TAG_module                   = 0x1e
	DW_TAG_ptr_to_member_type       = 0x1f
	DW_TAG_set_type                 = 0x20
	DW_TAG_subrange_type            = 0x21
	DW_TAG_with_stmt                = 0x22
	DW_TAG_access_declaration       = 0x23
	DW_TAG_base_type                = 0x24
	DW_TAG_catch_block              = 0x25
	DW_TAG_const_type               = 0x26
	DW_TAG_constant                 = 0x27
	DW_TAG_enumerator               = 0x28
	DW_TAG_file_type                = 0x29
	DW_TAG_friend                   = 0x2a
	DW_TAG_namelist                 = 0x2b
	DW_TAG_namelist_item            = 0x2c
	DW_TAG_packed_type              = 0x2d
	DW_TAG_subprogram               = 0x2e
	DW_TAG_template_type_parameter  = 0x2f
	DW_TAG_template_value_parameter = 0x30
	DW_TAG_thrown_type              = 0x31
	DW_TAG_try_block                = 0x32
	DW_TAG_variant_part             = 0x33
	DW_TAG_variable                 = 0x34
	DW_TAG_volatile_type            = 0x35
	// Dwarf3
	DW_TAG_dwarf_procedure  = 0x36
	DW_TAG_restrict_type    = 0x37
	DW_TAG_interface_type   = 0x38
	DW_TAG_namespace        = 0x39
	DW_TAG_imported_module  = 0x3a
	DW_TAG_unspecified_type = 0x3b
	DW_TAG_partial_unit     = 0x3c
	DW_TAG_imported_unit    = 0x3d
	DW_TAG_condition        = 0x3f
	DW_TAG_shared_type      = 0x40
	// Dwarf4
	DW_TAG_type_unit             = 0x41
	DW_TAG_rvalue_reference_type = 0x42
	DW_TAG_template_alias        = 0x43

	// User defined
	DW_TAG_lo_user = 0x4080
	DW_TAG_hi_user = 0xffff
)

// Table 19
const (
	DW_CHILDREN_no  = 0x00
	DW_CHILDREN_yes = 0x01
)

// Not from the spec, but logically belongs here
const (
	DW_CLS_ADDRESS = 0x01 + iota
	DW_CLS_BLOCK
	DW_CLS_CONSTANT
	DW_CLS_FLAG
	DW_CLS_PTR // lineptr, loclistptr, macptr, rangelistptr
	DW_CLS_REFERENCE
	DW_CLS_ADDRLOC
	DW_CLS_STRING

	// Go-specific internal hackery.
	DW_CLS_GO_TYPEREF
)

// Table 20
const (
	DW_AT_sibling              = 0x01 // reference
	DW_AT_location             = 0x02 // block, loclistptr
	DW_AT_name                 = 0x03 // string
	DW_AT_ordering             = 0x09 // constant
	DW_AT_byte_size            = 0x0b // block, constant, reference
	DW_AT_bit_offset           = 0x0c // block, constant, reference
	DW_AT_bit_size             = 0x0d // block, constant, reference
	DW_AT_stmt_list            = 0x10 // lineptr
	DW_AT_low_pc               = 0x11 // address
	DW_AT_high_pc              = 0x12 // address
	DW_AT_language             = 0x13 // constant
	DW_AT_discr                = 0x15 // reference
	DW_AT_discr_value          = 0x16 // constant
	DW_AT_visibility           = 0x17 // constant
	DW_AT_import               = 0x18 // reference
	DW_AT_string_length        = 0x19 // block, loclistptr
	DW_AT_common_reference     = 0x1a // reference
	DW_AT_comp_dir             = 0x1b // string
	DW_AT_const_value          = 0x1c // block, constant, string
	DW_AT_containing_type      = 0x1d // reference
	DW_AT_default_value        = 0x1e // reference
	DW_AT_inline               = 0x20 // constant
	DW_AT_is_optional          = 0x21 // flag
	DW_AT_lower_bound          = 0x22 // block, constant, reference
	DW_AT_producer             = 0x25 // string
	DW_AT_prototyped           = 0x27 // flag
	DW_AT_return_addr          = 0x2a // block, loclistptr
	DW_AT_start_scope          = 0x2c // constant
	DW_AT_bit_stride           = 0x2e // constant
	DW_AT_upper_bound          = 0x2f // block, constant, reference
	DW_AT_abstract_origin      = 0x31 // reference
	DW_AT_accessibility        = 0x32 // constant
	DW_AT_address_class        = 0x33 // constant
	DW_AT_artificial           = 0x34 // flag
	DW_AT_base_types           = 0x35 // reference
	DW_AT_calling_convention   = 0x36 // constant
	DW_AT_count                = 0x37 // block, constant, reference
	DW_AT_data_member_location = 0x38 // block, constant, loclistptr
	DW_AT_decl_column          = 0x39 // constant
	DW_AT_decl_file            = 0x3a // constant
	DW_AT_decl_line            = 0x3b // constant
	DW_AT_declaration          = 0x3c // flag
	DW_AT_discr_list           = 0x3d // block
	DW_AT_encoding             = 0x3e // constant
	DW_AT_external             = 0x3f // flag
	DW_AT_frame_base           = 0x40 // block, loclistptr
	DW_AT_friend               = 0x41 // reference
	DW_AT_identifier_case      = 0x42 // constant
	DW_AT_macro_info           = 0x43 // macptr
	DW_AT_namelist_item        = 0x44 // block
	DW_AT_priority             = 0x45 // reference
	DW_AT_segment              = 0x46 // block, loclistptr
	DW_AT_specification        = 0x47 // reference
	DW_AT_static_link          = 0x48 // block, loclistptr
	DW_AT_type                 = 0x49 // reference
	DW_AT_use_location         = 0x4a // block, loclistptr
	DW_AT_variable_parameter   = 0x4b // flag
	DW_AT_virtuality           = 0x4c // constant
	DW_AT_vtable_elem_location = 0x4d // block, loclistptr
	// Dwarf3
	DW_AT_allocated      = 0x4e // block, constant, reference
	DW_AT_associated     = 0x4f // block, constant, reference
	DW_AT_data_location  = 0x50 // block
	DW_AT_byte_stride    = 0x51 // block, constant, reference
	DW_AT_entry_pc       = 0x52 // address
	DW_AT_use_UTF8       = 0x53 // flag
	DW_AT_extension      = 0x54 // reference
	DW_AT_ranges         = 0x55 // rangelistptr
	DW_AT_trampoline     = 0x56 // address, flag, reference, string
	DW_AT_call_column    = 0x57 // constant
	DW_AT_call_file      = 0x58 // constant
	DW_AT_call_line      = 0x59 // constant
	DW_AT_description    = 0x5a // string
	DW_AT_binary_scale   = 0x5b // constant
	DW_AT_decimal_scale  = 0x5c // constant
	DW_AT_small          = 0x5d // reference
	DW_AT_decimal_sign   = 0x5e // constant
	DW_AT_digit_count    = 0x5f // constant
	DW_AT_picture_string = 0x60 // string
	DW_AT_mutable        = 0x61 // flag
	DW_AT_threads_scaled = 0x62 // flag
	DW_AT_explicit       = 0x63 // flag
	DW_AT_object_pointer = 0x64 // reference
	DW_AT_endianity      = 0x65 // constant
	DW_AT_elemental      = 0x66 // flag
	DW_AT_pure           = 0x67 // flag
	DW_AT_recursive      = 0x68 // flag

	DW_AT_lo_user = 0x2000 // ---
	DW_AT_hi_user = 0x3fff // ---
)

// Table 21
const (
	DW_FORM_addr      = 0x01 // address
	DW_FORM_block2    = 0x03 // block
	DW_FORM_block4    = 0x04 // block
	DW_FORM_data2     = 0x05 // constant
	DW_FORM_data4     = 0x06 // constant, lineptr, loclistptr, macptr, rangelistptr
	DW_FORM_data8     = 0x07 // constant, lineptr, loclistptr, macptr, rangelistptr
	DW_FORM_string    = 0x08 // string
	DW_FORM_block     = 0x09 // block
	DW_FORM_block1    = 0x0a // block
	DW_FORM_data1     = 0x0b // constant
	DW_FORM_flag      = 0x0c // flag
	DW_FORM_sdata     = 0x0d // constant
	DW_FORM_strp      = 0x0e // string
	DW_FORM_udata     = 0x0f // constant
	DW_FORM_ref_addr  = 0x10 // reference
	DW_FORM_ref1      = 0x11 // reference
	DW_FORM_ref2      = 0x12 // reference
	DW_FORM_ref4      = 0x13 // reference
	DW_FORM_ref8      = 0x14 // reference
	DW_FORM_ref_udata = 0x15 // reference
	DW_FORM_indirect  = 0x16 // (see Section 7.5.3)
	// Dwarf4
	DW_FORM_sec_offset   = 0x17 // lineptr, loclistptr, macptr, rangelistptr
	DW_FORM_exprloc      = 0x18 // exprloc
	DW_FORM_flag_present = 0x19 // flag
	DW_FORM_ref_sig8     = 0x20 // reference
	// Pseudo-form: expanded to data4 on IOS, udata elsewhere.
	DW_FORM_udata_pseudo = 0x99
)

// Table 24 (#operands, notes)
const (
	DW_OP_addr                = 0x03 // 1 constant address (size target specific)
	DW_OP_deref               = 0x06 // 0
	DW_OP_const1u             = 0x08 // 1 1-byte constant
	DW_OP_const1s             = 0x09 // 1 1-byte constant
	DW_OP_const2u             = 0x0a // 1 2-byte constant
	DW_OP_const2s             = 0x0b // 1 2-byte constant
	DW_OP_const4u             = 0x0c // 1 4-byte constant
	DW_OP_const4s             = 0x0d // 1 4-byte constant
	DW_OP_const8u             = 0x0e // 1 8-byte constant
	DW_OP_const8s             = 0x0f // 1 8-byte constant
	DW_OP_constu              = 0x10 // 1 ULEB128 constant
	DW_OP_consts              = 0x11 // 1 SLEB128 constant
	DW_OP_dup                 = 0x12 // 0
	DW_OP_drop                = 0x13 // 0
	DW_OP_over                = 0x14 // 0
	DW_OP_pick                = 0x15 // 1 1-byte stack index
	DW_OP_swap                = 0x16 // 0
	DW_OP_rot                 = 0x17 // 0
	DW_OP_xderef              = 0x18 // 0
	DW_OP_abs                 = 0x19 // 0
	DW_OP_and                 = 0x1a // 0
	DW_OP_div                 = 0x1b // 0
	DW_OP_minus               = 0x1c // 0
	DW_OP_mod                 = 0x1d // 0
	DW_OP_mul                 = 0x1e // 0
	DW_OP_neg                 = 0x1f // 0
	DW_OP_not                 = 0x20 // 0
	DW_OP_or                  = 0x21 // 0
	DW_OP_plus                = 0x22 // 0
	DW_OP_plus_uconst         = 0x23 // 1 ULEB128 addend
	DW_OP_shl                 = 0x24 // 0
	DW_OP_shr                 = 0x25 // 0
	DW_OP_shra                = 0x26 // 0
	DW_OP_xor                 = 0x27 // 0
	DW_OP_skip                = 0x2f // 1 signed 2-byte constant
	DW_OP_bra                 = 0x28 // 1 signed 2-byte constant
	DW_OP_eq                  = 0x29 // 0
	DW_OP_ge                  = 0x2a // 0
	DW_OP_gt                  = 0x2b // 0
	DW_OP_le                  = 0x2c // 0
	DW_OP_lt                  = 0x2d // 0
	DW_OP_ne                  = 0x2e // 0
	DW_OP_lit0                = 0x30 // 0 ...
	DW_OP_lit31               = 0x4f // 0 literals 0..31 = (DW_OP_lit0 + literal)
	DW_OP_reg0                = 0x50 // 0 ..
	DW_OP_reg31               = 0x6f // 0 reg 0..31 = (DW_OP_reg0 + regnum)
	DW_OP_breg0               = 0x70 // 1 ...
	DW_OP_breg31              = 0x8f // 1 SLEB128 offset base register 0..31 = (DW_OP_breg0 + regnum)
	DW_OP_regx                = 0x90 // 1 ULEB128 register
	DW_OP_fbreg               = 0x91 // 1 SLEB128 offset
	DW_OP_bregx               = 0x92 // 2 ULEB128 register followed by SLEB128 offset
	DW_OP_piece               = 0x93 // 1 ULEB128 size of piece addressed
	DW_OP_deref_size          = 0x94 // 1 1-byte size of data retrieved
	DW_OP_xderef_size         = 0x95 // 1 1-byte size of data retrieved
	DW_OP_nop                 = 0x96 // 0
	DW_OP_push_object_address = 0x97 // 0
	DW_OP_call2               = 0x98 // 1 2-byte offset of DIE
	DW_OP_call4               = 0x99 // 1 4-byte offset of DIE
	DW_OP_call_ref            = 0x9a // 1 4- or 8-byte offset of DIE
	DW_OP_form_tls_address    = 0x9b // 0
	DW_OP_call_frame_cfa      = 0x9c // 0
	DW_OP_bit_piece           = 0x9d // 2
	DW_OP_lo_user             = 0xe0
	DW_OP_hi_user             = 0xff
)

// Table 25
const (
	DW_ATE_address         = 0x01
	DW_ATE_boolean         = 0x02
	DW_ATE_complex_float   = 0x03
	DW_ATE_float           = 0x04
	DW_ATE_signed          = 0x05
	DW_ATE_signed_char     = 0x06
	DW_ATE_unsigned        = 0x07
	DW_ATE_unsigned_char   = 0x08
	DW_ATE_imaginary_float = 0x09
	DW_ATE_packed_decimal  = 0x0a
	DW_ATE_numeric_string  = 0x0b
	DW_ATE_edited          = 0x0c
	DW_ATE_signed_fixed    = 0x0d
	DW_ATE_unsigned_fixed  = 0x0e
	DW_ATE_decimal_float   = 0x0f
	DW_ATE_lo_user         = 0x80
	DW_ATE_hi_user         = 0xff
)

// Table 26
const (
	DW_DS_unsigned           = 0x01
	DW_DS_leading_overpunch  = 0x02
	DW_DS_trailing_overpunch = 0x03
	DW_DS_leading_separate   = 0x04
	DW_DS_trailing_separate  = 0x05
)

// Table 27
const (
	DW_END_default = 0x00
	DW_END_big     = 0x01
	DW_END_little  = 0x02
	DW_END_lo_user = 0x40
	DW_END_hi_user = 0xff
)

// Table 28
const (
	DW_ACCESS_public    = 0x01
	DW_ACCESS_protected = 0x02
	DW_ACCESS_private   = 0x03
)

// Table 29
const (
	DW_VIS_local     = 0x01
	DW_VIS_exported  = 0x02
	DW_VIS_qualified = 0x03
)

// Table 30
const (
	DW_VIRTUALITY_none         = 0x00
	DW_VIRTUALITY_virtual      = 0x01
	DW_VIRTUALITY_pure_virtual = 0x02
)

// Table 31
const (
	DW_LANG_C89         = 0x0001
	DW_LANG_C           = 0x0002
	DW_LANG_Ada83       = 0x0003
	DW_LANG_C_plus_plus = 0x0004
	DW_LANG_Cobol74     = 0x0005
	DW_LANG_Cobol85     = 0x0006
	DW_LANG_Fortran77   = 0x0007
	DW_LANG_Fortran90   = 0x0008
	DW_LANG_Pascal83    = 0x0009
	DW_LANG_Modula2     = 0x000a
	// Dwarf3
	DW_LANG_Java           = 0x000b
	DW_LANG_C99            = 0x000c
	DW_LANG_Ada95          = 0x000d
	DW_LANG_Fortran95      = 0x000e
	DW_LANG_PLI            = 0x000f
	DW_LANG_ObjC           = 0x0010
	DW_LANG_ObjC_plus_plus = 0x0011
	DW_LANG_UPC            = 0x0012
	DW_LANG_D              = 0x0013
	// Dwarf4
	DW_LANG_Python = 0x0014
	// Dwarf5
	DW_LANG_Go = 0x0016

	DW_LANG_lo_user = 0x8000
	DW_LANG_hi_user = 0xffff
)

// Table 32
const (
	DW_ID_case_sensitive   = 0x00
	DW_ID_up_case          = 0x01
	DW_ID_down_case        = 0x02
	DW_ID_case_insensitive = 0x03
)

// Table 33
const (
	DW_CC_normal  = 0x01
	DW_CC_program = 0x02
	DW_CC_nocall  = 0x03
	DW_CC_lo_user = 0x40
	DW_CC_hi_user = 0xff
)

// Table 34
const (
	DW_INL_not_inlined          = 0x00
	DW_INL_inlined              = 0x01
	DW_INL_declared_not_inlined = 0x02
	DW_INL_declared_inlined     = 0x03
)

// Table 35
const (
	DW_ORD_row_major = 0x00
	DW_ORD_col_major = 0x01
)

// Table 36
const (
	DW_DSC_label = 0x00
	DW_DSC_range = 0x01
)

// Table 37
const (
	DW_LNS_copy             = 0x01
	DW_LNS_advance_pc       = 0x02
	DW_LNS_advance_line     = 0x03
	DW_LNS_set_file         = 0x04
	DW_LNS_set_column       = 0x05
	DW_LNS_negate_stmt      = 0x06
	DW_LNS_set_basic_block  = 0x07
	DW_LNS_const_add_pc     = 0x08
	DW_LNS_fixed_advance_pc = 0x09
	// Dwarf3
	DW_LNS_set_prologue_end   = 0x0a
	DW_LNS_set_epilogue_begin = 0x0b
	DW_LNS_set_isa            = 0x0c
)

// Table 38
const (
	DW_LNE_end_sequence = 0x01
	DW_LNE_set_address  = 0x02
	DW_LNE_define_file  = 0x03
	DW_LNE_lo_user      = 0x80
	DW_LNE_hi_user      = 0xff
)

// Table 39
const (
	DW_MACINFO_define     = 0x01
	DW_MACINFO_undef      = 0x02
	DW_MACINFO_start_file = 0x03
	DW_MACINFO_end_file   = 0x04
	DW_MACINFO_vendor_ext = 0xff
)

// Table 40.
const (
	// operand,...
	DW_CFA_nop              = 0x00
	DW_CFA_set_loc          = 0x01 // address
	DW_CFA_advance_loc1     = 0x02 // 1-byte delta
	DW_CFA_advance_loc2     = 0x03 // 2-byte delta
	DW_CFA_advance_loc4     = 0x04 // 4-byte delta
	DW_CFA_offset_extended  = 0x05 // ULEB128 register, ULEB128 offset
	DW_CFA_restore_extended = 0x06 // ULEB128 register
	DW_CFA_undefined        = 0x07 // ULEB128 register
	DW_CFA_same_value       = 0x08 // ULEB128 register
	DW_CFA_register         = 0x09 // ULEB128 register, ULEB128 register
	DW_CFA_remember_state   = 0x0a
	DW_CFA_restore_state    = 0x0b

	DW_CFA_def_cfa            = 0x0c // ULEB128 register, ULEB128 offset
	DW_CFA_def_cfa_register   = 0x0d // ULEB128 register
	DW_CFA_def_cfa_offset     = 0x0e // ULEB128 offset
	DW_CFA_def_cfa_expression = 0x0f // BLOCK
	DW_CFA_expression         = 0x10 // ULEB128 register, BLOCK
	DW_CFA_offset_extended_sf = 0x11 // ULEB128 register, SLEB128 offset
	DW_CFA_def_cfa_sf         = 0x12 // ULEB128 register, SLEB128 offset
	DW_CFA_def_cfa_offset_sf  = 0x13 // SLEB128 offset
	DW_CFA_val_offset         = 0x14 // ULEB128, ULEB128
	DW_CFA_val_offset_sf      = 0x15 // ULEB128, SLEB128
	DW_CFA_val_expression     = 0x16 // ULEB128, BLOCK

	DW_CFA_lo_user = 0x1c
	DW_CFA_hi_user = 0x3f

	// Opcodes that take an addend operand.
	DW_CFA_advance_loc = 0x1 << 6 // +delta
	DW_CFA_offset      = 0x2 << 6 // +register (ULEB128 offset)
	DW_CFA_restore     = 0x3 << 6 // +register
)
```