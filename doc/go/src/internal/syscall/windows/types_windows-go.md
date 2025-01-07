Response:
我的目标是理解并解释给定的 Go 代码片段的功能，并尽可能推断其在高层 Go 功能中的作用。以下是我的思考过程：

1. **代码初步浏览：** 我首先快速浏览代码，注意到它定义了大量的常量和结构体。这些常量通常以 `FILE_`, `TCP_`, `OBJ_`, `DELETE`, `READ_CONTROL` 等前缀开头，结构体则命名为 `ACL`, `IO_STATUS_BLOCK`, `OBJECT_ATTRIBUTES` 等。这强烈暗示了这段代码是与 Windows 系统底层交互相关的。

2. **识别关键命名模式:**  `syscall` 包的导入以及常量和结构体的命名方式（例如 `FILE_READ_DATA`, `OBJECT_ATTRIBUTES`）都指向 Windows API。 这很可能是在 Go 的 `syscall` 包内部使用的，用于封装底层的 Windows 系统调用。

3. **理解常量的含义:** 我注意到 `TCP_KEEPIDLE`, `TCP_KEEPCNT`, `TCP_KEEPINTVL` 这些常量通常与 TCP keep-alive 机制相关。 而以 `FILE_` 开头的常量（例如 `FILE_READ_DATA`, `FILE_WRITE_DATA`, `FILE_SHARE_READ`）明显与文件操作的权限、属性和共享模式有关。  `OBJ_` 开头的常量很可能与对象属性相关，而 `DELETE`, `READ_CONTROL` 等则与访问控制权限相关。

4. **分析结构体的作用:**
    * `ACL` (Access Control List):  显然与访问控制列表相关，用于描述资源的访问权限。
    * `IO_STATUS_BLOCK`:  这个结构体通常用于异步 I/O 操作，用于返回操作的状态和信息。
    * `OBJECT_ATTRIBUTES`:  这个结构体包含了创建或打开对象（如文件）所需的各种属性，例如名称、根目录、安全描述符等。 `init` 方法进一步证实了这一点，它负责初始化 `ObjectName` 和 `RootDirectory`。
    * `SECURITY_DESCRIPTOR`:  这是一个更复杂的结构体，用于描述对象的安全属性，包括所有者、组、DACL 和 SACL。
    * `SECURITY_QUALITY_OF_SERVICE`:  这个结构体定义了与安全相关的服务质量参数，例如模拟级别。
    * `FILE_DISPOSITION_INFORMATION` 和 `FILE_DISPOSITION_INFORMATION_EX`:  这些结构体用于指定文件删除行为，例如是否在关闭时删除。

5. **推断功能领域:** 基于上述分析，我推断这段代码主要涉及以下几个方面：
    * **网络编程 (TCP Keep-Alive):** `TCP_KEEPIDLE` 等常量表明对 TCP 连接保活机制的支持。
    * **文件系统操作:** 大量的 `FILE_` 开头的常量和相关的结构体表明了对文件创建、打开、权限控制、属性设置等操作的支持。
    * **安全和访问控制:** `ACL`, `SECURITY_DESCRIPTOR`, `OBJECT_ATTRIBUTES` 以及 `DELETE`, `READ_CONTROL` 等常量都指向 Windows 的安全模型。

6. **尝试关联到 Go 功能:**  考虑到代码位于 `internal/syscall/windows` 路径下，我意识到这部分代码是 Go 标准库中 `syscall` 包的一部分，专门用于处理 Windows 平台的系统调用。  它为 Go 程序提供了访问底层 Windows API 的能力，例如创建文件、打开网络连接、设置文件权限等。

7. **代码举例和推理:**
    * **文件操作:**  我可以想到 Go 的 `os` 包中的 `Create`, `Open`, `OpenFile` 函数，这些函数最终会调用底层的 Windows API。  我可以使用 `OpenFile` 函数，并结合 `FILE_GENERIC_READ` 和 `FILE_SHARE_READ` 等常量来演示如何使用这些常量。
    * **网络编程:**  Go 的 `net` 包提供了网络编程的功能。  我可以尝试使用 `net.Dial` 创建一个 TCP 连接，并假设可以使用这里的 `TCP_KEEPIDLE` 等常量来配置 keep-alive 行为（尽管 `net` 包通常会提供更高级别的抽象）。

8. **易错点思考:**  由于这些常量是底层的 Windows API 定义，直接使用它们可能不如使用 Go 标准库提供的更高级别的抽象安全且方便。  直接操作这些常量需要对 Windows API 有深入的理解，容易出错。 例如，错误地组合权限标志可能导致安全漏洞或者程序行为异常。

9. **组织答案:** 最后，我将我的分析组织成清晰的中文答案，包括功能列表、Go 代码示例（带有假设的输入输出）、功能推断、以及易错点说明。我力求用易于理解的语言解释复杂的概念。

通过以上思考过程，我能够从给定的代码片段中提取出关键信息，并将其与 Go 的相关功能联系起来，最终形成了一个较为全面的解释。

这段 Go 语言代码文件 `go/src/internal/syscall/windows/types_windows.go` 的主要功能是**定义了在 Windows 系统调用中使用的各种常量、类型和结构体**。这些定义直接映射到 Windows API 的数据结构和标志位，为 Go 程序与底层 Windows 系统交互提供了必要的类型信息。

具体来说，这个文件包含了以下几个方面的定义：

**1. Socket 相关常量:**

* `TCP_KEEPIDLE`, `TCP_KEEPCNT`, `TCP_KEEPINTVL`: 这些常量用于配置 TCP socket 的 keep-alive 机制。它们分别代表了连接在发送 keep-alive 探测之前的空闲时间、探测失败的最大次数以及探测之间的时间间隔。

**2. 文件操作相关的常量:**

* **访问权限 (`FILE_READ_DATA`, `FILE_WRITE_DATA`, `FILE_EXECUTE` 等):** 定义了对文件进行读取、写入、执行等操作的权限标志。
* **组合的通用权限 (`FILE_GENERIC_READ`, `FILE_GENERIC_WRITE`, `FILE_GENERIC_EXECUTE`):**  将常用的基本权限组合在一起，方便使用。例如，`FILE_GENERIC_READ` 包含了读取数据、属性和扩展属性的权限。
* **目录操作权限 (`FILE_LIST_DIRECTORY`, `FILE_TRAVERSE`):** 定义了对目录进行列表和遍历的权限。
* **共享模式 (`FILE_SHARE_READ`, `FILE_SHARE_WRITE`, `FILE_SHARE_DELETE`):** 定义了在多个进程间共享文件的方式，例如是否允许其他进程读取、写入或删除。
* **文件属性 (`FILE_ATTRIBUTE_READONLY`, `FILE_ATTRIBUTE_HIDDEN`, `FILE_ATTRIBUTE_SYSTEM` 等):** 定义了文件的各种属性，例如只读、隐藏、系统文件等。
* `INVALID_FILE_ATTRIBUTES`: 表示无效的文件属性值。

**3. 访问掩码 (ACCESS_MASK) 相关的类型和常量:**

* `ACCESS_MASK`: 定义了表示访问权限的类型。
* `DELETE`, `READ_CONTROL`, `WRITE_DAC`, `WRITE_OWNER`, `SYNCHRONIZE`, `STANDARD_RIGHTS_*`, `GENERIC_*` 等常量:  定义了更细粒度的访问权限控制标志，例如删除权限、读取访问控制列表的权限、写入 DACL 的权限、同步访问权限以及一些预定义的标准权限集合。

**4. 安全描述符和访问控制列表相关的类型:**

* `ACL`: 表示访问控制列表的结构体。
* `SECURITY_DESCRIPTOR`: 表示安全描述符的结构体，包含了对象的安全信息，例如所有者、组和 ACL。
* `SECURITY_DESCRIPTOR_CONTROL`:  表示安全描述符控制信息的类型。
* `SECURITY_QUALITY_OF_SERVICE`: 表示安全服务质量的结构体。

**5. I/O 状态块相关的类型:**

* `IO_STATUS_BLOCK`:  表示 I/O 操作状态的结构体，包含了操作的状态码和信息。

**6. 对象属性相关的类型和常量:**

* `OBJECT_ATTRIBUTES`:  表示对象属性的结构体，用于在创建或打开对象时指定各种属性，例如对象名、根目录、安全描述符等。
* `init` 方法:  为 `OBJECT_ATTRIBUTES` 结构体提供初始化方法，用于设置根目录、对象名和长度。
* `OBJ_INHERIT`, `OBJ_PERMANENT`, `OBJ_CASE_INSENSITIVE` 等常量:  定义了 `OBJECT_ATTRIBUTES` 结构体中 `Attributes` 字段的各种标志位，用于指定对象的特性。

**7. 文件创建/打开相关的常量:**

* **创建方式 (`FILE_SUPERSEDE`, `FILE_OPEN`, `FILE_CREATE` 等):**  定义了创建或打开文件的方式，例如如果文件已存在则覆盖、只打开已存在的文件、如果文件不存在则创建等。
* **创建选项 (`FILE_DIRECTORY_FILE`, `FILE_WRITE_THROUGH`, `FILE_DELETE_ON_CLOSE` 等):**  定义了创建或打开文件时的各种选项，例如是否为目录、是否使用直写模式、是否在关闭时删除等。

**8. 文件处置信息相关的类型和常量:**

* `FILE_DISPOSITION_INFORMATION`:  表示文件处置信息的结构体，用于指定文件是否应该被删除。
* `FILE_DISPOSITION_INFORMATION_EX`:  表示扩展的文件处置信息的结构体，提供了更详细的删除选项。
* `FILE_DISPOSITION_DO_NOT_DELETE`, `FILE_DISPOSITION_DELETE`, `FILE_DISPOSITION_POSIX_SEMANTICS` 等常量: 定义了 `FILE_DISPOSITION_INFORMATION_EX` 结构体中 `Flags` 字段的各种标志位，用于更精细地控制文件删除行为。

**功能推断和 Go 代码示例:**

这个文件是 `internal/syscall/windows` 包的一部分，这意味着它主要被 Go 标准库内部使用，用于实现与 Windows 系统调用相关的底层功能。 开发者通常不会直接使用这个文件中的类型和常量，而是通过 Go 标准库中更高级别的包，例如 `os` 和 `net` 来间接使用。

例如，当你使用 `os.OpenFile` 函数在 Windows 上创建一个文件时，底层的实现可能会使用到这个文件中定义的 `FILE_CREATE` 和其他相关的 `FILE_` 开头的常量。

```go
package main

import (
	"fmt"
	"os"
)

func main() {
	filename := "example.txt"
	// 假设 os.OpenFile 内部使用了 types_windows.go 中定义的常量
	file, err := os.OpenFile(filename, os.O_RDWR|os.O_CREATE, 0666)
	if err != nil {
		fmt.Println("Error creating/opening file:", err)
		return
	}
	defer file.Close()

	fmt.Println("File created/opened successfully.")
}
```

**代码推理（假设的输入与输出）：**

在上面的 `os.OpenFile` 例子中：

* **假设输入：** `filename` 为 "example.txt"，`os.O_RDWR|os.O_CREATE` 对应于 Windows API 中创建或读写文件的意图，`0666` 是文件权限（尽管在 Windows 上权限模型有所不同，这里仅为演示）。
* **推断的底层行为：** `os.OpenFile` 可能会在内部构建一个 `OBJECT_ATTRIBUTES` 结构体，并将 `filename` 赋值给 `ObjectName`，并设置相应的 `Attributes` 和访问掩码，例如使用 `FILE_GENERIC_READ | FILE_GENERIC_WRITE` 来表示读写权限，使用 `FILE_CREATE_IF_NOT_EXIST` 类似的常量（虽然代码中没有完全对应的，但概念类似）来表示创建行为。
* **可能的输出：** 如果文件创建成功，`os.OpenFile` 将返回一个 `*os.File` 对象和 `nil` 错误。如果创建失败，将返回 `nil` 的 `*os.File` 和一个非 `nil` 的错误，描述失败原因。

**命令行参数处理：**

这个代码文件本身并不直接处理命令行参数。命令行参数的处理通常发生在 Go 程序的 `main` 函数中，并使用 `os.Args` 或 `flag` 包来解析。 这个文件定义的常量和类型会被底层的文件操作或网络操作相关的系统调用使用，而这些系统调用可能是由处理命令行参数的 Go 代码间接触发的。

例如，如果你的 Go 程序接受一个文件路径作为命令行参数，并打开该文件进行读取，那么在打开文件的过程中，`os` 包可能会使用到这个文件中定义的 `FILE_GENERIC_READ` 常量。

**使用者易犯错的点：**

由于这个文件是 `internal` 包的一部分，Go 官方不建议开发者直接使用其中的类型和常量。 直接使用可能会导致以下问题：

1. **API 稳定性：** `internal` 包的 API 不保证稳定，可能会在未来的 Go 版本中发生更改，导致你的代码无法编译或运行。
2. **平台兼容性：**  这个文件是特定于 Windows 平台的，直接使用会导致代码在其他操作系统上无法移植。
3. **复杂性：**  直接操作底层的 Windows API 往往比较复杂，需要对 Windows 的内部机制有深入的了解，容易出错。

**举例说明易犯错的点：**

假设开发者尝试直接使用 `types_windows.go` 中定义的 `FILE_SHARE_READ` 常量来尝试实现文件共享：

```go
// 错误示例，不建议直接使用 internal 包的常量
package main

import (
	"fmt"
	"syscall"
	"unsafe"
	_ "unsafe" // For go:linkname

	"internal/syscall/windows"
)

//go:linkname openFile syscall.openFile
func openFile(path string, mode int, perm uint32) (fd syscall.Handle, err error)

func main() {
	filename := "shared_file.txt"
	// 尝试使用 internal 包的常量
	handle, err := openFile(filename, syscall.O_RDWR|syscall.O_CREAT, windows.FILE_SHARE_READ)
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer syscall.Close(handle)

	fmt.Println("File opened with shared read access (attempted).")
}
```

在这个例子中，开发者尝试直接调用 `syscall.openFile` 并使用 `windows.FILE_SHARE_READ` 常量。 这样做的问题是：

* **代码可移植性差：** 这段代码只能在 Windows 上运行。
* **使用了 internal 包：**  `internal/syscall/windows` 的 API 可能随时更改。
* **对系统调用细节的理解要求高：** 正确使用 `openFile` 需要对底层的系统调用有深入的理解，包括参数的含义和组合方式。

**正确的做法是使用 Go 标准库提供的 `os` 包：**

```go
package main

import (
	"fmt"
	"os"
)

func main() {
	filename := "shared_file.txt"
	// 使用 os 包提供的功能
	file, err := os.OpenFile(filename, os.O_RDWR|os.O_CREATE, 0666)
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer file.Close()

	fmt.Println("File opened successfully.")
}
```

Go 的 `os` 包在底层会根据操作系统选择合适的系统调用和参数，并提供了更简洁和跨平台的 API。 开发者应该优先使用标准库提供的功能，而不是直接操作 `internal` 包的内容。

Prompt: 
```
这是路径为go/src/internal/syscall/windows/types_windows.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package windows

import (
	"syscall"
	"unsafe"
)

// Socket related.
const (
	TCP_KEEPIDLE  = 0x03
	TCP_KEEPCNT   = 0x10
	TCP_KEEPINTVL = 0x11
)

const (
	FILE_READ_DATA        = 0x00000001
	FILE_READ_ATTRIBUTES  = 0x00000080
	FILE_READ_EA          = 0x00000008
	FILE_WRITE_DATA       = 0x00000002
	FILE_WRITE_ATTRIBUTES = 0x00000100
	FILE_WRITE_EA         = 0x00000010
	FILE_APPEND_DATA      = 0x00000004
	FILE_EXECUTE          = 0x00000020

	FILE_GENERIC_READ    = STANDARD_RIGHTS_READ | FILE_READ_DATA | FILE_READ_ATTRIBUTES | FILE_READ_EA | SYNCHRONIZE
	FILE_GENERIC_WRITE   = STANDARD_RIGHTS_WRITE | FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA | FILE_APPEND_DATA | SYNCHRONIZE
	FILE_GENERIC_EXECUTE = STANDARD_RIGHTS_EXECUTE | FILE_READ_ATTRIBUTES | FILE_EXECUTE | SYNCHRONIZE

	FILE_LIST_DIRECTORY = 0x00000001
	FILE_TRAVERSE       = 0x00000020

	FILE_SHARE_READ                      = 0x00000001
	FILE_SHARE_WRITE                     = 0x00000002
	FILE_SHARE_DELETE                    = 0x00000004
	FILE_ATTRIBUTE_READONLY              = 0x00000001
	FILE_ATTRIBUTE_HIDDEN                = 0x00000002
	FILE_ATTRIBUTE_SYSTEM                = 0x00000004
	FILE_ATTRIBUTE_DIRECTORY             = 0x00000010
	FILE_ATTRIBUTE_ARCHIVE               = 0x00000020
	FILE_ATTRIBUTE_DEVICE                = 0x00000040
	FILE_ATTRIBUTE_NORMAL                = 0x00000080
	FILE_ATTRIBUTE_TEMPORARY             = 0x00000100
	FILE_ATTRIBUTE_SPARSE_FILE           = 0x00000200
	FILE_ATTRIBUTE_REPARSE_POINT         = 0x00000400
	FILE_ATTRIBUTE_COMPRESSED            = 0x00000800
	FILE_ATTRIBUTE_OFFLINE               = 0x00001000
	FILE_ATTRIBUTE_NOT_CONTENT_INDEXED   = 0x00002000
	FILE_ATTRIBUTE_ENCRYPTED             = 0x00004000
	FILE_ATTRIBUTE_INTEGRITY_STREAM      = 0x00008000
	FILE_ATTRIBUTE_VIRTUAL               = 0x00010000
	FILE_ATTRIBUTE_NO_SCRUB_DATA         = 0x00020000
	FILE_ATTRIBUTE_RECALL_ON_OPEN        = 0x00040000
	FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS = 0x00400000

	INVALID_FILE_ATTRIBUTES = 0xffffffff
)

// https://learn.microsoft.com/en-us/windows/win32/secauthz/access-mask
type ACCESS_MASK uint32

// Constants for type ACCESS_MASK
const (
	DELETE                   = 0x00010000
	READ_CONTROL             = 0x00020000
	WRITE_DAC                = 0x00040000
	WRITE_OWNER              = 0x00080000
	SYNCHRONIZE              = 0x00100000
	STANDARD_RIGHTS_REQUIRED = 0x000F0000
	STANDARD_RIGHTS_READ     = READ_CONTROL
	STANDARD_RIGHTS_WRITE    = READ_CONTROL
	STANDARD_RIGHTS_EXECUTE  = READ_CONTROL
	STANDARD_RIGHTS_ALL      = 0x001F0000
	SPECIFIC_RIGHTS_ALL      = 0x0000FFFF
	ACCESS_SYSTEM_SECURITY   = 0x01000000
	MAXIMUM_ALLOWED          = 0x02000000
	GENERIC_READ             = 0x80000000
	GENERIC_WRITE            = 0x40000000
	GENERIC_EXECUTE          = 0x20000000
	GENERIC_ALL              = 0x10000000
)

// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_acl
type ACL struct {
	AclRevision byte
	Sbz1        byte
	AclSize     uint16
	AceCount    uint16
	Sbz2        uint16
}

// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_io_status_block
type IO_STATUS_BLOCK struct {
	Status      NTStatus
	Information uintptr
}

// https://learn.microsoft.com/en-us/windows/win32/api/ntdef/ns-ntdef-_object_attributes
type OBJECT_ATTRIBUTES struct {
	Length             uint32
	RootDirectory      syscall.Handle
	ObjectName         *NTUnicodeString
	Attributes         uint32
	SecurityDescriptor *SECURITY_DESCRIPTOR
	SecurityQoS        *SECURITY_QUALITY_OF_SERVICE
}

// init sets o's RootDirectory, ObjectName, and Length.
func (o *OBJECT_ATTRIBUTES) init(root syscall.Handle, name string) error {
	if name == "." {
		name = ""
	}
	objectName, err := NewNTUnicodeString(name)
	if err != nil {
		return err
	}
	o.ObjectName = objectName
	if root != syscall.InvalidHandle {
		o.RootDirectory = root
	}
	o.Length = uint32(unsafe.Sizeof(*o))
	return nil
}

// Values for the Attributes member of OBJECT_ATTRIBUTES.
const (
	OBJ_INHERIT                       = 0x00000002
	OBJ_PERMANENT                     = 0x00000010
	OBJ_EXCLUSIVE                     = 0x00000020
	OBJ_CASE_INSENSITIVE              = 0x00000040
	OBJ_OPENIF                        = 0x00000080
	OBJ_OPENLINK                      = 0x00000100
	OBJ_KERNEL_HANDLE                 = 0x00000200
	OBJ_FORCE_ACCESS_CHECK            = 0x00000400
	OBJ_IGNORE_IMPERSONATED_DEVICEMAP = 0x00000800
	OBJ_DONT_REPARSE                  = 0x00001000
	OBJ_VALID_ATTRIBUTES              = 0x00001FF2
)

// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_security_descriptor
type SECURITY_DESCRIPTOR struct {
	revision byte
	sbz1     byte
	control  SECURITY_DESCRIPTOR_CONTROL
	owner    *syscall.SID
	group    *syscall.SID
	sacl     *ACL
	dacl     *ACL
}

// https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/security-descriptor-control
type SECURITY_DESCRIPTOR_CONTROL uint16

// https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-security_quality_of_service
type SECURITY_QUALITY_OF_SERVICE struct {
	Length              uint32
	ImpersonationLevel  uint32 // type SECURITY_IMPERSONATION_LEVEL
	ContextTrackingMode byte   // type SECURITY_CONTEXT_TRACKING_MODE
	EffectiveOnly       byte
}

const (
	// CreateDisposition flags for NtCreateFile and NtCreateNamedPipeFile.
	FILE_SUPERSEDE           = 0x00000000
	FILE_OPEN                = 0x00000001
	FILE_CREATE              = 0x00000002
	FILE_OPEN_IF             = 0x00000003
	FILE_OVERWRITE           = 0x00000004
	FILE_OVERWRITE_IF        = 0x00000005
	FILE_MAXIMUM_DISPOSITION = 0x00000005

	// CreateOptions flags for NtCreateFile and NtCreateNamedPipeFile.
	FILE_DIRECTORY_FILE            = 0x00000001
	FILE_WRITE_THROUGH             = 0x00000002
	FILE_SEQUENTIAL_ONLY           = 0x00000004
	FILE_NO_INTERMEDIATE_BUFFERING = 0x00000008
	FILE_SYNCHRONOUS_IO_ALERT      = 0x00000010
	FILE_SYNCHRONOUS_IO_NONALERT   = 0x00000020
	FILE_NON_DIRECTORY_FILE        = 0x00000040
	FILE_CREATE_TREE_CONNECTION    = 0x00000080
	FILE_COMPLETE_IF_OPLOCKED      = 0x00000100
	FILE_NO_EA_KNOWLEDGE           = 0x00000200
	FILE_OPEN_REMOTE_INSTANCE      = 0x00000400
	FILE_RANDOM_ACCESS             = 0x00000800
	FILE_DELETE_ON_CLOSE           = 0x00001000
	FILE_OPEN_BY_FILE_ID           = 0x00002000
	FILE_OPEN_FOR_BACKUP_INTENT    = 0x00004000
	FILE_NO_COMPRESSION            = 0x00008000
	FILE_OPEN_REQUIRING_OPLOCK     = 0x00010000
	FILE_DISALLOW_EXCLUSIVE        = 0x00020000
	FILE_RESERVE_OPFILTER          = 0x00100000
	FILE_OPEN_REPARSE_POINT        = 0x00200000
	FILE_OPEN_NO_RECALL            = 0x00400000
	FILE_OPEN_FOR_FREE_SPACE_QUERY = 0x00800000
)

// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-_file_disposition_information
type FILE_DISPOSITION_INFORMATION struct {
	DeleteFile bool
}

// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-_file_disposition_information_ex
type FILE_DISPOSITION_INFORMATION_EX struct {
	Flags uint32
}

// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-_file_disposition_information_ex
const (
	FILE_DISPOSITION_DO_NOT_DELETE             = 0x00000000
	FILE_DISPOSITION_DELETE                    = 0x00000001
	FILE_DISPOSITION_POSIX_SEMANTICS           = 0x00000002
	FILE_DISPOSITION_FORCE_IMAGE_SECTION_CHECK = 0x00000004
	FILE_DISPOSITION_ON_CLOSE                  = 0x00000008
	FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE = 0x00000010
)

"""



```