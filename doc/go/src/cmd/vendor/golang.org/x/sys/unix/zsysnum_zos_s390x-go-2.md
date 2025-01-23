Response:
Let's break down the thought process for analyzing the provided Go code snippet.

**1. Initial Observation and Goal Identification:**

The first thing I notice is that the code defines a series of Go constants. Each constant starts with `SYS_` and is assigned a hexadecimal value and a decimal value in a comment. The path `go/src/cmd/vendor/golang.org/x/sys/unix/zsysnum_zos_s390x.go` strongly suggests this file is related to system calls on the z/OS operating system for the s390x architecture. The request asks for the functionality, how it's used, examples, and common mistakes.

**2. Deeper Dive into the Constants:**

I examine the naming convention. The `SYS_` prefix clearly indicates these are system call numbers. The names themselves (e.g., `SYS_READ`, `SYS_WRITE`, `SYS_OPEN`) are very suggestive of standard POSIX system calls. However, the presence of less common names (e.g., `SYS___CLASS2F`, `SYS___LE_CEEGTJS`) suggests platform-specific extensions or internal z/OS syscalls. The numerical values are likely the actual system call numbers used by the z/OS kernel.

**3. Core Functionality Identification:**

Based on the `SYS_` prefix and the names, the primary function of this file is to define the system call numbers for the z/OS operating system on the s390x architecture. This allows Go programs to interact with the operating system kernel by referencing these named constants instead of raw numbers. This significantly improves code readability and maintainability.

**4. Connecting to Go's `syscall` Package:**

I recall that Go's `syscall` package is the standard way to make system calls. I hypothesize that these constants are used internally by the `syscall` package (or its sub-packages) when targeting the z/OS/s390x platform. This allows Go's platform-independent system call abstractions to be translated into the correct syscall numbers for this specific OS and architecture.

**5. Constructing a Go Code Example:**

To illustrate the usage, I need to create a simple example that demonstrates a system call. A common and straightforward system call is `open`. I know the corresponding constant is `SYS_OPEN`. Therefore, I can construct an example like this:

```go
package main

import (
	"fmt"
	"syscall"
	"unsafe"
)

func main() {
	// Assuming SYS_OPEN is defined in this file or another relevant package.
	pathname := "/tmp/test.txt"
	flags := syscall.O_RDONLY
	mode := 0 // Not used for O_RDONLY

	fd, _, err := syscall.Syscall(uintptr(0xC01), // Assume SYS_OPEN = 0xC01
		uintptr(unsafe.Pointer(syscall.StringBytePtr(pathname))),
		uintptr(flags),
		uintptr(mode))

	if err != 0 {
		fmt.Printf("Error opening file: %v\n", err)
		return
	}
	fmt.Printf("File descriptor: %d\n", fd)
	syscall.Close(int(fd))
}
```

* **Key Considerations for the Example:**
    * **`syscall.Syscall`:** This is the core function for making raw system calls.
    * **`uintptr(0xC01)`:**  I replaced the direct constant `SYS_OPEN` with its assumed value. In a real-world scenario, the `syscall` package would use the defined constant.
    * **`unsafe.Pointer`:**  Required to convert the string to a pointer suitable for the system call.
    * **Error Handling:**  Crucial for any system call.
    * **Closing the File Descriptor:** Important to release resources.
    * **Assumptions:** I explicitly stated the assumption about the value of `SYS_OPEN` since the provided snippet is only a part of the file.

**6. Reasoning About Command-Line Arguments and Common Mistakes:**

* **Command-Line Arguments:**  This specific file primarily deals with *internal* system call mappings. It doesn't directly handle command-line arguments. The system calls themselves might be invoked by programs that *do* process command-line arguments, but this file is one level deeper.

* **Common Mistakes:**
    * **Incorrect Syscall Number:**  The most likely error is using the wrong numerical value for a system call. This file aims to prevent that by providing named constants.
    * **Incorrect Argument Types/Sizes:** System calls often have strict requirements for argument types and sizes. While this file doesn't directly cause this error, developers using these constants need to be aware of the correct types expected by the z/OS kernel.
    * **Forgetting Error Handling:** A general programming mistake when dealing with system calls.

**7. Synthesizing the Summary (Part 3):**

Based on the analysis, the concluding summary should reinforce the role of this file as a definition of system call numbers for z/OS on s390x. It facilitates the interaction between Go programs and the kernel by providing meaningful names for these system calls.

**Self-Correction/Refinement during the Process:**

* Initially, I might have focused too much on the individual system call names. It's important to step back and see the *overall purpose* of the file.
* I considered providing examples for multiple system calls, but for brevity and clarity in the explanation, focusing on a single, fundamental example like `open` is more effective.
* I made sure to clearly state my assumptions when providing the code example, as the provided snippet is incomplete. This prevents confusion.

By following this systematic process, I was able to arrive at a comprehensive and accurate answer to the user's request. The key was understanding the context of the file (system calls, OS/architecture specific), connecting it to relevant Go concepts (`syscall` package), and providing a concrete example to illustrate its purpose.
这是 `go/src/cmd/vendor/golang.org/x/sys/unix/zsysnum_zos_s390x.go` 文件的一部分，它定义了一系列 Go 语言常量。这些常量代表了 **z/OS 操作系统在 s390x 架构上的系统调用号**。

**它的主要功能是：**

1. **为 z/OS (s390x) 架构下的系统调用提供人类可读的名称。**  例如，`SYS_READ` 代表了读取文件的系统调用，而不是直接使用数字 `0xC01`。
2. **作为 Go 语言 `syscall` 包的一部分，用于在 z/OS (s390x) 系统上执行底层的操作系统调用。** Go 的 `syscall` 包提供了跨平台的系统调用接口，而这个文件则为特定的平台提供了具体的系统调用号映射。

**可以推理出它是什么 Go 语言功能的实现：**

这个文件是 Go 语言 `syscall` 标准库中针对特定操作系统和架构的系统调用号定义部分。Go 语言为了实现跨平台能力，将操作系统相关的底层调用抽象出来，通过 `syscall` 包提供统一的接口。在编译时，Go 编译器会根据目标操作系统和架构选择相应的 `zsysnum_*.go` 文件，以确定实际使用的系统调用号。

**Go 代码举例说明:**

虽然你不会直接在你的应用程序中引用这些常量，但它们会被 `syscall` 包内部使用。以下代码展示了如何使用 `syscall` 包进行系统调用，而 `zsysnum_zos_s390x.go` 中定义的常量在幕后发挥作用：

```go
package main

import (
	"fmt"
	"syscall"
	"unsafe"
)

func main() {
	filename := "/tmp/test.txt" // 假设文件存在

	// 调用 open 系统调用 (SYS_OPEN 在 zsysnum_zos_s390x.go 中定义)
	fd, err := syscall.Open(filename, syscall.O_RDONLY, 0)
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer syscall.Close(fd)

	// 读取文件内容 (SYS_READ 在 zsysnum_zos_s390x.go 中定义)
	buf := make([]byte, 100)
	n, err := syscall.Read(fd, buf)
	if err != nil {
		fmt.Println("Error reading file:", err)
		return
	}

	fmt.Printf("Read %d bytes: %s\n", n, string(buf[:n]))
}
```

**假设的输入与输出：**

假设 `/tmp/test.txt` 文件包含文本 "Hello, z/OS!".

**输入:**  执行上述 Go 程序。

**输出:**

```
Read 11 bytes: Hello, z/OS!
```

**代码推理:**

1. `syscall.Open(filename, syscall.O_RDONLY, 0)`:  这个函数调用会最终调用底层的 `open` 系统调用。Go 的 `syscall` 包会根据目标平台（z/OS, s390x）使用 `zsysnum_zos_s390x.go` 中定义的 `SYS_OPEN` 常量作为系统调用号。
2. `syscall.Read(fd, buf)`: 类似地，这个函数调用会使用 `zsysnum_zos_s390x.go` 中定义的 `SYS_READ` 常量来执行底层的读取操作。

**涉及命令行参数的具体处理：**

这个文件本身并不直接处理命令行参数。它定义的是系统调用号，而系统调用通常是由程序内部逻辑触发的。命令行参数的处理发生在程序的更上层，例如 `os` 包中的 `os.Args` 可以用来获取命令行参数。当程序需要执行某些与命令行参数相关的操作时，可能会间接地调用到 `syscall` 包，从而用到这里定义的系统调用号。

**使用者易犯错的点：**

普通 Go 开发者通常不需要直接操作 `zsysnum_zos_s390x.go` 文件中的常量。这个文件是 Go 运行时库的一部分，主要供 `syscall` 包的开发者和维护者使用。

然而，如果有人尝试 **直接使用这些常量进行系统调用**，而不是通过 `syscall` 包提供的封装好的函数，就很容易犯错：

* **参数传递错误:** 直接使用系统调用需要非常清楚每个系统调用所需的参数类型、数量和顺序，这很容易出错。
* **平台兼容性问题:**  直接使用特定平台的系统调用号会使代码失去跨平台能力。
* **ABI (Application Binary Interface) 问题:** 不同操作系统或架构的 ABI 可能不同，直接调用可能会导致程序崩溃或产生未定义的行为。

**归纳一下它的功能 (第3部分):**

作为第 3 部分，可以归纳出 `go/src/cmd/vendor/golang.org/x/sys/unix/zsysnum_zos_s390x.go` 文件的核心功能是：

**为 Go 语言在 z/OS 操作系统和 s390x 架构上进行底层系统调用提供必要的系统调用号映射。它充当了 Go 语言 `syscall` 包与 z/OS 内核之间的桥梁，使得 Go 程序能够以平台无关的方式调用操作系统提供的服务。**  这个文件是 Go 运行时环境针对特定平台实现细节的一部分，确保了 `syscall` 包的跨平台抽象能够正确地转化为目标系统的底层操作。

### 提示词
```
这是路径为go/src/cmd/vendor/golang.org/x/sys/unix/zsysnum_zos_s390x.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第3部分，共3部分，请归纳一下它的功能
```

### 源代码
```go
= 0xC41 // 3137
	SYS_WCSTOD64                        = 0xC42 // 3138
	SYS_WCSTOD128                       = 0xC43 // 3139
	SYS___CODEPAGE_INFO                 = 0xC64 // 3172
	SYS_POSIX_OPENPT                    = 0xC66 // 3174
	SYS_PSELECT                         = 0xC67 // 3175
	SYS_SOCKATMARK                      = 0xC68 // 3176
	SYS_AIO_FSYNC                       = 0xC69 // 3177
	SYS_LIO_LISTIO                      = 0xC6A // 3178
	SYS___ATANPID32                     = 0xC6B // 3179
	SYS___ATANPID64                     = 0xC6C // 3180
	SYS___ATANPID128                    = 0xC6D // 3181
	SYS___COSPID32                      = 0xC6E // 3182
	SYS___COSPID64                      = 0xC6F // 3183
	SYS___COSPID128                     = 0xC70 // 3184
	SYS___SINPID32                      = 0xC71 // 3185
	SYS___SINPID64                      = 0xC72 // 3186
	SYS___SINPID128                     = 0xC73 // 3187
	SYS_SETIPV4SOURCEFILTER             = 0xC76 // 3190
	SYS_GETIPV4SOURCEFILTER             = 0xC77 // 3191
	SYS_SETSOURCEFILTER                 = 0xC78 // 3192
	SYS_GETSOURCEFILTER                 = 0xC79 // 3193
	SYS_FWRITE_UNLOCKED                 = 0xC7A // 3194
	SYS_FREAD_UNLOCKED                  = 0xC7B // 3195
	SYS_FGETS_UNLOCKED                  = 0xC7C // 3196
	SYS_GETS_UNLOCKED                   = 0xC7D // 3197
	SYS_FPUTS_UNLOCKED                  = 0xC7E // 3198
	SYS_PUTS_UNLOCKED                   = 0xC7F // 3199
	SYS_FGETC_UNLOCKED                  = 0xC80 // 3200
	SYS_FPUTC_UNLOCKED                  = 0xC81 // 3201
	SYS_DLADDR                          = 0xC82 // 3202
	SYS_SHM_OPEN                        = 0xC8C // 3212
	SYS_SHM_UNLINK                      = 0xC8D // 3213
	SYS___CLASS2F                       = 0xC91 // 3217
	SYS___CLASS2L                       = 0xC92 // 3218
	SYS___CLASS2F_B                     = 0xC93 // 3219
	SYS___CLASS2F_H                     = 0xC94 // 3220
	SYS___CLASS2L_B                     = 0xC95 // 3221
	SYS___CLASS2L_H                     = 0xC96 // 3222
	SYS___CLASS2D32                     = 0xC97 // 3223
	SYS___CLASS2D64                     = 0xC98 // 3224
	SYS___CLASS2D128                    = 0xC99 // 3225
	SYS___TOCSNAME2                     = 0xC9A // 3226
	SYS___D1TOP                         = 0xC9B // 3227
	SYS___D2TOP                         = 0xC9C // 3228
	SYS___D4TOP                         = 0xC9D // 3229
	SYS___PTOD1                         = 0xC9E // 3230
	SYS___PTOD2                         = 0xC9F // 3231
	SYS___PTOD4                         = 0xCA0 // 3232
	SYS_CLEARERR_UNLOCKED               = 0xCA1 // 3233
	SYS_FDELREC_UNLOCKED                = 0xCA2 // 3234
	SYS_FEOF_UNLOCKED                   = 0xCA3 // 3235
	SYS_FERROR_UNLOCKED                 = 0xCA4 // 3236
	SYS_FFLUSH_UNLOCKED                 = 0xCA5 // 3237
	SYS_FGETPOS_UNLOCKED                = 0xCA6 // 3238
	SYS_FGETWC_UNLOCKED                 = 0xCA7 // 3239
	SYS_FGETWS_UNLOCKED                 = 0xCA8 // 3240
	SYS_FILENO_UNLOCKED                 = 0xCA9 // 3241
	SYS_FLDATA_UNLOCKED                 = 0xCAA // 3242
	SYS_FLOCATE_UNLOCKED                = 0xCAB // 3243
	SYS_FPRINTF_UNLOCKED                = 0xCAC // 3244
	SYS_FPUTWC_UNLOCKED                 = 0xCAD // 3245
	SYS_FPUTWS_UNLOCKED                 = 0xCAE // 3246
	SYS_FSCANF_UNLOCKED                 = 0xCAF // 3247
	SYS_FSEEK_UNLOCKED                  = 0xCB0 // 3248
	SYS_FSEEKO_UNLOCKED                 = 0xCB1 // 3249
	SYS_FSETPOS_UNLOCKED                = 0xCB3 // 3251
	SYS_FTELL_UNLOCKED                  = 0xCB4 // 3252
	SYS_FTELLO_UNLOCKED                 = 0xCB5 // 3253
	SYS_FUPDATE_UNLOCKED                = 0xCB7 // 3255
	SYS_FWIDE_UNLOCKED                  = 0xCB8 // 3256
	SYS_FWPRINTF_UNLOCKED               = 0xCB9 // 3257
	SYS_FWSCANF_UNLOCKED                = 0xCBA // 3258
	SYS_GETWC_UNLOCKED                  = 0xCBB // 3259
	SYS_GETWCHAR_UNLOCKED               = 0xCBC // 3260
	SYS_PERROR_UNLOCKED                 = 0xCBD // 3261
	SYS_PRINTF_UNLOCKED                 = 0xCBE // 3262
	SYS_PUTWC_UNLOCKED                  = 0xCBF // 3263
	SYS_PUTWCHAR_UNLOCKED               = 0xCC0 // 3264
	SYS_REWIND_UNLOCKED                 = 0xCC1 // 3265
	SYS_SCANF_UNLOCKED                  = 0xCC2 // 3266
	SYS_UNGETC_UNLOCKED                 = 0xCC3 // 3267
	SYS_UNGETWC_UNLOCKED                = 0xCC4 // 3268
	SYS_VFPRINTF_UNLOCKED               = 0xCC5 // 3269
	SYS_VFSCANF_UNLOCKED                = 0xCC7 // 3271
	SYS_VFWPRINTF_UNLOCKED              = 0xCC9 // 3273
	SYS_VFWSCANF_UNLOCKED               = 0xCCB // 3275
	SYS_VPRINTF_UNLOCKED                = 0xCCD // 3277
	SYS_VSCANF_UNLOCKED                 = 0xCCF // 3279
	SYS_VWPRINTF_UNLOCKED               = 0xCD1 // 3281
	SYS_VWSCANF_UNLOCKED                = 0xCD3 // 3283
	SYS_WPRINTF_UNLOCKED                = 0xCD5 // 3285
	SYS_WSCANF_UNLOCKED                 = 0xCD6 // 3286
	SYS_ASCTIME64                       = 0xCD7 // 3287
	SYS_ASCTIME64_R                     = 0xCD8 // 3288
	SYS_CTIME64                         = 0xCD9 // 3289
	SYS_CTIME64_R                       = 0xCDA // 3290
	SYS_DIFFTIME64                      = 0xCDB // 3291
	SYS_GMTIME64                        = 0xCDC // 3292
	SYS_GMTIME64_R                      = 0xCDD // 3293
	SYS_LOCALTIME64                     = 0xCDE // 3294
	SYS_LOCALTIME64_R                   = 0xCDF // 3295
	SYS_MKTIME64                        = 0xCE0 // 3296
	SYS_TIME64                          = 0xCE1 // 3297
	SYS___LOGIN_APPLID                  = 0xCE2 // 3298
	SYS___PASSWD_APPLID                 = 0xCE3 // 3299
	SYS_PTHREAD_SECURITY_APPLID_NP      = 0xCE4 // 3300
	SYS___GETTHENT                      = 0xCE5 // 3301
	SYS_FREEIFADDRS                     = 0xCE6 // 3302
	SYS_GETIFADDRS                      = 0xCE7 // 3303
	SYS_POSIX_FALLOCATE                 = 0xCE8 // 3304
	SYS_POSIX_MEMALIGN                  = 0xCE9 // 3305
	SYS_SIZEOF_ALLOC                    = 0xCEA // 3306
	SYS_RESIZE_ALLOC                    = 0xCEB // 3307
	SYS_FREAD_NOUPDATE                  = 0xCEC // 3308
	SYS_FREAD_NOUPDATE_UNLOCKED         = 0xCED // 3309
	SYS_FGETPOS64                       = 0xCEE // 3310
	SYS_FSEEK64                         = 0xCEF // 3311
	SYS_FSEEKO64                        = 0xCF0 // 3312
	SYS_FSETPOS64                       = 0xCF1 // 3313
	SYS_FTELL64                         = 0xCF2 // 3314
	SYS_FTELLO64                        = 0xCF3 // 3315
	SYS_FGETPOS64_UNLOCKED              = 0xCF4 // 3316
	SYS_FSEEK64_UNLOCKED                = 0xCF5 // 3317
	SYS_FSEEKO64_UNLOCKED               = 0xCF6 // 3318
	SYS_FSETPOS64_UNLOCKED              = 0xCF7 // 3319
	SYS_FTELL64_UNLOCKED                = 0xCF8 // 3320
	SYS_FTELLO64_UNLOCKED               = 0xCF9 // 3321
	SYS_FOPEN_UNLOCKED                  = 0xCFA // 3322
	SYS_FREOPEN_UNLOCKED                = 0xCFB // 3323
	SYS_FDOPEN_UNLOCKED                 = 0xCFC // 3324
	SYS_TMPFILE_UNLOCKED                = 0xCFD // 3325
	SYS___MOSERVICES                    = 0xD3D // 3389
	SYS___GETTOD                        = 0xD3E // 3390
	SYS_C16RTOMB                        = 0xD40 // 3392
	SYS_C32RTOMB                        = 0xD41 // 3393
	SYS_MBRTOC16                        = 0xD42 // 3394
	SYS_MBRTOC32                        = 0xD43 // 3395
	SYS_QUANTEXPD32                     = 0xD44 // 3396
	SYS_QUANTEXPD64                     = 0xD45 // 3397
	SYS_QUANTEXPD128                    = 0xD46 // 3398
	SYS___LOCALE_CTL                    = 0xD47 // 3399
	SYS___SMF_RECORD2                   = 0xD48 // 3400
	SYS_FOPEN64                         = 0xD49 // 3401
	SYS_FOPEN64_UNLOCKED                = 0xD4A // 3402
	SYS_FREOPEN64                       = 0xD4B // 3403
	SYS_FREOPEN64_UNLOCKED              = 0xD4C // 3404
	SYS_TMPFILE64                       = 0xD4D // 3405
	SYS_TMPFILE64_UNLOCKED              = 0xD4E // 3406
	SYS_GETDATE64                       = 0xD4F // 3407
	SYS_GETTIMEOFDAY64                  = 0xD50 // 3408
	SYS_BIND2ADDRSEL                    = 0xD59 // 3417
	SYS_INET6_IS_SRCADDR                = 0xD5A // 3418
	SYS___GETGRGID1                     = 0xD5B // 3419
	SYS___GETGRNAM1                     = 0xD5C // 3420
	SYS___FBUFSIZE                      = 0xD60 // 3424
	SYS___FPENDING                      = 0xD61 // 3425
	SYS___FLBF                          = 0xD62 // 3426
	SYS___FREADABLE                     = 0xD63 // 3427
	SYS___FWRITABLE                     = 0xD64 // 3428
	SYS___FREADING                      = 0xD65 // 3429
	SYS___FWRITING                      = 0xD66 // 3430
	SYS___FSETLOCKING                   = 0xD67 // 3431
	SYS__FLUSHLBF                       = 0xD68 // 3432
	SYS___FPURGE                        = 0xD69 // 3433
	SYS___FREADAHEAD                    = 0xD6A // 3434
	SYS___FSETERR                       = 0xD6B // 3435
	SYS___FPENDING_UNLOCKED             = 0xD6C // 3436
	SYS___FREADING_UNLOCKED             = 0xD6D // 3437
	SYS___FWRITING_UNLOCKED             = 0xD6E // 3438
	SYS__FLUSHLBF_UNLOCKED              = 0xD6F // 3439
	SYS___FPURGE_UNLOCKED               = 0xD70 // 3440
	SYS___FREADAHEAD_UNLOCKED           = 0xD71 // 3441
	SYS___LE_CEEGTJS                    = 0xD72 // 3442
	SYS___LE_RECORD_DUMP                = 0xD73 // 3443
	SYS_FSTAT64                         = 0xD74 // 3444
	SYS_LSTAT64                         = 0xD75 // 3445
	SYS_STAT64                          = 0xD76 // 3446
	SYS___READDIR2_64                   = 0xD77 // 3447
	SYS___OPEN_STAT64                   = 0xD78 // 3448
	SYS_FTW64                           = 0xD79 // 3449
	SYS_NFTW64                          = 0xD7A // 3450
	SYS_UTIME64                         = 0xD7B // 3451
	SYS_UTIMES64                        = 0xD7C // 3452
	SYS___GETIPC64                      = 0xD7D // 3453
	SYS_MSGCTL64                        = 0xD7E // 3454
	SYS_SEMCTL64                        = 0xD7F // 3455
	SYS_SHMCTL64                        = 0xD80 // 3456
	SYS_MSGXRCV64                       = 0xD81 // 3457
	SYS___MGXR64                        = 0xD81 // 3457
	SYS_W_GETPSENT64                    = 0xD82 // 3458
	SYS_PTHREAD_COND_TIMEDWAIT64        = 0xD83 // 3459
	SYS_FTIME64                         = 0xD85 // 3461
	SYS_GETUTXENT64                     = 0xD86 // 3462
	SYS_GETUTXID64                      = 0xD87 // 3463
	SYS_GETUTXLINE64                    = 0xD88 // 3464
	SYS_PUTUTXLINE64                    = 0xD89 // 3465
	SYS_NEWLOCALE                       = 0xD8A // 3466
	SYS_FREELOCALE                      = 0xD8B // 3467
	SYS_USELOCALE                       = 0xD8C // 3468
	SYS_DUPLOCALE                       = 0xD8D // 3469
	SYS___CHATTR64                      = 0xD9C // 3484
	SYS___LCHATTR64                     = 0xD9D // 3485
	SYS___FCHATTR64                     = 0xD9E // 3486
	SYS_____CHATTR64_A                  = 0xD9F // 3487
	SYS_____LCHATTR64_A                 = 0xDA0 // 3488
	SYS___LE_CEEUSGD                    = 0xDA1 // 3489
	SYS___LE_IFAM_CON                   = 0xDA2 // 3490
	SYS___LE_IFAM_DSC                   = 0xDA3 // 3491
	SYS___LE_IFAM_GET                   = 0xDA4 // 3492
	SYS___LE_IFAM_QRY                   = 0xDA5 // 3493
	SYS_ALIGNED_ALLOC                   = 0xDA6 // 3494
	SYS_ACCEPT4                         = 0xDA7 // 3495
	SYS___ACCEPT4_A                     = 0xDA8 // 3496
	SYS_COPYFILERANGE                   = 0xDA9 // 3497
	SYS_GETLINE                         = 0xDAA // 3498
	SYS___GETLINE_A                     = 0xDAB // 3499
	SYS_DIRFD                           = 0xDAC // 3500
	SYS_CLOCK_GETTIME                   = 0xDAD // 3501
	SYS_DUP3                            = 0xDAE // 3502
	SYS_EPOLL_CREATE                    = 0xDAF // 3503
	SYS_EPOLL_CREATE1                   = 0xDB0 // 3504
	SYS_EPOLL_CTL                       = 0xDB1 // 3505
	SYS_EPOLL_WAIT                      = 0xDB2 // 3506
	SYS_EPOLL_PWAIT                     = 0xDB3 // 3507
	SYS_EVENTFD                         = 0xDB4 // 3508
	SYS_STATFS                          = 0xDB5 // 3509
	SYS___STATFS_A                      = 0xDB6 // 3510
	SYS_FSTATFS                         = 0xDB7 // 3511
	SYS_INOTIFY_INIT                    = 0xDB8 // 3512
	SYS_INOTIFY_INIT1                   = 0xDB9 // 3513
	SYS_INOTIFY_ADD_WATCH               = 0xDBA // 3514
	SYS___INOTIFY_ADD_WATCH_A           = 0xDBB // 3515
	SYS_INOTIFY_RM_WATCH                = 0xDBC // 3516
	SYS_PIPE2                           = 0xDBD // 3517
	SYS_PIVOT_ROOT                      = 0xDBE // 3518
	SYS___PIVOT_ROOT_A                  = 0xDBF // 3519
	SYS_PRCTL                           = 0xDC0 // 3520
	SYS_PRLIMIT                         = 0xDC1 // 3521
	SYS_SETHOSTNAME                     = 0xDC2 // 3522
	SYS___SETHOSTNAME_A                 = 0xDC3 // 3523
	SYS_SETRESUID                       = 0xDC4 // 3524
	SYS_SETRESGID                       = 0xDC5 // 3525
	SYS_PTHREAD_CONDATTR_GETCLOCK       = 0xDC6 // 3526
	SYS_FLOCK                           = 0xDC7 // 3527
	SYS_FGETXATTR                       = 0xDC8 // 3528
	SYS___FGETXATTR_A                   = 0xDC9 // 3529
	SYS_FLISTXATTR                      = 0xDCA // 3530
	SYS___FLISTXATTR_A                  = 0xDCB // 3531
	SYS_FREMOVEXATTR                    = 0xDCC // 3532
	SYS___FREMOVEXATTR_A                = 0xDCD // 3533
	SYS_FSETXATTR                       = 0xDCE // 3534
	SYS___FSETXATTR_A                   = 0xDCF // 3535
	SYS_GETXATTR                        = 0xDD0 // 3536
	SYS___GETXATTR_A                    = 0xDD1 // 3537
	SYS_LGETXATTR                       = 0xDD2 // 3538
	SYS___LGETXATTR_A                   = 0xDD3 // 3539
	SYS_LISTXATTR                       = 0xDD4 // 3540
	SYS___LISTXATTR_A                   = 0xDD5 // 3541
	SYS_LLISTXATTR                      = 0xDD6 // 3542
	SYS___LLISTXATTR_A                  = 0xDD7 // 3543
	SYS_LREMOVEXATTR                    = 0xDD8 // 3544
	SYS___LREMOVEXATTR_A                = 0xDD9 // 3545
	SYS_LSETXATTR                       = 0xDDA // 3546
	SYS___LSETXATTR_A                   = 0xDDB // 3547
	SYS_REMOVEXATTR                     = 0xDDC // 3548
	SYS___REMOVEXATTR_A                 = 0xDDD // 3549
	SYS_SETXATTR                        = 0xDDE // 3550
	SYS___SETXATTR_A                    = 0xDDF // 3551
	SYS_FDATASYNC                       = 0xDE0 // 3552
	SYS_SYNCFS                          = 0xDE1 // 3553
	SYS_FUTIMES                         = 0xDE2 // 3554
	SYS_FUTIMESAT                       = 0xDE3 // 3555
	SYS___FUTIMESAT_A                   = 0xDE4 // 3556
	SYS_LUTIMES                         = 0xDE5 // 3557
	SYS___LUTIMES_A                     = 0xDE6 // 3558
	SYS_INET_ATON                       = 0xDE7 // 3559
	SYS_GETRANDOM                       = 0xDE8 // 3560
	SYS_GETTID                          = 0xDE9 // 3561
	SYS_MEMFD_CREATE                    = 0xDEA // 3562
	SYS___MEMFD_CREATE_A                = 0xDEB // 3563
	SYS_FACCESSAT                       = 0xDEC // 3564
	SYS___FACCESSAT_A                   = 0xDED // 3565
	SYS_FCHMODAT                        = 0xDEE // 3566
	SYS___FCHMODAT_A                    = 0xDEF // 3567
	SYS_FCHOWNAT                        = 0xDF0 // 3568
	SYS___FCHOWNAT_A                    = 0xDF1 // 3569
	SYS_FSTATAT                         = 0xDF2 // 3570
	SYS___FSTATAT_A                     = 0xDF3 // 3571
	SYS_LINKAT                          = 0xDF4 // 3572
	SYS___LINKAT_A                      = 0xDF5 // 3573
	SYS_MKDIRAT                         = 0xDF6 // 3574
	SYS___MKDIRAT_A                     = 0xDF7 // 3575
	SYS_MKFIFOAT                        = 0xDF8 // 3576
	SYS___MKFIFOAT_A                    = 0xDF9 // 3577
	SYS_MKNODAT                         = 0xDFA // 3578
	SYS___MKNODAT_A                     = 0xDFB // 3579
	SYS_OPENAT                          = 0xDFC // 3580
	SYS___OPENAT_A                      = 0xDFD // 3581
	SYS_READLINKAT                      = 0xDFE // 3582
	SYS___READLINKAT_A                  = 0xDFF // 3583
	SYS_RENAMEAT                        = 0xE00 // 3584
	SYS___RENAMEAT_A                    = 0xE01 // 3585
	SYS_RENAMEAT2                       = 0xE02 // 3586
	SYS___RENAMEAT2_A                   = 0xE03 // 3587
	SYS_SYMLINKAT                       = 0xE04 // 3588
	SYS___SYMLINKAT_A                   = 0xE05 // 3589
	SYS_UNLINKAT                        = 0xE06 // 3590
	SYS___UNLINKAT_A                    = 0xE07 // 3591
	SYS_SYSINFO                         = 0xE08 // 3592
	SYS_WAIT4                           = 0xE0A // 3594
	SYS_CLONE                           = 0xE0B // 3595
	SYS_UNSHARE                         = 0xE0C // 3596
	SYS_SETNS                           = 0xE0D // 3597
	SYS_CAPGET                          = 0xE0E // 3598
	SYS_CAPSET                          = 0xE0F // 3599
	SYS_STRCHRNUL                       = 0xE10 // 3600
	SYS_PTHREAD_CONDATTR_SETCLOCK       = 0xE12 // 3602
	SYS_OPEN_BY_HANDLE_AT               = 0xE13 // 3603
	SYS___OPEN_BY_HANDLE_AT_A           = 0xE14 // 3604
	SYS___INET_ATON_A                   = 0xE15 // 3605
	SYS_MOUNT1                          = 0xE16 // 3606
	SYS___MOUNT1_A                      = 0xE17 // 3607
	SYS_UMOUNT1                         = 0xE18 // 3608
	SYS___UMOUNT1_A                     = 0xE19 // 3609
	SYS_UMOUNT2                         = 0xE1A // 3610
	SYS___UMOUNT2_A                     = 0xE1B // 3611
	SYS___PRCTL_A                       = 0xE1C // 3612
	SYS_LOCALTIME_R2                    = 0xE1D // 3613
	SYS___LOCALTIME_R2_A                = 0xE1E // 3614
	SYS_OPENAT2                         = 0xE1F // 3615
	SYS___OPENAT2_A                     = 0xE20 // 3616
	SYS___LE_CEEMICT                    = 0xE21 // 3617
	SYS_GETENTROPY                      = 0xE22 // 3618
	SYS_NANOSLEEP                       = 0xE23 // 3619
	SYS_UTIMENSAT                       = 0xE24 // 3620
	SYS___UTIMENSAT_A                   = 0xE25 // 3621
	SYS_ASPRINTF                        = 0xE26 // 3622
	SYS___ASPRINTF_A                    = 0xE27 // 3623
	SYS_VASPRINTF                       = 0xE28 // 3624
	SYS___VASPRINTF_A                   = 0xE29 // 3625
	SYS_DPRINTF                         = 0xE2A // 3626
	SYS___DPRINTF_A                     = 0xE2B // 3627
	SYS_GETOPT_LONG                     = 0xE2C // 3628
	SYS___GETOPT_LONG_A                 = 0xE2D // 3629
	SYS_PSIGNAL                         = 0xE2E // 3630
	SYS___PSIGNAL_A                     = 0xE2F // 3631
	SYS_PSIGNAL_UNLOCKED                = 0xE30 // 3632
	SYS___PSIGNAL_UNLOCKED_A            = 0xE31 // 3633
	SYS_FSTATAT_O                       = 0xE32 // 3634
	SYS___FSTATAT_O_A                   = 0xE33 // 3635
	SYS_FSTATAT64                       = 0xE34 // 3636
	SYS___FSTATAT64_A                   = 0xE35 // 3637
	SYS___CHATTRAT                      = 0xE36 // 3638
	SYS_____CHATTRAT_A                  = 0xE37 // 3639
	SYS___CHATTRAT64                    = 0xE38 // 3640
	SYS_____CHATTRAT64_A                = 0xE39 // 3641
	SYS_MADVISE                         = 0xE3A // 3642
	SYS___AUTHENTICATE                  = 0xE3B // 3643

)
```