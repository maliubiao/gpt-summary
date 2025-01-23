Response:
Let's break down the thought process for answering this request.

**1. Understanding the Core Task:**

The primary request is to understand the functionality of a Go file (`zerrors_windows.go`) that seems to define a large number of constants. The name itself, "zerrors," strongly suggests these are error codes. The file path also provides context: `go/src/cmd/vendor/golang.org/x/sys/windows/`. This tells us it's part of the Go standard library's extension for system-level interactions on Windows. The `vendor` directory suggests it might be a vendored dependency.

**2. Initial Analysis of the Code Snippet:**

Scanning the provided code immediately reveals a pattern:

* **Constant Declarations:** Each line declares a constant using the Go syntax `const identifier syscall.Errno = value`.
* **`syscall.Errno` Type:** The type of each constant is `syscall.Errno`. This is a crucial piece of information, indicating these constants represent system error numbers.
* **Windows Error Code Naming Convention:** The constant names follow a clear convention: `ERROR_` followed by a descriptive name (e.g., `ERROR_ELEVATION_REQUIRED`). This directly maps to Windows API error codes.
* **Sequential Integer Values:** While not perfectly sequential, the integer values assigned to `syscall.Errno` generally increase. This reinforces the idea that they are distinct error codes.

**3. Inferring the Functionality:**

Based on the above observations, the primary function of this file is to:

* **Define Windows System Error Constants:**  It provides a way to refer to specific Windows error codes using meaningful Go constant names.
* **Map Windows Error Codes to `syscall.Errno`:** It bridges the gap between the numerical representation of Windows errors and Go's `syscall.Errno` type. This allows Go programs to handle Windows-specific errors in a type-safe and readable manner.

**4. Hypothesizing Go Language Feature Implementation:**

The natural conclusion is that this file is part of Go's integration with the Windows operating system. It's likely used in conjunction with Go's `syscall` package to interact with Windows API functions. When a Windows API call fails, it returns an error code. This file provides the Go constants that correspond to those error codes, making it easier to check for specific error conditions.

**5. Crafting a Go Code Example:**

To demonstrate the usage, a simple example involving a potential Windows API failure is needed. File operations are a common source of errors. The `os.Open` function is a good choice because it wraps the underlying Windows API call. The example should:

* Attempt an operation that could fail (opening a non-existent file).
* Check for errors.
* Use the constants from `zerrors_windows.go` to specifically identify the `ERROR_FILE_NOT_FOUND` error.

This leads to the example code provided in the initial good answer. The key is demonstrating how the defined constants are used for error comparison.

**6. Considering Inputs and Outputs (for the Code Example):**

* **Input:** The filename "non_existent_file.txt".
* **Expected Output:** If the file doesn't exist, the program should print "File not found!". This validates that the `ERROR_FILE_NOT_FOUND` constant is correctly identified.

**7. Addressing Command-Line Arguments:**

This particular file (`zerrors_windows.go`) doesn't directly process command-line arguments. Its purpose is to define constants. Therefore, the answer correctly states that command-line argument processing isn't relevant here.

**8. Identifying Common Mistakes:**

A potential pitfall for developers is directly comparing the `error` returned by functions with the integer values of Windows error codes. Go's error handling often wraps errors. The correct way is to check if the error is a `syscall.Errno` and then compare that `Errno` value with the defined constants. This is illustrated in the "Potential Pitfalls" section of the good answer.

**9. Summarizing the Functionality (for Part 2):**

Since this is part 2 of a 15-part series, the summary should focus on the specific set of error codes defined in this particular section of the file. It should reiterate the general purpose (mapping Windows errors) but narrow it down to the range of error codes present in the snippet.

**Self-Correction/Refinement During the Thought Process:**

* **Initial thought:**  Maybe this file is just a long list of magic numbers.
* **Correction:** The type `syscall.Errno` and the `ERROR_` prefix strongly suggest these are *system* error codes, not just arbitrary numbers.
* **Initial thought:** How do these constants get used?
* **Refinement:** They are used to compare against the `syscall.Errno` value of errors returned by system calls.
* **Initial thought:**  Should I explain all the error codes individually?
* **Correction:** That would be impractical given the sheer number of them. Focus on the general purpose and a specific example.

By following these steps, the answer can accurately and comprehensively address the prompt, covering the functionality, usage, potential pitfalls, and providing a clear summary.
Let's break down the functionality of this specific part (part 2) of the `zerrors_windows.go` file.

**Functionality:**

This section of the `zerrors_windows.go` file defines a large number of Go constants. Each constant represents a specific Windows system error code.

* **Mapping Windows Error Codes to Go Constants:**  The core function is to provide a symbolic name (a Go constant) for each numeric Windows error code. This makes it easier to read and write Go code that deals with Windows system errors. Instead of remembering or looking up magic numbers like `739`, developers can use meaningful names like `ERROR_ELEVATION_REQUIRED`.
* **Type Safety:**  By assigning the type `syscall.Errno` to each constant, Go's type system ensures that these constants are used in the correct context when interacting with system calls. `syscall.Errno` is Go's way of representing system-level errors.
* **Comprehensive Coverage (Partial):** This specific section covers a range of Windows error codes, continuing from the previous part and going up to `ERROR_PRINTER_DELETED`.

**Go Language Feature Implementation:**

This file is a crucial part of Go's ability to interact with the Windows operating system at a low level. Specifically, it facilitates the handling of errors returned by Windows system calls.

When a Go program makes a system call on Windows (using the `syscall` package or higher-level packages that internally use `syscall`), and that system call fails, it typically returns an error. This error often corresponds to one of the numeric error codes defined in this file.

Here's a Go code example illustrating its usage:

```go
package main

import (
	"fmt"
	"os"
	"syscall"
)

func main() {
	_, err := os.Open("non_existent_file.txt")
	if err != nil {
		errno := err.(syscall.Errno)
		if errno == syscall.ERROR_FILE_NOT_FOUND {
			fmt.Println("File not found!")
		} else if errno == syscall.ERROR_ACCESS_DENIED {
			fmt.Println("Access denied!")
		} else {
			fmt.Printf("An unexpected error occurred: %v (Error code: %d)\n", err, errno)
		}
	}
}
```

**Explanation of the Code Example:**

1. **`os.Open("non_existent_file.txt")`:** This attempts to open a file that likely doesn't exist. This is done to trigger a Windows system error.
2. **`if err != nil`:**  Checks if an error occurred during the file opening operation.
3. **`errno := err.(syscall.Errno)`:** This is a type assertion. It checks if the returned `error` is actually a `syscall.Errno`, which it will be for many system call errors on Windows.
4. **`if errno == syscall.ERROR_FILE_NOT_FOUND`:** This is where the constants from `zerrors_windows.go` are used. We compare the `errno` (the numeric error code returned by the system) with the Go constant `syscall.ERROR_FILE_NOT_FOUND`.
5. **Other Error Handling:** The `else if` block shows how you might check for other specific Windows errors using the defined constants.

**Assumptions and Input/Output for the Code Example:**

* **Assumption:** The file "non_existent_file.txt" does not exist in the current directory.
* **Input:** The program is executed.
* **Output:** The program will print: "File not found!"

If the file existed but the program didn't have permission to access it, the output would be: "Access denied!".

**Command-Line Parameter Handling:**

This specific file (`zerrors_windows.go`) does **not** handle command-line parameters. Its sole purpose is to define constants. The logic for handling command-line arguments would reside in other parts of the Go program that utilize these error constants.

**Potential Pitfalls for Users:**

* **Incorrect Error Type Assertion:**  A common mistake is to assume *all* errors returned from Windows-related operations are `syscall.Errno`. While many are, some might be higher-level errors. Always check the type of the error before attempting a type assertion.
* **Comparing Against Raw Numbers:**  Avoid comparing against the raw integer values of the error codes directly (e.g., `if errno == 1006`). Always use the defined constants for better readability and maintainability. The constants provide semantic meaning.
* **Platform-Specific Code:**  Code that relies heavily on these Windows-specific error codes will not be portable to other operating systems without significant modifications.

**Summary of Functionality (Part 2):**

This specific section of `go/src/cmd/vendor/golang.org/x/sys/windows/zerrors_windows.go` continues the process of defining Go constants that correspond to Windows system error codes, ranging from `ERROR_ELEVATION_REQUIRED` (740) up to `ERROR_PRINTER_DELETED`. This mapping allows Go programs to handle Windows-specific system errors in a type-safe and more readable manner by using symbolic names instead of raw error numbers. It's a fundamental part of Go's low-level interaction with the Windows operating system.

### 提示词
```
这是路径为go/src/cmd/vendor/golang.org/x/sys/windows/zerrors_windows.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第2部分，共15部分，请归纳一下它的功能
```

### 源代码
```go
syscall.Errno = 739
	ERROR_ELEVATION_REQUIRED                                                  syscall.Errno = 740
	ERROR_REPARSE                                                             syscall.Errno = 741
	ERROR_OPLOCK_BREAK_IN_PROGRESS                                            syscall.Errno = 742
	ERROR_VOLUME_MOUNTED                                                      syscall.Errno = 743
	ERROR_RXACT_COMMITTED                                                     syscall.Errno = 744
	ERROR_NOTIFY_CLEANUP                                                      syscall.Errno = 745
	ERROR_PRIMARY_TRANSPORT_CONNECT_FAILED                                    syscall.Errno = 746
	ERROR_PAGE_FAULT_TRANSITION                                               syscall.Errno = 747
	ERROR_PAGE_FAULT_DEMAND_ZERO                                              syscall.Errno = 748
	ERROR_PAGE_FAULT_COPY_ON_WRITE                                            syscall.Errno = 749
	ERROR_PAGE_FAULT_GUARD_PAGE                                               syscall.Errno = 750
	ERROR_PAGE_FAULT_PAGING_FILE                                              syscall.Errno = 751
	ERROR_CACHE_PAGE_LOCKED                                                   syscall.Errno = 752
	ERROR_CRASH_DUMP                                                          syscall.Errno = 753
	ERROR_BUFFER_ALL_ZEROS                                                    syscall.Errno = 754
	ERROR_REPARSE_OBJECT                                                      syscall.Errno = 755
	ERROR_RESOURCE_REQUIREMENTS_CHANGED                                       syscall.Errno = 756
	ERROR_TRANSLATION_COMPLETE                                                syscall.Errno = 757
	ERROR_NOTHING_TO_TERMINATE                                                syscall.Errno = 758
	ERROR_PROCESS_NOT_IN_JOB                                                  syscall.Errno = 759
	ERROR_PROCESS_IN_JOB                                                      syscall.Errno = 760
	ERROR_VOLSNAP_HIBERNATE_READY                                             syscall.Errno = 761
	ERROR_FSFILTER_OP_COMPLETED_SUCCESSFULLY                                  syscall.Errno = 762
	ERROR_INTERRUPT_VECTOR_ALREADY_CONNECTED                                  syscall.Errno = 763
	ERROR_INTERRUPT_STILL_CONNECTED                                           syscall.Errno = 764
	ERROR_WAIT_FOR_OPLOCK                                                     syscall.Errno = 765
	ERROR_DBG_EXCEPTION_HANDLED                                               syscall.Errno = 766
	ERROR_DBG_CONTINUE                                                        syscall.Errno = 767
	ERROR_CALLBACK_POP_STACK                                                  syscall.Errno = 768
	ERROR_COMPRESSION_DISABLED                                                syscall.Errno = 769
	ERROR_CANTFETCHBACKWARDS                                                  syscall.Errno = 770
	ERROR_CANTSCROLLBACKWARDS                                                 syscall.Errno = 771
	ERROR_ROWSNOTRELEASED                                                     syscall.Errno = 772
	ERROR_BAD_ACCESSOR_FLAGS                                                  syscall.Errno = 773
	ERROR_ERRORS_ENCOUNTERED                                                  syscall.Errno = 774
	ERROR_NOT_CAPABLE                                                         syscall.Errno = 775
	ERROR_REQUEST_OUT_OF_SEQUENCE                                             syscall.Errno = 776
	ERROR_VERSION_PARSE_ERROR                                                 syscall.Errno = 777
	ERROR_BADSTARTPOSITION                                                    syscall.Errno = 778
	ERROR_MEMORY_HARDWARE                                                     syscall.Errno = 779
	ERROR_DISK_REPAIR_DISABLED                                                syscall.Errno = 780
	ERROR_INSUFFICIENT_RESOURCE_FOR_SPECIFIED_SHARED_SECTION_SIZE             syscall.Errno = 781
	ERROR_SYSTEM_POWERSTATE_TRANSITION                                        syscall.Errno = 782
	ERROR_SYSTEM_POWERSTATE_COMPLEX_TRANSITION                                syscall.Errno = 783
	ERROR_MCA_EXCEPTION                                                       syscall.Errno = 784
	ERROR_ACCESS_AUDIT_BY_POLICY                                              syscall.Errno = 785
	ERROR_ACCESS_DISABLED_NO_SAFER_UI_BY_POLICY                               syscall.Errno = 786
	ERROR_ABANDON_HIBERFILE                                                   syscall.Errno = 787
	ERROR_LOST_WRITEBEHIND_DATA_NETWORK_DISCONNECTED                          syscall.Errno = 788
	ERROR_LOST_WRITEBEHIND_DATA_NETWORK_SERVER_ERROR                          syscall.Errno = 789
	ERROR_LOST_WRITEBEHIND_DATA_LOCAL_DISK_ERROR                              syscall.Errno = 790
	ERROR_BAD_MCFG_TABLE                                                      syscall.Errno = 791
	ERROR_DISK_REPAIR_REDIRECTED                                              syscall.Errno = 792
	ERROR_DISK_REPAIR_UNSUCCESSFUL                                            syscall.Errno = 793
	ERROR_CORRUPT_LOG_OVERFULL                                                syscall.Errno = 794
	ERROR_CORRUPT_LOG_CORRUPTED                                               syscall.Errno = 795
	ERROR_CORRUPT_LOG_UNAVAILABLE                                             syscall.Errno = 796
	ERROR_CORRUPT_LOG_DELETED_FULL                                            syscall.Errno = 797
	ERROR_CORRUPT_LOG_CLEARED                                                 syscall.Errno = 798
	ERROR_ORPHAN_NAME_EXHAUSTED                                               syscall.Errno = 799
	ERROR_OPLOCK_SWITCHED_TO_NEW_HANDLE                                       syscall.Errno = 800
	ERROR_CANNOT_GRANT_REQUESTED_OPLOCK                                       syscall.Errno = 801
	ERROR_CANNOT_BREAK_OPLOCK                                                 syscall.Errno = 802
	ERROR_OPLOCK_HANDLE_CLOSED                                                syscall.Errno = 803
	ERROR_NO_ACE_CONDITION                                                    syscall.Errno = 804
	ERROR_INVALID_ACE_CONDITION                                               syscall.Errno = 805
	ERROR_FILE_HANDLE_REVOKED                                                 syscall.Errno = 806
	ERROR_IMAGE_AT_DIFFERENT_BASE                                             syscall.Errno = 807
	ERROR_ENCRYPTED_IO_NOT_POSSIBLE                                           syscall.Errno = 808
	ERROR_FILE_METADATA_OPTIMIZATION_IN_PROGRESS                              syscall.Errno = 809
	ERROR_QUOTA_ACTIVITY                                                      syscall.Errno = 810
	ERROR_HANDLE_REVOKED                                                      syscall.Errno = 811
	ERROR_CALLBACK_INVOKE_INLINE                                              syscall.Errno = 812
	ERROR_CPU_SET_INVALID                                                     syscall.Errno = 813
	ERROR_ENCLAVE_NOT_TERMINATED                                              syscall.Errno = 814
	ERROR_ENCLAVE_VIOLATION                                                   syscall.Errno = 815
	ERROR_EA_ACCESS_DENIED                                                    syscall.Errno = 994
	ERROR_OPERATION_ABORTED                                                   syscall.Errno = 995
	ERROR_IO_INCOMPLETE                                                       syscall.Errno = 996
	ERROR_IO_PENDING                                                          syscall.Errno = 997
	ERROR_NOACCESS                                                            syscall.Errno = 998
	ERROR_SWAPERROR                                                           syscall.Errno = 999
	ERROR_STACK_OVERFLOW                                                      syscall.Errno = 1001
	ERROR_INVALID_MESSAGE                                                     syscall.Errno = 1002
	ERROR_CAN_NOT_COMPLETE                                                    syscall.Errno = 1003
	ERROR_INVALID_FLAGS                                                       syscall.Errno = 1004
	ERROR_UNRECOGNIZED_VOLUME                                                 syscall.Errno = 1005
	ERROR_FILE_INVALID                                                        syscall.Errno = 1006
	ERROR_FULLSCREEN_MODE                                                     syscall.Errno = 1007
	ERROR_NO_TOKEN                                                            syscall.Errno = 1008
	ERROR_BADDB                                                               syscall.Errno = 1009
	ERROR_BADKEY                                                              syscall.Errno = 1010
	ERROR_CANTOPEN                                                            syscall.Errno = 1011
	ERROR_CANTREAD                                                            syscall.Errno = 1012
	ERROR_CANTWRITE                                                           syscall.Errno = 1013
	ERROR_REGISTRY_RECOVERED                                                  syscall.Errno = 1014
	ERROR_REGISTRY_CORRUPT                                                    syscall.Errno = 1015
	ERROR_REGISTRY_IO_FAILED                                                  syscall.Errno = 1016
	ERROR_NOT_REGISTRY_FILE                                                   syscall.Errno = 1017
	ERROR_KEY_DELETED                                                         syscall.Errno = 1018
	ERROR_NO_LOG_SPACE                                                        syscall.Errno = 1019
	ERROR_KEY_HAS_CHILDREN                                                    syscall.Errno = 1020
	ERROR_CHILD_MUST_BE_VOLATILE                                              syscall.Errno = 1021
	ERROR_NOTIFY_ENUM_DIR                                                     syscall.Errno = 1022
	ERROR_DEPENDENT_SERVICES_RUNNING                                          syscall.Errno = 1051
	ERROR_INVALID_SERVICE_CONTROL                                             syscall.Errno = 1052
	ERROR_SERVICE_REQUEST_TIMEOUT                                             syscall.Errno = 1053
	ERROR_SERVICE_NO_THREAD                                                   syscall.Errno = 1054
	ERROR_SERVICE_DATABASE_LOCKED                                             syscall.Errno = 1055
	ERROR_SERVICE_ALREADY_RUNNING                                             syscall.Errno = 1056
	ERROR_INVALID_SERVICE_ACCOUNT                                             syscall.Errno = 1057
	ERROR_SERVICE_DISABLED                                                    syscall.Errno = 1058
	ERROR_CIRCULAR_DEPENDENCY                                                 syscall.Errno = 1059
	ERROR_SERVICE_DOES_NOT_EXIST                                              syscall.Errno = 1060
	ERROR_SERVICE_CANNOT_ACCEPT_CTRL                                          syscall.Errno = 1061
	ERROR_SERVICE_NOT_ACTIVE                                                  syscall.Errno = 1062
	ERROR_FAILED_SERVICE_CONTROLLER_CONNECT                                   syscall.Errno = 1063
	ERROR_EXCEPTION_IN_SERVICE                                                syscall.Errno = 1064
	ERROR_DATABASE_DOES_NOT_EXIST                                             syscall.Errno = 1065
	ERROR_SERVICE_SPECIFIC_ERROR                                              syscall.Errno = 1066
	ERROR_PROCESS_ABORTED                                                     syscall.Errno = 1067
	ERROR_SERVICE_DEPENDENCY_FAIL                                             syscall.Errno = 1068
	ERROR_SERVICE_LOGON_FAILED                                                syscall.Errno = 1069
	ERROR_SERVICE_START_HANG                                                  syscall.Errno = 1070
	ERROR_INVALID_SERVICE_LOCK                                                syscall.Errno = 1071
	ERROR_SERVICE_MARKED_FOR_DELETE                                           syscall.Errno = 1072
	ERROR_SERVICE_EXISTS                                                      syscall.Errno = 1073
	ERROR_ALREADY_RUNNING_LKG                                                 syscall.Errno = 1074
	ERROR_SERVICE_DEPENDENCY_DELETED                                          syscall.Errno = 1075
	ERROR_BOOT_ALREADY_ACCEPTED                                               syscall.Errno = 1076
	ERROR_SERVICE_NEVER_STARTED                                               syscall.Errno = 1077
	ERROR_DUPLICATE_SERVICE_NAME                                              syscall.Errno = 1078
	ERROR_DIFFERENT_SERVICE_ACCOUNT                                           syscall.Errno = 1079
	ERROR_CANNOT_DETECT_DRIVER_FAILURE                                        syscall.Errno = 1080
	ERROR_CANNOT_DETECT_PROCESS_ABORT                                         syscall.Errno = 1081
	ERROR_NO_RECOVERY_PROGRAM                                                 syscall.Errno = 1082
	ERROR_SERVICE_NOT_IN_EXE                                                  syscall.Errno = 1083
	ERROR_NOT_SAFEBOOT_SERVICE                                                syscall.Errno = 1084
	ERROR_END_OF_MEDIA                                                        syscall.Errno = 1100
	ERROR_FILEMARK_DETECTED                                                   syscall.Errno = 1101
	ERROR_BEGINNING_OF_MEDIA                                                  syscall.Errno = 1102
	ERROR_SETMARK_DETECTED                                                    syscall.Errno = 1103
	ERROR_NO_DATA_DETECTED                                                    syscall.Errno = 1104
	ERROR_PARTITION_FAILURE                                                   syscall.Errno = 1105
	ERROR_INVALID_BLOCK_LENGTH                                                syscall.Errno = 1106
	ERROR_DEVICE_NOT_PARTITIONED                                              syscall.Errno = 1107
	ERROR_UNABLE_TO_LOCK_MEDIA                                                syscall.Errno = 1108
	ERROR_UNABLE_TO_UNLOAD_MEDIA                                              syscall.Errno = 1109
	ERROR_MEDIA_CHANGED                                                       syscall.Errno = 1110
	ERROR_BUS_RESET                                                           syscall.Errno = 1111
	ERROR_NO_MEDIA_IN_DRIVE                                                   syscall.Errno = 1112
	ERROR_NO_UNICODE_TRANSLATION                                              syscall.Errno = 1113
	ERROR_DLL_INIT_FAILED                                                     syscall.Errno = 1114
	ERROR_SHUTDOWN_IN_PROGRESS                                                syscall.Errno = 1115
	ERROR_NO_SHUTDOWN_IN_PROGRESS                                             syscall.Errno = 1116
	ERROR_IO_DEVICE                                                           syscall.Errno = 1117
	ERROR_SERIAL_NO_DEVICE                                                    syscall.Errno = 1118
	ERROR_IRQ_BUSY                                                            syscall.Errno = 1119
	ERROR_MORE_WRITES                                                         syscall.Errno = 1120
	ERROR_COUNTER_TIMEOUT                                                     syscall.Errno = 1121
	ERROR_FLOPPY_ID_MARK_NOT_FOUND                                            syscall.Errno = 1122
	ERROR_FLOPPY_WRONG_CYLINDER                                               syscall.Errno = 1123
	ERROR_FLOPPY_UNKNOWN_ERROR                                                syscall.Errno = 1124
	ERROR_FLOPPY_BAD_REGISTERS                                                syscall.Errno = 1125
	ERROR_DISK_RECALIBRATE_FAILED                                             syscall.Errno = 1126
	ERROR_DISK_OPERATION_FAILED                                               syscall.Errno = 1127
	ERROR_DISK_RESET_FAILED                                                   syscall.Errno = 1128
	ERROR_EOM_OVERFLOW                                                        syscall.Errno = 1129
	ERROR_NOT_ENOUGH_SERVER_MEMORY                                            syscall.Errno = 1130
	ERROR_POSSIBLE_DEADLOCK                                                   syscall.Errno = 1131
	ERROR_MAPPED_ALIGNMENT                                                    syscall.Errno = 1132
	ERROR_SET_POWER_STATE_VETOED                                              syscall.Errno = 1140
	ERROR_SET_POWER_STATE_FAILED                                              syscall.Errno = 1141
	ERROR_TOO_MANY_LINKS                                                      syscall.Errno = 1142
	ERROR_OLD_WIN_VERSION                                                     syscall.Errno = 1150
	ERROR_APP_WRONG_OS                                                        syscall.Errno = 1151
	ERROR_SINGLE_INSTANCE_APP                                                 syscall.Errno = 1152
	ERROR_RMODE_APP                                                           syscall.Errno = 1153
	ERROR_INVALID_DLL                                                         syscall.Errno = 1154
	ERROR_NO_ASSOCIATION                                                      syscall.Errno = 1155
	ERROR_DDE_FAIL                                                            syscall.Errno = 1156
	ERROR_DLL_NOT_FOUND                                                       syscall.Errno = 1157
	ERROR_NO_MORE_USER_HANDLES                                                syscall.Errno = 1158
	ERROR_MESSAGE_SYNC_ONLY                                                   syscall.Errno = 1159
	ERROR_SOURCE_ELEMENT_EMPTY                                                syscall.Errno = 1160
	ERROR_DESTINATION_ELEMENT_FULL                                            syscall.Errno = 1161
	ERROR_ILLEGAL_ELEMENT_ADDRESS                                             syscall.Errno = 1162
	ERROR_MAGAZINE_NOT_PRESENT                                                syscall.Errno = 1163
	ERROR_DEVICE_REINITIALIZATION_NEEDED                                      syscall.Errno = 1164
	ERROR_DEVICE_REQUIRES_CLEANING                                            syscall.Errno = 1165
	ERROR_DEVICE_DOOR_OPEN                                                    syscall.Errno = 1166
	ERROR_DEVICE_NOT_CONNECTED                                                syscall.Errno = 1167
	ERROR_NOT_FOUND                                                           syscall.Errno = 1168
	ERROR_NO_MATCH                                                            syscall.Errno = 1169
	ERROR_SET_NOT_FOUND                                                       syscall.Errno = 1170
	ERROR_POINT_NOT_FOUND                                                     syscall.Errno = 1171
	ERROR_NO_TRACKING_SERVICE                                                 syscall.Errno = 1172
	ERROR_NO_VOLUME_ID                                                        syscall.Errno = 1173
	ERROR_UNABLE_TO_REMOVE_REPLACED                                           syscall.Errno = 1175
	ERROR_UNABLE_TO_MOVE_REPLACEMENT                                          syscall.Errno = 1176
	ERROR_UNABLE_TO_MOVE_REPLACEMENT_2                                        syscall.Errno = 1177
	ERROR_JOURNAL_DELETE_IN_PROGRESS                                          syscall.Errno = 1178
	ERROR_JOURNAL_NOT_ACTIVE                                                  syscall.Errno = 1179
	ERROR_POTENTIAL_FILE_FOUND                                                syscall.Errno = 1180
	ERROR_JOURNAL_ENTRY_DELETED                                               syscall.Errno = 1181
	ERROR_SHUTDOWN_IS_SCHEDULED                                               syscall.Errno = 1190
	ERROR_SHUTDOWN_USERS_LOGGED_ON                                            syscall.Errno = 1191
	ERROR_BAD_DEVICE                                                          syscall.Errno = 1200
	ERROR_CONNECTION_UNAVAIL                                                  syscall.Errno = 1201
	ERROR_DEVICE_ALREADY_REMEMBERED                                           syscall.Errno = 1202
	ERROR_NO_NET_OR_BAD_PATH                                                  syscall.Errno = 1203
	ERROR_BAD_PROVIDER                                                        syscall.Errno = 1204
	ERROR_CANNOT_OPEN_PROFILE                                                 syscall.Errno = 1205
	ERROR_BAD_PROFILE                                                         syscall.Errno = 1206
	ERROR_NOT_CONTAINER                                                       syscall.Errno = 1207
	ERROR_EXTENDED_ERROR                                                      syscall.Errno = 1208
	ERROR_INVALID_GROUPNAME                                                   syscall.Errno = 1209
	ERROR_INVALID_COMPUTERNAME                                                syscall.Errno = 1210
	ERROR_INVALID_EVENTNAME                                                   syscall.Errno = 1211
	ERROR_INVALID_DOMAINNAME                                                  syscall.Errno = 1212
	ERROR_INVALID_SERVICENAME                                                 syscall.Errno = 1213
	ERROR_INVALID_NETNAME                                                     syscall.Errno = 1214
	ERROR_INVALID_SHARENAME                                                   syscall.Errno = 1215
	ERROR_INVALID_PASSWORDNAME                                                syscall.Errno = 1216
	ERROR_INVALID_MESSAGENAME                                                 syscall.Errno = 1217
	ERROR_INVALID_MESSAGEDEST                                                 syscall.Errno = 1218
	ERROR_SESSION_CREDENTIAL_CONFLICT                                         syscall.Errno = 1219
	ERROR_REMOTE_SESSION_LIMIT_EXCEEDED                                       syscall.Errno = 1220
	ERROR_DUP_DOMAINNAME                                                      syscall.Errno = 1221
	ERROR_NO_NETWORK                                                          syscall.Errno = 1222
	ERROR_CANCELLED                                                           syscall.Errno = 1223
	ERROR_USER_MAPPED_FILE                                                    syscall.Errno = 1224
	ERROR_CONNECTION_REFUSED                                                  syscall.Errno = 1225
	ERROR_GRACEFUL_DISCONNECT                                                 syscall.Errno = 1226
	ERROR_ADDRESS_ALREADY_ASSOCIATED                                          syscall.Errno = 1227
	ERROR_ADDRESS_NOT_ASSOCIATED                                              syscall.Errno = 1228
	ERROR_CONNECTION_INVALID                                                  syscall.Errno = 1229
	ERROR_CONNECTION_ACTIVE                                                   syscall.Errno = 1230
	ERROR_NETWORK_UNREACHABLE                                                 syscall.Errno = 1231
	ERROR_HOST_UNREACHABLE                                                    syscall.Errno = 1232
	ERROR_PROTOCOL_UNREACHABLE                                                syscall.Errno = 1233
	ERROR_PORT_UNREACHABLE                                                    syscall.Errno = 1234
	ERROR_REQUEST_ABORTED                                                     syscall.Errno = 1235
	ERROR_CONNECTION_ABORTED                                                  syscall.Errno = 1236
	ERROR_RETRY                                                               syscall.Errno = 1237
	ERROR_CONNECTION_COUNT_LIMIT                                              syscall.Errno = 1238
	ERROR_LOGIN_TIME_RESTRICTION                                              syscall.Errno = 1239
	ERROR_LOGIN_WKSTA_RESTRICTION                                             syscall.Errno = 1240
	ERROR_INCORRECT_ADDRESS                                                   syscall.Errno = 1241
	ERROR_ALREADY_REGISTERED                                                  syscall.Errno = 1242
	ERROR_SERVICE_NOT_FOUND                                                   syscall.Errno = 1243
	ERROR_NOT_AUTHENTICATED                                                   syscall.Errno = 1244
	ERROR_NOT_LOGGED_ON                                                       syscall.Errno = 1245
	ERROR_CONTINUE                                                            syscall.Errno = 1246
	ERROR_ALREADY_INITIALIZED                                                 syscall.Errno = 1247
	ERROR_NO_MORE_DEVICES                                                     syscall.Errno = 1248
	ERROR_NO_SUCH_SITE                                                        syscall.Errno = 1249
	ERROR_DOMAIN_CONTROLLER_EXISTS                                            syscall.Errno = 1250
	ERROR_ONLY_IF_CONNECTED                                                   syscall.Errno = 1251
	ERROR_OVERRIDE_NOCHANGES                                                  syscall.Errno = 1252
	ERROR_BAD_USER_PROFILE                                                    syscall.Errno = 1253
	ERROR_NOT_SUPPORTED_ON_SBS                                                syscall.Errno = 1254
	ERROR_SERVER_SHUTDOWN_IN_PROGRESS                                         syscall.Errno = 1255
	ERROR_HOST_DOWN                                                           syscall.Errno = 1256
	ERROR_NON_ACCOUNT_SID                                                     syscall.Errno = 1257
	ERROR_NON_DOMAIN_SID                                                      syscall.Errno = 1258
	ERROR_APPHELP_BLOCK                                                       syscall.Errno = 1259
	ERROR_ACCESS_DISABLED_BY_POLICY                                           syscall.Errno = 1260
	ERROR_REG_NAT_CONSUMPTION                                                 syscall.Errno = 1261
	ERROR_CSCSHARE_OFFLINE                                                    syscall.Errno = 1262
	ERROR_PKINIT_FAILURE                                                      syscall.Errno = 1263
	ERROR_SMARTCARD_SUBSYSTEM_FAILURE                                         syscall.Errno = 1264
	ERROR_DOWNGRADE_DETECTED                                                  syscall.Errno = 1265
	ERROR_MACHINE_LOCKED                                                      syscall.Errno = 1271
	ERROR_SMB_GUEST_LOGON_BLOCKED                                             syscall.Errno = 1272
	ERROR_CALLBACK_SUPPLIED_INVALID_DATA                                      syscall.Errno = 1273
	ERROR_SYNC_FOREGROUND_REFRESH_REQUIRED                                    syscall.Errno = 1274
	ERROR_DRIVER_BLOCKED                                                      syscall.Errno = 1275
	ERROR_INVALID_IMPORT_OF_NON_DLL                                           syscall.Errno = 1276
	ERROR_ACCESS_DISABLED_WEBBLADE                                            syscall.Errno = 1277
	ERROR_ACCESS_DISABLED_WEBBLADE_TAMPER                                     syscall.Errno = 1278
	ERROR_RECOVERY_FAILURE                                                    syscall.Errno = 1279
	ERROR_ALREADY_FIBER                                                       syscall.Errno = 1280
	ERROR_ALREADY_THREAD                                                      syscall.Errno = 1281
	ERROR_STACK_BUFFER_OVERRUN                                                syscall.Errno = 1282
	ERROR_PARAMETER_QUOTA_EXCEEDED                                            syscall.Errno = 1283
	ERROR_DEBUGGER_INACTIVE                                                   syscall.Errno = 1284
	ERROR_DELAY_LOAD_FAILED                                                   syscall.Errno = 1285
	ERROR_VDM_DISALLOWED                                                      syscall.Errno = 1286
	ERROR_UNIDENTIFIED_ERROR                                                  syscall.Errno = 1287
	ERROR_INVALID_CRUNTIME_PARAMETER                                          syscall.Errno = 1288
	ERROR_BEYOND_VDL                                                          syscall.Errno = 1289
	ERROR_INCOMPATIBLE_SERVICE_SID_TYPE                                       syscall.Errno = 1290
	ERROR_DRIVER_PROCESS_TERMINATED                                           syscall.Errno = 1291
	ERROR_IMPLEMENTATION_LIMIT                                                syscall.Errno = 1292
	ERROR_PROCESS_IS_PROTECTED                                                syscall.Errno = 1293
	ERROR_SERVICE_NOTIFY_CLIENT_LAGGING                                       syscall.Errno = 1294
	ERROR_DISK_QUOTA_EXCEEDED                                                 syscall.Errno = 1295
	ERROR_CONTENT_BLOCKED                                                     syscall.Errno = 1296
	ERROR_INCOMPATIBLE_SERVICE_PRIVILEGE                                      syscall.Errno = 1297
	ERROR_APP_HANG                                                            syscall.Errno = 1298
	ERROR_INVALID_LABEL                                                       syscall.Errno = 1299
	ERROR_NOT_ALL_ASSIGNED                                                    syscall.Errno = 1300
	ERROR_SOME_NOT_MAPPED                                                     syscall.Errno = 1301
	ERROR_NO_QUOTAS_FOR_ACCOUNT                                               syscall.Errno = 1302
	ERROR_LOCAL_USER_SESSION_KEY                                              syscall.Errno = 1303
	ERROR_NULL_LM_PASSWORD                                                    syscall.Errno = 1304
	ERROR_UNKNOWN_REVISION                                                    syscall.Errno = 1305
	ERROR_REVISION_MISMATCH                                                   syscall.Errno = 1306
	ERROR_INVALID_OWNER                                                       syscall.Errno = 1307
	ERROR_INVALID_PRIMARY_GROUP                                               syscall.Errno = 1308
	ERROR_NO_IMPERSONATION_TOKEN                                              syscall.Errno = 1309
	ERROR_CANT_DISABLE_MANDATORY                                              syscall.Errno = 1310
	ERROR_NO_LOGON_SERVERS                                                    syscall.Errno = 1311
	ERROR_NO_SUCH_LOGON_SESSION                                               syscall.Errno = 1312
	ERROR_NO_SUCH_PRIVILEGE                                                   syscall.Errno = 1313
	ERROR_PRIVILEGE_NOT_HELD                                                  syscall.Errno = 1314
	ERROR_INVALID_ACCOUNT_NAME                                                syscall.Errno = 1315
	ERROR_USER_EXISTS                                                         syscall.Errno = 1316
	ERROR_NO_SUCH_USER                                                        syscall.Errno = 1317
	ERROR_GROUP_EXISTS                                                        syscall.Errno = 1318
	ERROR_NO_SUCH_GROUP                                                       syscall.Errno = 1319
	ERROR_MEMBER_IN_GROUP                                                     syscall.Errno = 1320
	ERROR_MEMBER_NOT_IN_GROUP                                                 syscall.Errno = 1321
	ERROR_LAST_ADMIN                                                          syscall.Errno = 1322
	ERROR_WRONG_PASSWORD                                                      syscall.Errno = 1323
	ERROR_ILL_FORMED_PASSWORD                                                 syscall.Errno = 1324
	ERROR_PASSWORD_RESTRICTION                                                syscall.Errno = 1325
	ERROR_LOGON_FAILURE                                                       syscall.Errno = 1326
	ERROR_ACCOUNT_RESTRICTION                                                 syscall.Errno = 1327
	ERROR_INVALID_LOGON_HOURS                                                 syscall.Errno = 1328
	ERROR_INVALID_WORKSTATION                                                 syscall.Errno = 1329
	ERROR_PASSWORD_EXPIRED                                                    syscall.Errno = 1330
	ERROR_ACCOUNT_DISABLED                                                    syscall.Errno = 1331
	ERROR_NONE_MAPPED                                                         syscall.Errno = 1332
	ERROR_TOO_MANY_LUIDS_REQUESTED                                            syscall.Errno = 1333
	ERROR_LUIDS_EXHAUSTED                                                     syscall.Errno = 1334
	ERROR_INVALID_SUB_AUTHORITY                                               syscall.Errno = 1335
	ERROR_INVALID_ACL                                                         syscall.Errno = 1336
	ERROR_INVALID_SID                                                         syscall.Errno = 1337
	ERROR_INVALID_SECURITY_DESCR                                              syscall.Errno = 1338
	ERROR_BAD_INHERITANCE_ACL                                                 syscall.Errno = 1340
	ERROR_SERVER_DISABLED                                                     syscall.Errno = 1341
	ERROR_SERVER_NOT_DISABLED                                                 syscall.Errno = 1342
	ERROR_INVALID_ID_AUTHORITY                                                syscall.Errno = 1343
	ERROR_ALLOTTED_SPACE_EXCEEDED                                             syscall.Errno = 1344
	ERROR_INVALID_GROUP_ATTRIBUTES                                            syscall.Errno = 1345
	ERROR_BAD_IMPERSONATION_LEVEL                                             syscall.Errno = 1346
	ERROR_CANT_OPEN_ANONYMOUS                                                 syscall.Errno = 1347
	ERROR_BAD_VALIDATION_CLASS                                                syscall.Errno = 1348
	ERROR_BAD_TOKEN_TYPE                                                      syscall.Errno = 1349
	ERROR_NO_SECURITY_ON_OBJECT                                               syscall.Errno = 1350
	ERROR_CANT_ACCESS_DOMAIN_INFO                                             syscall.Errno = 1351
	ERROR_INVALID_SERVER_STATE                                                syscall.Errno = 1352
	ERROR_INVALID_DOMAIN_STATE                                                syscall.Errno = 1353
	ERROR_INVALID_DOMAIN_ROLE                                                 syscall.Errno = 1354
	ERROR_NO_SUCH_DOMAIN                                                      syscall.Errno = 1355
	ERROR_DOMAIN_EXISTS                                                       syscall.Errno = 1356
	ERROR_DOMAIN_LIMIT_EXCEEDED                                               syscall.Errno = 1357
	ERROR_INTERNAL_DB_CORRUPTION                                              syscall.Errno = 1358
	ERROR_INTERNAL_ERROR                                                      syscall.Errno = 1359
	ERROR_GENERIC_NOT_MAPPED                                                  syscall.Errno = 1360
	ERROR_BAD_DESCRIPTOR_FORMAT                                               syscall.Errno = 1361
	ERROR_NOT_LOGON_PROCESS                                                   syscall.Errno = 1362
	ERROR_LOGON_SESSION_EXISTS                                                syscall.Errno = 1363
	ERROR_NO_SUCH_PACKAGE                                                     syscall.Errno = 1364
	ERROR_BAD_LOGON_SESSION_STATE                                             syscall.Errno = 1365
	ERROR_LOGON_SESSION_COLLISION                                             syscall.Errno = 1366
	ERROR_INVALID_LOGON_TYPE                                                  syscall.Errno = 1367
	ERROR_CANNOT_IMPERSONATE                                                  syscall.Errno = 1368
	ERROR_RXACT_INVALID_STATE                                                 syscall.Errno = 1369
	ERROR_RXACT_COMMIT_FAILURE                                                syscall.Errno = 1370
	ERROR_SPECIAL_ACCOUNT                                                     syscall.Errno = 1371
	ERROR_SPECIAL_GROUP                                                       syscall.Errno = 1372
	ERROR_SPECIAL_USER                                                        syscall.Errno = 1373
	ERROR_MEMBERS_PRIMARY_GROUP                                               syscall.Errno = 1374
	ERROR_TOKEN_ALREADY_IN_USE                                                syscall.Errno = 1375
	ERROR_NO_SUCH_ALIAS                                                       syscall.Errno = 1376
	ERROR_MEMBER_NOT_IN_ALIAS                                                 syscall.Errno = 1377
	ERROR_MEMBER_IN_ALIAS                                                     syscall.Errno = 1378
	ERROR_ALIAS_EXISTS                                                        syscall.Errno = 1379
	ERROR_LOGON_NOT_GRANTED                                                   syscall.Errno = 1380
	ERROR_TOO_MANY_SECRETS                                                    syscall.Errno = 1381
	ERROR_SECRET_TOO_LONG                                                     syscall.Errno = 1382
	ERROR_INTERNAL_DB_ERROR                                                   syscall.Errno = 1383
	ERROR_TOO_MANY_CONTEXT_IDS                                                syscall.Errno = 1384
	ERROR_LOGON_TYPE_NOT_GRANTED                                              syscall.Errno = 1385
	ERROR_NT_CROSS_ENCRYPTION_REQUIRED                                        syscall.Errno = 1386
	ERROR_NO_SUCH_MEMBER                                                      syscall.Errno = 1387
	ERROR_INVALID_MEMBER                                                      syscall.Errno = 1388
	ERROR_TOO_MANY_SIDS                                                       syscall.Errno = 1389
	ERROR_LM_CROSS_ENCRYPTION_REQUIRED                                        syscall.Errno = 1390
	ERROR_NO_INHERITANCE                                                      syscall.Errno = 1391
	ERROR_FILE_CORRUPT                                                        syscall.Errno = 1392
	ERROR_DISK_CORRUPT                                                        syscall.Errno = 1393
	ERROR_NO_USER_SESSION_KEY                                                 syscall.Errno = 1394
	ERROR_LICENSE_QUOTA_EXCEEDED                                              syscall.Errno = 1395
	ERROR_WRONG_TARGET_NAME                                                   syscall.Errno = 1396
	ERROR_MUTUAL_AUTH_FAILED                                                  syscall.Errno = 1397
	ERROR_TIME_SKEW                                                           syscall.Errno = 1398
	ERROR_CURRENT_DOMAIN_NOT_ALLOWED                                          syscall.Errno = 1399
	ERROR_INVALID_WINDOW_HANDLE                                               syscall.Errno = 1400
	ERROR_INVALID_MENU_HANDLE                                                 syscall.Errno = 1401
	ERROR_INVALID_CURSOR_HANDLE                                               syscall.Errno = 1402
	ERROR_INVALID_ACCEL_HANDLE                                                syscall.Errno = 1403
	ERROR_INVALID_HOOK_HANDLE                                                 syscall.Errno = 1404
	ERROR_INVALID_DWP_HANDLE                                                  syscall.Errno = 1405
	ERROR_TLW_WITH_WSCHILD                                                    syscall.Errno = 1406
	ERROR_CANNOT_FIND_WND_CLASS                                               syscall.Errno = 1407
	ERROR_WINDOW_OF_OTHER_THREAD                                              syscall.Errno = 1408
	ERROR_HOTKEY_ALREADY_REGISTERED                                           syscall.Errno = 1409
	ERROR_CLASS_ALREADY_EXISTS                                                syscall.Errno = 1410
	ERROR_CLASS_DOES_NOT_EXIST                                                syscall.Errno = 1411
	ERROR_CLASS_HAS_WINDOWS                                                   syscall.Errno = 1412
	ERROR_INVALID_INDEX                                                       syscall.Errno = 1413
	ERROR_INVALID_ICON_HANDLE                                                 syscall.Errno = 1414
	ERROR_PRIVATE_DIALOG_INDEX                                                syscall.Errno = 1415
	ERROR_LISTBOX_ID_NOT_FOUND                                                syscall.Errno = 1416
	ERROR_NO_WILDCARD_CHARACTERS                                              syscall.Errno = 1417
	ERROR_CLIPBOARD_NOT_OPEN                                                  syscall.Errno = 1418
	ERROR_HOTKEY_NOT_REGISTERED                                               syscall.Errno = 1419
	ERROR_WINDOW_NOT_DIALOG                                                   syscall.Errno = 1420
	ERROR_CONTROL_ID_NOT_FOUND                                                syscall.Errno = 1421
	ERROR_INVALID_COMBOBOX_MESSAGE                                            syscall.Errno = 1422
	ERROR_WINDOW_NOT_COMBOBOX                                                 syscall.Errno = 1423
	ERROR_INVALID_EDIT_HEIGHT                                                 syscall.Errno = 1424
	ERROR_DC_NOT_FOUND                                                        syscall.Errno = 1425
	ERROR_INVALID_HOOK_FILTER                                                 syscall.Errno = 1426
	ERROR_INVALID_FILTER_PROC                                                 syscall.Errno = 1427
	ERROR_HOOK_NEEDS_HMOD                                                     syscall.Errno = 1428
	ERROR_GLOBAL_ONLY_HOOK                                                    syscall.Errno = 1429
	ERROR_JOURNAL_HOOK_SET                                                    syscall.Errno = 1430
	ERROR_HOOK_NOT_INSTALLED                                                  syscall.Errno = 1431
	ERROR_INVALID_LB_MESSAGE                                                  syscall.Errno = 1432
	ERROR_SETCOUNT_ON_BAD_LB                                                  syscall.Errno = 1433
	ERROR_LB_WITHOUT_TABSTOPS                                                 syscall.Errno = 1434
	ERROR_DESTROY_OBJECT_OF_OTHER_THREAD                                      syscall.Errno = 1435
	ERROR_CHILD_WINDOW_MENU                                                   syscall.Errno = 1436
	ERROR_NO_SYSTEM_MENU                                                      syscall.Errno = 1437
	ERROR_INVALID_MSGBOX_STYLE                                                syscall.Errno = 1438
	ERROR_INVALID_SPI_VALUE                                                   syscall.Errno = 1439
	ERROR_SCREEN_ALREADY_LOCKED                                               syscall.Errno = 1440
	ERROR_HWNDS_HAVE_DIFF_PARENT                                              syscall.Errno = 1441
	ERROR_NOT_CHILD_WINDOW                                                    syscall.Errno = 1442
	ERROR_INVALID_GW_COMMAND                                                  syscall.Errno = 1443
	ERROR_INVALID_THREAD_ID                                                   syscall.Errno = 1444
	ERROR_NON_MDICHILD_WINDOW                                                 syscall.Errno = 1445
	ERROR_POPUP_ALREADY_ACTIVE                                                syscall.Errno = 1446
	ERROR_NO_SCROLLBARS                                                       syscall.Errno = 1447
	ERROR_INVALID_SCROLLBAR_RANGE                                             syscall.Errno = 1448
	ERROR_INVALID_SHOWWIN_COMMAND                                             syscall.Errno = 1449
	ERROR_NO_SYSTEM_RESOURCES                                                 syscall.Errno = 1450
	ERROR_NONPAGED_SYSTEM_RESOURCES                                           syscall.Errno = 1451
	ERROR_PAGED_SYSTEM_RESOURCES                                              syscall.Errno = 1452
	ERROR_WORKING_SET_QUOTA                                                   syscall.Errno = 1453
	ERROR_PAGEFILE_QUOTA                                                      syscall.Errno = 1454
	ERROR_COMMITMENT_LIMIT                                                    syscall.Errno = 1455
	ERROR_MENU_ITEM_NOT_FOUND                                                 syscall.Errno = 1456
	ERROR_INVALID_KEYBOARD_HANDLE                                             syscall.Errno = 1457
	ERROR_HOOK_TYPE_NOT_ALLOWED                                               syscall.Errno = 1458
	ERROR_REQUIRES_INTERACTIVE_WINDOWSTATION                                  syscall.Errno = 1459
	ERROR_TIMEOUT                                                             syscall.Errno = 1460
	ERROR_INVALID_MONITOR_HANDLE                                              syscall.Errno = 1461
	ERROR_INCORRECT_SIZE                                                      syscall.Errno = 1462
	ERROR_SYMLINK_CLASS_DISABLED                                              syscall.Errno = 1463
	ERROR_SYMLINK_NOT_SUPPORTED                                               syscall.Errno = 1464
	ERROR_XML_PARSE_ERROR                                                     syscall.Errno = 1465
	ERROR_XMLDSIG_ERROR                                                       syscall.Errno = 1466
	ERROR_RESTART_APPLICATION                                                 syscall.Errno = 1467
	ERROR_WRONG_COMPARTMENT                                                   syscall.Errno = 1468
	ERROR_AUTHIP_FAILURE                                                      syscall.Errno = 1469
	ERROR_NO_NVRAM_RESOURCES                                                  syscall.Errno = 1470
	ERROR_NOT_GUI_PROCESS                                                     syscall.Errno = 1471
	ERROR_EVENTLOG_FILE_CORRUPT                                               syscall.Errno = 1500
	ERROR_EVENTLOG_CANT_START                                                 syscall.Errno = 1501
	ERROR_LOG_FILE_FULL                                                       syscall.Errno = 1502
	ERROR_EVENTLOG_FILE_CHANGED                                               syscall.Errno = 1503
	ERROR_CONTAINER_ASSIGNED                                                  syscall.Errno = 1504
	ERROR_JOB_NO_CONTAINER                                                    syscall.Errno = 1505
	ERROR_INVALID_TASK_NAME                                                   syscall.Errno = 1550
	ERROR_INVALID_TASK_INDEX                                                  syscall.Errno = 1551
	ERROR_THREAD_ALREADY_IN_TASK                                              syscall.Errno = 1552
	ERROR_INSTALL_SERVICE_FAILURE                                             syscall.Errno = 1601
	ERROR_INSTALL_USEREXIT                                                    syscall.Errno = 1602
	ERROR_INSTALL_FAILURE                                                     syscall.Errno = 1603
	ERROR_INSTALL_SUSPEND                                                     syscall.Errno = 1604
	ERROR_UNKNOWN_PRODUCT                                                     syscall.Errno = 1605
	ERROR_UNKNOWN_FEATURE                                                     syscall.Errno = 1606
	ERROR_UNKNOWN_COMPONENT                                                   syscall.Errno = 1607
	ERROR_UNKNOWN_PROPERTY                                                    syscall.Errno = 1608
	ERROR_INVALID_HANDLE_STATE                                                syscall.Errno = 1609
	ERROR_BAD_CONFIGURATION                                                   syscall.Errno = 1610
	ERROR_INDEX_ABSENT                                                        syscall.Errno = 1611
	ERROR_INSTALL_SOURCE_ABSENT                                               syscall.Errno = 1612
	ERROR_INSTALL_PACKAGE_VERSION                                             syscall.Errno = 1613
	ERROR_PRODUCT_UNINSTALLED                                                 syscall.Errno = 1614
	ERROR_BAD_QUERY_SYNTAX                                                    syscall.Errno = 1615
	ERROR_INVALID_FIELD                                                       syscall.Errno = 1616
	ERROR_DEVICE_REMOVED                                                      syscall.Errno = 1617
	ERROR_INSTALL_ALREADY_RUNNING                                             syscall.Errno = 1618
	ERROR_INSTALL_PACKAGE_OPEN_FAILED                                         syscall.Errno = 1619
	ERROR_INSTALL_PACKAGE_INVALID                                             syscall.Errno = 1620
	ERROR_INSTALL_UI_FAILURE                                                  syscall.Errno = 1621
	ERROR_INSTALL_LOG_FAILURE                                                 syscall.Errno = 1622
	ERROR_INSTALL_LANGUAGE_UNSUPPORTED                                        syscall.Errno = 1623
	ERROR_INSTALL_TRANSFORM_FAILURE                                           syscall.Errno = 1624
	ERROR_INSTALL_PACKAGE_REJECTED                                            syscall.Errno = 1625
	ERROR_FUNCTION_NOT_CALLED                                                 syscall.Errno = 1626
	ERROR_FUNCTION_FAILED                                                     syscall.Errno = 1627
	ERROR_INVALID_TABLE                                                       syscall.Errno = 1628
	ERROR_DATATYPE_MISMATCH                                                   syscall.Errno = 1629
	ERROR_UNSUPPORTED_TYPE                                                    syscall.Errno = 1630
	ERROR_CREATE_FAILED                                                       syscall.Errno = 1631
	ERROR_INSTALL_TEMP_UNWRITABLE                                             syscall.Errno = 1632
	ERROR_INSTALL_PLATFORM_UNSUPPORTED                                        syscall.Errno = 1633
	ERROR_INSTALL_NOTUSED                                                     syscall.Errno = 1634
	ERROR_PATCH_PACKAGE_OPEN_FAILED                                           syscall.Errno = 1635
	ERROR_PATCH_PACKAGE_INVALID                                               syscall.Errno = 1636
	ERROR_PATCH_PACKAGE_UNSUPPORTED                                           syscall.Errno = 1637
	ERROR_PRODUCT_VERSION                                                     syscall.Errno = 1638
	ERROR_INVALID_COMMAND_LINE                                                syscall.Errno = 1639
	ERROR_INSTALL_REMOTE_DISALLOWED                                           syscall.Errno = 1640
	ERROR_SUCCESS_REBOOT_INITIATED                                            syscall.Errno = 1641
	ERROR_PATCH_TARGET_NOT_FOUND                                              syscall.Errno = 1642
	ERROR_PATCH_PACKAGE_REJECTED                                              syscall.Errno = 1643
	ERROR_INSTALL_TRANSFORM_REJECTED                                          syscall.Errno = 1644
	ERROR_INSTALL_REMOTE_PROHIBITED                                           syscall.Errno = 1645
	ERROR_PATCH_REMOVAL_UNSUPPORTED                                           syscall.Errno = 1646
	ERROR_UNKNOWN_PATCH                                                       syscall.Errno = 1647
	ERROR_PATCH_NO_SEQUENCE                                                   syscall.Errno = 1648
	ERROR_PATCH_REMOVAL_DISALLOWED                                            syscall.Errno = 1649
	ERROR_INVALID_PATCH_XML                                                   syscall.Errno = 1650
	ERROR_PATCH_MANAGED_ADVERTISED_PRODUCT                                    syscall.Errno = 1651
	ERROR_INSTALL_SERVICE_SAFEBOOT                                            syscall.Errno = 1652
	ERROR_FAIL_FAST_EXCEPTION                                                 syscall.Errno = 1653
	ERROR_INSTALL_REJECTED                                                    syscall.Errno = 1654
	ERROR_DYNAMIC_CODE_BLOCKED                                                syscall.Errno = 1655
	ERROR_NOT_SAME_OBJECT                                                     syscall.Errno = 1656
	ERROR_STRICT_CFG_VIOLATION                                                syscall.Errno = 1657
	ERROR_SET_CONTEXT_DENIED                                                  syscall.Errno = 1660
	ERROR_CROSS_PARTITION_VIOLATION                                           syscall.Errno = 1661
	RPC_S_INVALID_STRING_BINDING                                              syscall.Errno = 1700
	RPC_S_WRONG_KIND_OF_BINDING                                               syscall.Errno = 1701
	RPC_S_INVALID_BINDING                                                     syscall.Errno = 1702
	RPC_S_PROTSEQ_NOT_SUPPORTED                                               syscall.Errno = 1703
	RPC_S_INVALID_RPC_PROTSEQ                                                 syscall.Errno = 1704
	RPC_S_INVALID_STRING_UUID                                                 syscall.Errno = 1705
	RPC_S_INVALID_ENDPOINT_FORMAT                                             syscall.Errno = 1706
	RPC_S_INVALID_NET_ADDR                                                    syscall.Errno = 1707
	RPC_S_NO_ENDPOINT_FOUND                                                   syscall.Errno = 1708
	RPC_S_INVALID_TIMEOUT                                                     syscall.Errno = 1709
	RPC_S_OBJECT_NOT_FOUND                                                    syscall.Errno = 1710
	RPC_S_ALREADY_REGISTERED                                                  syscall.Errno = 1711
	RPC_S_TYPE_ALREADY_REGISTERED                                             syscall.Errno = 1712
	RPC_S_ALREADY_LISTENING                                                   syscall.Errno = 1713
	RPC_S_NO_PROTSEQS_REGISTERED                                              syscall.Errno = 1714
	RPC_S_NOT_LISTENING                                                       syscall.Errno = 1715
	RPC_S_UNKNOWN_MGR_TYPE                                                    syscall.Errno = 1716
	RPC_S_UNKNOWN_IF                                                          syscall.Errno = 1717
	RPC_S_NO_BINDINGS                                                         syscall.Errno = 1718
	RPC_S_NO_PROTSEQS                                                         syscall.Errno = 1719
	RPC_S_CANT_CREATE_ENDPOINT                                                syscall.Errno = 1720
	RPC_S_OUT_OF_RESOURCES                                                    syscall.Errno = 1721
	RPC_S_SERVER_UNAVAILABLE                                                  syscall.Errno = 1722
	RPC_S_SERVER_TOO_BUSY                                                     syscall.Errno = 1723
	RPC_S_INVALID_NETWORK_OPTIONS                                             syscall.Errno = 1724
	RPC_S_NO_CALL_ACTIVE                                                      syscall.Errno = 1725
	RPC_S_CALL_FAILED                                                         syscall.Errno = 1726
	RPC_S_CALL_FAILED_DNE                                                     syscall.Errno = 1727
	RPC_S_PROTOCOL_ERROR                                                      syscall.Errno = 1728
	RPC_S_PROXY_ACCESS_DENIED                                                 syscall.Errno = 1729
	RPC_S_UNSUPPORTED_TRANS_SYN                                               syscall.Errno = 1730
	RPC_S_UNSUPPORTED_TYPE                                                    syscall.Errno = 1732
	RPC_S_INVALID_TAG                                                         syscall.Errno = 1733
	RPC_S_INVALID_BOUND                                                       syscall.Errno = 1734
	RPC_S_NO_ENTRY_NAME                                                       syscall.Errno = 1735
	RPC_S_INVALID_NAME_SYNTAX                                                 syscall.Errno = 1736
	RPC_S_UNSUPPORTED_NAME_SYNTAX                                             syscall.Errno = 1737
	RPC_S_UUID_NO_ADDRESS                                                     syscall.Errno = 1739
	RPC_S_DUPLICATE_ENDPOINT                                                  syscall.Errno = 1740
	RPC_S_UNKNOWN_AUTHN_TYPE                                                  syscall.Errno = 1741
	RPC_S_MAX_CALLS_TOO_SMALL                                                 syscall.Errno = 1742
	RPC_S_STRING_TOO_LONG                                                     syscall.Errno = 1743
	RPC_S_PROTSEQ_NOT_FOUND                                                   syscall.Errno = 1744
	RPC_S_PROCNUM_OUT_OF_RANGE                                                syscall.Errno = 1745
	RPC_S_BINDING_HAS_NO_AUTH                                                 syscall.Errno = 1746
	RPC_S_UNKNOWN_AUTHN_SERVICE                                               syscall.Errno = 1747
	RPC_S_UNKNOWN_AUTHN_LEVEL                                                 syscall.Errno = 1748
	RPC_S_INVALID_AUTH_IDENTITY                                               syscall.Errno = 1749
	RPC_S_UNKNOWN_AUTHZ_SERVICE                                               syscall.Errno = 1750
	EPT_S_INVALID_ENTRY                                                       syscall.Errno = 1751
	EPT_S_CANT_PERFORM_OP                                                     syscall.Errno = 1752
	EPT_S_NOT_REGISTERED                                                      syscall.Errno = 1753
	RPC_S_NOTHING_TO_EXPORT                                                   syscall.Errno = 1754
	RPC_S_INCOMPLETE_NAME                                                     syscall.Errno = 1755
	RPC_S_INVALID_VERS_OPTION                                                 syscall.Errno = 1756
	RPC_S_NO_MORE_MEMBERS                                                     syscall.Errno = 1757
	RPC_S_NOT_ALL_OBJS_UNEXPORTED                                             syscall.Errno = 1758
	RPC_S_INTERFACE_NOT_FOUND                                                 syscall.Errno = 1759
	RPC_S_ENTRY_ALREADY_EXISTS                                                syscall.Errno = 1760
	RPC_S_ENTRY_NOT_FOUND                                                     syscall.Errno = 1761
	RPC_S_NAME_SERVICE_UNAVAILABLE                                            syscall.Errno = 1762
	RPC_S_INVALID_NAF_ID                                                      syscall.Errno = 1763
	RPC_S_CANNOT_SUPPORT                                                      syscall.Errno = 1764
	RPC_S_NO_CONTEXT_AVAILABLE                                                syscall.Errno = 1765
	RPC_S_INTERNAL_ERROR                                                      syscall.Errno = 1766
	RPC_S_ZERO_DIVIDE                                                         syscall.Errno = 1767
	RPC_S_ADDRESS_ERROR                                                       syscall.Errno = 1768
	RPC_S_FP_DIV_ZERO                                                         syscall.Errno = 1769
	RPC_S_FP_UNDERFLOW                                                        syscall.Errno = 1770
	RPC_S_FP_OVERFLOW                                                         syscall.Errno = 1771
	RPC_X_NO_MORE_ENTRIES                                                     syscall.Errno = 1772
	RPC_X_SS_CHAR_TRANS_OPEN_FAIL                                             syscall.Errno = 1773
	RPC_X_SS_CHAR_TRANS_SHORT_FILE                                            syscall.Errno = 1774
	RPC_X_SS_IN_NULL_CONTEXT                                                  syscall.Errno = 1775
	RPC_X_SS_CONTEXT_DAMAGED                                                  syscall.Errno = 1777
	RPC_X_SS_HANDLES_MISMATCH                                                 syscall.Errno = 1778
	RPC_X_SS_CANNOT_GET_CALL_HANDLE                                           syscall.Errno = 1779
	RPC_X_NULL_REF_POINTER                                                    syscall.Errno = 1780
	RPC_X_ENUM_VALUE_OUT_OF_RANGE                                             syscall.Errno = 1781
	RPC_X_BYTE_COUNT_TOO_SMALL                                                syscall.Errno = 1782
	RPC_X_BAD_STUB_DATA                                                       syscall.Errno = 1783
	ERROR_INVALID_USER_BUFFER                                                 syscall.Errno = 1784
	ERROR_UNRECOGNIZED_MEDIA                                                  syscall.Errno = 1785
	ERROR_NO_TRUST_LSA_SECRET                                                 syscall.Errno = 1786
	ERROR_NO_TRUST_SAM_ACCOUNT                                                syscall.Errno = 1787
	ERROR_TRUSTED_DOMAIN_FAILURE                                              syscall.Errno = 1788
	ERROR_TRUSTED_RELATIONSHIP_FAILURE                                        syscall.Errno = 1789
	ERROR_TRUST_FAILURE                                                       syscall.Errno = 1790
	RPC_S_CALL_IN_PROGRESS                                                    syscall.Errno = 1791
	ERROR_NETLOGON_NOT_STARTED                                                syscall.Errno = 1792
	ERROR_ACCOUNT_EXPIRED                                                     syscall.Errno = 1793
	ERROR_REDIRECTOR_HAS_OPEN_HANDLES                                         syscall.Errno = 1794
	ERROR_PRINTER_DRIVER_ALREADY_INSTALLED                                    syscall.Errno = 1795
	ERROR_UNKNOWN_PORT                                                        syscall.Errno = 1796
	ERROR_UNKNOWN_PRINTER_DRIVER                                              syscall.Errno = 1797
	ERROR_UNKNOWN_PRINTPROCESSOR                                              syscall.Errno = 1798
	ERROR_INVALID_SEPARATOR_FILE                                              syscall.Errno = 1799
	ERROR_INVALID_PRIORITY                                                    syscall.Errno = 1800
	ERROR_INVALID_PRINTER_NAME                                                syscall.Errno = 1801
	ERROR_PRINTER_ALREADY_EXISTS                                              syscall.Errno = 1802
	ERROR_INVALID_PRINTER_COMMAND                                             syscall.Errno = 1803
	ERROR_INVALID_DATATYPE                                                    syscall.Errno = 1804
	ERROR_INVALID_ENVIRONMENT                                                 syscall.Errno = 1805
	RPC_S_NO_MORE_BINDINGS                                                    syscall.Errno = 1806
	ERROR_NOLOGON_INTERDOMAIN_TRUST_ACCOUNT                                   syscall.Errno = 1807
	ERROR_NOLOGON_WORKSTATION_TRUST_ACCOUNT                                   syscall.Errno = 1808
	ERROR_NOLOGON_SERVER_TRUST_ACCOUNT                                        syscall.Errno = 1809
	ERROR_DOMAIN_TRUST_INCONSISTENT                                           syscall.Errno = 1810
	ERROR_SERVER_HAS_OPEN_HANDLES                                             syscall.Errno = 1811
	ERROR_RESOURCE_DATA_NOT_FOUND                                             syscall.Errno = 1812
	ERROR_RESOURCE_TYPE_NOT_FOUND                                             syscall.Errno = 1813
	ERROR_RESOURCE_NAME_NOT_FOUND                                             syscall.Errno = 1814
	ERROR_RESOURCE_LANG_NOT_FOUND                                             syscall.Errno = 1815
	ERROR_NOT_ENOUGH_QUOTA                                                    syscall.Errno = 1816
	RPC_S_NO_INTERFACES                                                       syscall.Errno = 1817
	RPC_S_CALL_CANCELLED                                                      syscall.Errno = 1818
	RPC_S_BINDING_INCOMPLETE                                                  syscall.Errno = 1819
	RPC_S_COMM_FAILURE                                                        syscall.Errno = 1820
	RPC_S_UNSUPPORTED_AUTHN_LEVEL                                             syscall.Errno = 1821
	RPC_S_NO_PRINC_NAME                                                       syscall.Errno = 1822
	RPC_S_NOT_RPC_ERROR                                                       syscall.Errno = 1823
	RPC_S_UUID_LOCAL_ONLY                                                     syscall.Errno = 1824
	RPC_S_SEC_PKG_ERROR                                                       syscall.Errno = 1825
	RPC_S_NOT_CANCELLED                                                       syscall.Errno = 1826
	RPC_X_INVALID_ES_ACTION                                                   syscall.Errno = 1827
	RPC_X_WRONG_ES_VERSION                                                    syscall.Errno = 1828
	RPC_X_WRONG_STUB_VERSION                                                  syscall.Errno = 1829
	RPC_X_INVALID_PIPE_OBJECT                                                 syscall.Errno = 1830
	RPC_X_WRONG_PIPE_ORDER                                                    syscall.Errno = 1831
	RPC_X_WRONG_PIPE_VERSION                                                  syscall.Errno = 1832
	RPC_S_COOKIE_AUTH_FAILED                                                  syscall.Errno = 1833
	RPC_S_DO_NOT_DISTURB                                                      syscall.Errno = 1834
	RPC_S_SYSTEM_HANDLE_COUNT_EXCEEDED                                        syscall.Errno = 1835
	RPC_S_SYSTEM_HANDLE_TYPE_MISMATCH                                         syscall.Errno = 1836
	RPC_S_GROUP_MEMBER_NOT_FOUND                                              syscall.Errno = 1898
	EPT_S_CANT_CREATE                                                         syscall.Errno = 1899
	RPC_S_INVALID_OBJECT                                                      syscall.Errno = 1900
	ERROR_INVALID_TIME                                                        syscall.Errno = 1901
	ERROR_INVALID_FORM_NAME                                                   syscall.Errno = 1902
	ERROR_INVALID_FORM_SIZE                                                   syscall.Errno = 1903
	ERROR_ALREADY_WAITING                                                     syscall.Errno = 1904
	ERROR_PRINTER_DELETED
```