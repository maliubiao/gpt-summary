Response:
Let's break down the thought process for analyzing this Go code snippet.

**1. Initial Scan and Keyword Recognition:**

The first step is a quick visual scan of the code. Immediately noticeable are:

* `package` declaration: `package windows` - This tells us the code is part of the `windows` package within the `golang.org/x/sys` repository. This strongly suggests it's related to interacting with the Windows operating system.
* A large number of lines starting with uppercase names (like `ERROR_GRAPHICS_...`, `NAP_E_...`, `TPM_E_...`, etc.) followed by `Handle` and a hexadecimal value.
* The assignment operator `=`.
* The `Handle` type.

**2. Identifying the Core Functionality:**

The repetitive structure of `CONSTANT_NAME Handle = 0x...` strongly indicates the definition of constants. The names themselves are highly descriptive, using prefixes like `ERROR_GRAPHICS`, `NAP_E`, `TPM_E`, and `FVE_E`. This suggests these constants represent error codes related to different Windows subsystems or components.

* `ERROR_GRAPHICS`: Likely related to graphics and display functionalities.
* `NAP_E`:  Potentially related to Network Access Protection (NAP). The `E` suffix likely denotes an error.
* `TPM_E` and `TPM_20_E`: Almost certainly related to Trusted Platform Module (TPM), with `20` possibly indicating a TPM 2.0 specific error.
* `TBS_E`: Likely related to the TPM Base Services (TBS).
* `TPMAPI_E`:  Possibly errors from a TPM API.
* `TBSIMP_E`:  Could be errors from a TBS implementation.
* `TPM_E_PPI`: Likely errors related to the Platform Provisioning Interface (PPI) of the TPM.
* `TPM_E_PCP`:  Potentially related to the Platform Configuration Parameters (PCP) of the TPM.
* `PLA_E`:  Might relate to Performance Logs and Alerts (PLA).
* `FVE_E`: Very likely related to BitLocker Drive Encryption (formerly Full Volume Encryption).

The `Handle` type is declared but its underlying type isn't shown in this snippet. However, the hexadecimal values assigned to the constants and the context strongly suggest it's likely an integer type (probably `uint32` or `int32`).

**3. Inferring the Purpose within Go:**

Knowing that this is part of the `golang.org/x/sys/windows` package, the most likely purpose is to provide Go-friendly constants for accessing and interpreting Windows system error codes. Go programs interacting with the Windows API (through syscalls or higher-level libraries) will receive these error codes as numerical values. This file provides meaningful names for those values, making the code more readable and maintainable.

**4. Constructing a Go Example:**

Based on the inference, a reasonable Go example would involve making a Windows system call that could return one of these errors. The `syscall` package is the obvious choice. A simple example would be trying to open a file that doesn't exist. The expected error would be related to file access. While the provided snippet doesn't contain *file* errors directly, the general principle applies. We'd want to show how to compare the returned error with the constants defined in this file.

Since the provided snippet heavily features graphics and TPM related errors, a more directly relevant example (even if we don't have the exact Go code for the underlying Windows API calls) would involve a hypothetical scenario where a graphics operation or a TPM command fails.

**5. Considering Command-Line Arguments and Common Mistakes:**

Since this file primarily defines constants, it doesn't directly handle command-line arguments. The errors themselves *might* arise from operations initiated by command-line tools, but the `zerrors_windows.go` file is a static data file, not an executable.

Common mistakes would involve:

* **Incorrectly comparing errors:**  Assuming the error type is directly comparable without type assertion or proper comparison.
* **Not handling errors:** Ignoring potential errors returned by Windows API calls.
* **Misinterpreting error codes:**  Not understanding the specific meaning of each error code.

**6. Synthesizing the Summary:**

The summary needs to concisely capture the main function. It should highlight that this file defines Go constants representing Windows error codes, particularly for graphics, NAP, TPM, PLA, and BitLocker. It serves as a mapping between numeric error values and human-readable names, crucial for error handling in Go programs interacting with Windows.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** "Maybe these are flags or bitmasks."  However, the individual error names are too specific, and there's no bitwise operations evident. So, they're more likely distinct error codes.
* **Considering the `Handle` type:** Initially, I might not be sure of its exact type. However, the context of error codes makes an integer type the most probable. I'd avoid making definitive claims without seeing the type definition but acknowledge the likely possibility.
* **Refining the Go example:**  Initially, a file I/O example might come to mind first as a common error scenario. However, to be more specific to the provided snippet, focusing on graphics or TPM errors (even with a more abstract example) is more appropriate.

By following these steps, combining keyword recognition, contextual understanding, and some logical deduction, we can arrive at a comprehensive understanding of the provided Go code snippet's functionality.
This Go code snippet from `go/src/cmd/vendor/golang.org/x/sys/windows/zerrors_windows.go` defines a large set of **Go constants** that represent **Windows error codes**. Specifically, this section (part 8 of 15) primarily focuses on error codes related to:

* **Graphics:** Errors starting with `ERROR_GRAPHICS_`, dealing with display settings, video present networks (VidPN), monitors, and related functionalities.
* **Network Access Protection (NAP):** Errors starting with `NAP_E_`, indicating problems with network access control and health validation.
* **Trusted Platform Module (TPM):** Errors starting with `TPM_E_`, `TPM_20_E_`, `TBS_E_`, `TPMAPI_E_`, `TBSIMP_E_`, and `TPM_E_PPI_`, covering a wide range of TPM-related issues, including authentication, key management, command failures, and platform provisioning.
* **Performance Logs and Alerts (PLA):** Errors starting with `PLA_E_`, signaling issues with performance monitoring and alerting.
* **BitLocker Drive Encryption (FVE):** Errors starting with `FVE_E_`, indicating various problems with BitLocker encryption, decryption, key management, and policy enforcement.

**Functionality:**

The primary function of this code is to provide a **mapping between numeric Windows error codes and meaningful Go constant names**. This allows Go programmers to write more readable and maintainable code when interacting with Windows APIs that return error codes. Instead of checking against magic numbers, they can compare against these well-defined constants.

**Go Language Feature Implementation:**

This code directly implements the Go language feature of **constant declaration**. Go allows you to define named constant values using the `const` keyword. In this case, the constants are assigned hexadecimal values that correspond to the actual Windows error codes.

**Go Code Example:**

While this specific file doesn't contain executable logic, its constants are used in other parts of the `golang.org/x/sys/windows` package and in user code that interacts with Windows APIs.

Let's imagine you're using a function from the `golang.org/x/sys/windows` package that interacts with the graphics subsystem and it returns an error.

```go
package main

import (
	"fmt"
	"syscall"

	"golang.org/x/sys/windows"
)

func main() {
	// Hypothetical function that might return a graphics error.
	// In reality, you would be calling a Windows API through the syscall package
	// or a higher-level library wrapping it.
	err := simulateGraphicsError()

	if err != nil {
		if err == windows.ERROR_GRAPHICS_INVALID_VIDPN_SOURCEMODESET {
			fmt.Println("Error: The specified VidPN source mode set is invalid.")
		} else if err == windows.ERROR_GRAPHICS_MODE_NOT_PINNED {
			fmt.Println("Error: The graphics mode is not pinned.")
		} else {
			fmt.Printf("An unexpected graphics error occurred: %v\n", err)
		}
	} else {
		fmt.Println("Graphics operation successful.")
	}
}

// This is a placeholder. In a real scenario, this would be a function
// interacting with the Windows graphics API.
func simulateGraphicsError() error {
	// For demonstration, we'll return a specific graphics error constant.
	return windows.ERROR_GRAPHICS_INVALID_VIDPN_SOURCEMODESET
}
```

**Assumptions and Output:**

* **Input (Hypothetical):** The `simulateGraphicsError` function is called.
* **Output:** `Error: The specified VidPN source mode set is invalid.` will be printed to the console because `simulateGraphicsError` is set to return `windows.ERROR_GRAPHICS_INVALID_VIDPN_SOURCEMODESET`.

If `simulateGraphicsError` were to return `windows.ERROR_GRAPHICS_MODE_NOT_PINNED`, the output would be:
* **Output:** `Error: The graphics mode is not pinned.`

If it returned a different error not explicitly handled, the output would be:
* **Output (example if returning `syscall.EINVAL`):** `An unexpected graphics error occurred: invalid argument`

**Command-Line Parameters:**

This specific code snippet does not handle any command-line parameters. It's a data file defining constants. Command-line parameters would be handled in the code that *uses* these constants, typically within the `main` function or other entry points of an application.

**User Mistakes (Conceptual):**

While users don't directly interact with this file, common mistakes when working with Windows error codes in Go include:

* **Incorrectly comparing error types:**  Sometimes, a Windows API might return a generic error type. You need to ensure you're comparing against the correct type (e.g., by using type assertions if necessary). However, in this case, the constants themselves are the error values, so direct comparison is generally sufficient.
* **Not checking for errors:**  Ignoring the error return values from Windows API calls is a common mistake that can lead to unexpected behavior.
* **Misinterpreting the meaning of specific error codes:**  It's important to consult the Windows documentation to understand the exact cause of a particular error code. This file provides the constant names, making it easier to look up the corresponding documentation.

**Summary of Functionality (Part 8):**

This section of `zerrors_windows.go` defines Go constants that represent Windows error codes specifically related to **graphics, Network Access Protection (NAP), the Trusted Platform Module (TPM), Performance Logs and Alerts (PLA), and BitLocker Drive Encryption (FVE).** It serves as a crucial component for Go programs interacting with Windows by providing symbolic names for numeric error values, improving code readability and maintainability.

### 提示词
```
这是路径为go/src/cmd/vendor/golang.org/x/sys/windows/zerrors_windows.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第8部分，共15部分，请归纳一下它的功能
```

### 源代码
```go
305
	ERROR_GRAPHICS_VIDPN_MODALITY_NOT_SUPPORTED                               Handle        = 0xC0262306
	ERROR_GRAPHICS_MODE_NOT_PINNED                                            Handle        = 0x00262307
	ERROR_GRAPHICS_INVALID_VIDPN_SOURCEMODESET                                Handle        = 0xC0262308
	ERROR_GRAPHICS_INVALID_VIDPN_TARGETMODESET                                Handle        = 0xC0262309
	ERROR_GRAPHICS_INVALID_FREQUENCY                                          Handle        = 0xC026230A
	ERROR_GRAPHICS_INVALID_ACTIVE_REGION                                      Handle        = 0xC026230B
	ERROR_GRAPHICS_INVALID_TOTAL_REGION                                       Handle        = 0xC026230C
	ERROR_GRAPHICS_INVALID_VIDEO_PRESENT_SOURCE_MODE                          Handle        = 0xC0262310
	ERROR_GRAPHICS_INVALID_VIDEO_PRESENT_TARGET_MODE                          Handle        = 0xC0262311
	ERROR_GRAPHICS_PINNED_MODE_MUST_REMAIN_IN_SET                             Handle        = 0xC0262312
	ERROR_GRAPHICS_PATH_ALREADY_IN_TOPOLOGY                                   Handle        = 0xC0262313
	ERROR_GRAPHICS_MODE_ALREADY_IN_MODESET                                    Handle        = 0xC0262314
	ERROR_GRAPHICS_INVALID_VIDEOPRESENTSOURCESET                              Handle        = 0xC0262315
	ERROR_GRAPHICS_INVALID_VIDEOPRESENTTARGETSET                              Handle        = 0xC0262316
	ERROR_GRAPHICS_SOURCE_ALREADY_IN_SET                                      Handle        = 0xC0262317
	ERROR_GRAPHICS_TARGET_ALREADY_IN_SET                                      Handle        = 0xC0262318
	ERROR_GRAPHICS_INVALID_VIDPN_PRESENT_PATH                                 Handle        = 0xC0262319
	ERROR_GRAPHICS_NO_RECOMMENDED_VIDPN_TOPOLOGY                              Handle        = 0xC026231A
	ERROR_GRAPHICS_INVALID_MONITOR_FREQUENCYRANGESET                          Handle        = 0xC026231B
	ERROR_GRAPHICS_INVALID_MONITOR_FREQUENCYRANGE                             Handle        = 0xC026231C
	ERROR_GRAPHICS_FREQUENCYRANGE_NOT_IN_SET                                  Handle        = 0xC026231D
	ERROR_GRAPHICS_NO_PREFERRED_MODE                                          Handle        = 0x0026231E
	ERROR_GRAPHICS_FREQUENCYRANGE_ALREADY_IN_SET                              Handle        = 0xC026231F
	ERROR_GRAPHICS_STALE_MODESET                                              Handle        = 0xC0262320
	ERROR_GRAPHICS_INVALID_MONITOR_SOURCEMODESET                              Handle        = 0xC0262321
	ERROR_GRAPHICS_INVALID_MONITOR_SOURCE_MODE                                Handle        = 0xC0262322
	ERROR_GRAPHICS_NO_RECOMMENDED_FUNCTIONAL_VIDPN                            Handle        = 0xC0262323
	ERROR_GRAPHICS_MODE_ID_MUST_BE_UNIQUE                                     Handle        = 0xC0262324
	ERROR_GRAPHICS_EMPTY_ADAPTER_MONITOR_MODE_SUPPORT_INTERSECTION            Handle        = 0xC0262325
	ERROR_GRAPHICS_VIDEO_PRESENT_TARGETS_LESS_THAN_SOURCES                    Handle        = 0xC0262326
	ERROR_GRAPHICS_PATH_NOT_IN_TOPOLOGY                                       Handle        = 0xC0262327
	ERROR_GRAPHICS_ADAPTER_MUST_HAVE_AT_LEAST_ONE_SOURCE                      Handle        = 0xC0262328
	ERROR_GRAPHICS_ADAPTER_MUST_HAVE_AT_LEAST_ONE_TARGET                      Handle        = 0xC0262329
	ERROR_GRAPHICS_INVALID_MONITORDESCRIPTORSET                               Handle        = 0xC026232A
	ERROR_GRAPHICS_INVALID_MONITORDESCRIPTOR                                  Handle        = 0xC026232B
	ERROR_GRAPHICS_MONITORDESCRIPTOR_NOT_IN_SET                               Handle        = 0xC026232C
	ERROR_GRAPHICS_MONITORDESCRIPTOR_ALREADY_IN_SET                           Handle        = 0xC026232D
	ERROR_GRAPHICS_MONITORDESCRIPTOR_ID_MUST_BE_UNIQUE                        Handle        = 0xC026232E
	ERROR_GRAPHICS_INVALID_VIDPN_TARGET_SUBSET_TYPE                           Handle        = 0xC026232F
	ERROR_GRAPHICS_RESOURCES_NOT_RELATED                                      Handle        = 0xC0262330
	ERROR_GRAPHICS_SOURCE_ID_MUST_BE_UNIQUE                                   Handle        = 0xC0262331
	ERROR_GRAPHICS_TARGET_ID_MUST_BE_UNIQUE                                   Handle        = 0xC0262332
	ERROR_GRAPHICS_NO_AVAILABLE_VIDPN_TARGET                                  Handle        = 0xC0262333
	ERROR_GRAPHICS_MONITOR_COULD_NOT_BE_ASSOCIATED_WITH_ADAPTER               Handle        = 0xC0262334
	ERROR_GRAPHICS_NO_VIDPNMGR                                                Handle        = 0xC0262335
	ERROR_GRAPHICS_NO_ACTIVE_VIDPN                                            Handle        = 0xC0262336
	ERROR_GRAPHICS_STALE_VIDPN_TOPOLOGY                                       Handle        = 0xC0262337
	ERROR_GRAPHICS_MONITOR_NOT_CONNECTED                                      Handle        = 0xC0262338
	ERROR_GRAPHICS_SOURCE_NOT_IN_TOPOLOGY                                     Handle        = 0xC0262339
	ERROR_GRAPHICS_INVALID_PRIMARYSURFACE_SIZE                                Handle        = 0xC026233A
	ERROR_GRAPHICS_INVALID_VISIBLEREGION_SIZE                                 Handle        = 0xC026233B
	ERROR_GRAPHICS_INVALID_STRIDE                                             Handle        = 0xC026233C
	ERROR_GRAPHICS_INVALID_PIXELFORMAT                                        Handle        = 0xC026233D
	ERROR_GRAPHICS_INVALID_COLORBASIS                                         Handle        = 0xC026233E
	ERROR_GRAPHICS_INVALID_PIXELVALUEACCESSMODE                               Handle        = 0xC026233F
	ERROR_GRAPHICS_TARGET_NOT_IN_TOPOLOGY                                     Handle        = 0xC0262340
	ERROR_GRAPHICS_NO_DISPLAY_MODE_MANAGEMENT_SUPPORT                         Handle        = 0xC0262341
	ERROR_GRAPHICS_VIDPN_SOURCE_IN_USE                                        Handle        = 0xC0262342
	ERROR_GRAPHICS_CANT_ACCESS_ACTIVE_VIDPN                                   Handle        = 0xC0262343
	ERROR_GRAPHICS_INVALID_PATH_IMPORTANCE_ORDINAL                            Handle        = 0xC0262344
	ERROR_GRAPHICS_INVALID_PATH_CONTENT_GEOMETRY_TRANSFORMATION               Handle        = 0xC0262345
	ERROR_GRAPHICS_PATH_CONTENT_GEOMETRY_TRANSFORMATION_NOT_SUPPORTED         Handle        = 0xC0262346
	ERROR_GRAPHICS_INVALID_GAMMA_RAMP                                         Handle        = 0xC0262347
	ERROR_GRAPHICS_GAMMA_RAMP_NOT_SUPPORTED                                   Handle        = 0xC0262348
	ERROR_GRAPHICS_MULTISAMPLING_NOT_SUPPORTED                                Handle        = 0xC0262349
	ERROR_GRAPHICS_MODE_NOT_IN_MODESET                                        Handle        = 0xC026234A
	ERROR_GRAPHICS_DATASET_IS_EMPTY                                           Handle        = 0x0026234B
	ERROR_GRAPHICS_NO_MORE_ELEMENTS_IN_DATASET                                Handle        = 0x0026234C
	ERROR_GRAPHICS_INVALID_VIDPN_TOPOLOGY_RECOMMENDATION_REASON               Handle        = 0xC026234D
	ERROR_GRAPHICS_INVALID_PATH_CONTENT_TYPE                                  Handle        = 0xC026234E
	ERROR_GRAPHICS_INVALID_COPYPROTECTION_TYPE                                Handle        = 0xC026234F
	ERROR_GRAPHICS_UNASSIGNED_MODESET_ALREADY_EXISTS                          Handle        = 0xC0262350
	ERROR_GRAPHICS_PATH_CONTENT_GEOMETRY_TRANSFORMATION_NOT_PINNED            Handle        = 0x00262351
	ERROR_GRAPHICS_INVALID_SCANLINE_ORDERING                                  Handle        = 0xC0262352
	ERROR_GRAPHICS_TOPOLOGY_CHANGES_NOT_ALLOWED                               Handle        = 0xC0262353
	ERROR_GRAPHICS_NO_AVAILABLE_IMPORTANCE_ORDINALS                           Handle        = 0xC0262354
	ERROR_GRAPHICS_INCOMPATIBLE_PRIVATE_FORMAT                                Handle        = 0xC0262355
	ERROR_GRAPHICS_INVALID_MODE_PRUNING_ALGORITHM                             Handle        = 0xC0262356
	ERROR_GRAPHICS_INVALID_MONITOR_CAPABILITY_ORIGIN                          Handle        = 0xC0262357
	ERROR_GRAPHICS_INVALID_MONITOR_FREQUENCYRANGE_CONSTRAINT                  Handle        = 0xC0262358
	ERROR_GRAPHICS_MAX_NUM_PATHS_REACHED                                      Handle        = 0xC0262359
	ERROR_GRAPHICS_CANCEL_VIDPN_TOPOLOGY_AUGMENTATION                         Handle        = 0xC026235A
	ERROR_GRAPHICS_INVALID_CLIENT_TYPE                                        Handle        = 0xC026235B
	ERROR_GRAPHICS_CLIENTVIDPN_NOT_SET                                        Handle        = 0xC026235C
	ERROR_GRAPHICS_SPECIFIED_CHILD_ALREADY_CONNECTED                          Handle        = 0xC0262400
	ERROR_GRAPHICS_CHILD_DESCRIPTOR_NOT_SUPPORTED                             Handle        = 0xC0262401
	ERROR_GRAPHICS_UNKNOWN_CHILD_STATUS                                       Handle        = 0x4026242F
	ERROR_GRAPHICS_NOT_A_LINKED_ADAPTER                                       Handle        = 0xC0262430
	ERROR_GRAPHICS_LEADLINK_NOT_ENUMERATED                                    Handle        = 0xC0262431
	ERROR_GRAPHICS_CHAINLINKS_NOT_ENUMERATED                                  Handle        = 0xC0262432
	ERROR_GRAPHICS_ADAPTER_CHAIN_NOT_READY                                    Handle        = 0xC0262433
	ERROR_GRAPHICS_CHAINLINKS_NOT_STARTED                                     Handle        = 0xC0262434
	ERROR_GRAPHICS_CHAINLINKS_NOT_POWERED_ON                                  Handle        = 0xC0262435
	ERROR_GRAPHICS_INCONSISTENT_DEVICE_LINK_STATE                             Handle        = 0xC0262436
	ERROR_GRAPHICS_LEADLINK_START_DEFERRED                                    Handle        = 0x40262437
	ERROR_GRAPHICS_NOT_POST_DEVICE_DRIVER                                     Handle        = 0xC0262438
	ERROR_GRAPHICS_POLLING_TOO_FREQUENTLY                                     Handle        = 0x40262439
	ERROR_GRAPHICS_START_DEFERRED                                             Handle        = 0x4026243A
	ERROR_GRAPHICS_ADAPTER_ACCESS_NOT_EXCLUDED                                Handle        = 0xC026243B
	ERROR_GRAPHICS_DEPENDABLE_CHILD_STATUS                                    Handle        = 0x4026243C
	ERROR_GRAPHICS_OPM_NOT_SUPPORTED                                          Handle        = 0xC0262500
	ERROR_GRAPHICS_COPP_NOT_SUPPORTED                                         Handle        = 0xC0262501
	ERROR_GRAPHICS_UAB_NOT_SUPPORTED                                          Handle        = 0xC0262502
	ERROR_GRAPHICS_OPM_INVALID_ENCRYPTED_PARAMETERS                           Handle        = 0xC0262503
	ERROR_GRAPHICS_OPM_NO_VIDEO_OUTPUTS_EXIST                                 Handle        = 0xC0262505
	ERROR_GRAPHICS_OPM_INTERNAL_ERROR                                         Handle        = 0xC026250B
	ERROR_GRAPHICS_OPM_INVALID_HANDLE                                         Handle        = 0xC026250C
	ERROR_GRAPHICS_PVP_INVALID_CERTIFICATE_LENGTH                             Handle        = 0xC026250E
	ERROR_GRAPHICS_OPM_SPANNING_MODE_ENABLED                                  Handle        = 0xC026250F
	ERROR_GRAPHICS_OPM_THEATER_MODE_ENABLED                                   Handle        = 0xC0262510
	ERROR_GRAPHICS_PVP_HFS_FAILED                                             Handle        = 0xC0262511
	ERROR_GRAPHICS_OPM_INVALID_SRM                                            Handle        = 0xC0262512
	ERROR_GRAPHICS_OPM_OUTPUT_DOES_NOT_SUPPORT_HDCP                           Handle        = 0xC0262513
	ERROR_GRAPHICS_OPM_OUTPUT_DOES_NOT_SUPPORT_ACP                            Handle        = 0xC0262514
	ERROR_GRAPHICS_OPM_OUTPUT_DOES_NOT_SUPPORT_CGMSA                          Handle        = 0xC0262515
	ERROR_GRAPHICS_OPM_HDCP_SRM_NEVER_SET                                     Handle        = 0xC0262516
	ERROR_GRAPHICS_OPM_RESOLUTION_TOO_HIGH                                    Handle        = 0xC0262517
	ERROR_GRAPHICS_OPM_ALL_HDCP_HARDWARE_ALREADY_IN_USE                       Handle        = 0xC0262518
	ERROR_GRAPHICS_OPM_VIDEO_OUTPUT_NO_LONGER_EXISTS                          Handle        = 0xC026251A
	ERROR_GRAPHICS_OPM_SESSION_TYPE_CHANGE_IN_PROGRESS                        Handle        = 0xC026251B
	ERROR_GRAPHICS_OPM_VIDEO_OUTPUT_DOES_NOT_HAVE_COPP_SEMANTICS              Handle        = 0xC026251C
	ERROR_GRAPHICS_OPM_INVALID_INFORMATION_REQUEST                            Handle        = 0xC026251D
	ERROR_GRAPHICS_OPM_DRIVER_INTERNAL_ERROR                                  Handle        = 0xC026251E
	ERROR_GRAPHICS_OPM_VIDEO_OUTPUT_DOES_NOT_HAVE_OPM_SEMANTICS               Handle        = 0xC026251F
	ERROR_GRAPHICS_OPM_SIGNALING_NOT_SUPPORTED                                Handle        = 0xC0262520
	ERROR_GRAPHICS_OPM_INVALID_CONFIGURATION_REQUEST                          Handle        = 0xC0262521
	ERROR_GRAPHICS_I2C_NOT_SUPPORTED                                          Handle        = 0xC0262580
	ERROR_GRAPHICS_I2C_DEVICE_DOES_NOT_EXIST                                  Handle        = 0xC0262581
	ERROR_GRAPHICS_I2C_ERROR_TRANSMITTING_DATA                                Handle        = 0xC0262582
	ERROR_GRAPHICS_I2C_ERROR_RECEIVING_DATA                                   Handle        = 0xC0262583
	ERROR_GRAPHICS_DDCCI_VCP_NOT_SUPPORTED                                    Handle        = 0xC0262584
	ERROR_GRAPHICS_DDCCI_INVALID_DATA                                         Handle        = 0xC0262585
	ERROR_GRAPHICS_DDCCI_MONITOR_RETURNED_INVALID_TIMING_STATUS_BYTE          Handle        = 0xC0262586
	ERROR_GRAPHICS_MCA_INVALID_CAPABILITIES_STRING                            Handle        = 0xC0262587
	ERROR_GRAPHICS_MCA_INTERNAL_ERROR                                         Handle        = 0xC0262588
	ERROR_GRAPHICS_DDCCI_INVALID_MESSAGE_COMMAND                              Handle        = 0xC0262589
	ERROR_GRAPHICS_DDCCI_INVALID_MESSAGE_LENGTH                               Handle        = 0xC026258A
	ERROR_GRAPHICS_DDCCI_INVALID_MESSAGE_CHECKSUM                             Handle        = 0xC026258B
	ERROR_GRAPHICS_INVALID_PHYSICAL_MONITOR_HANDLE                            Handle        = 0xC026258C
	ERROR_GRAPHICS_MONITOR_NO_LONGER_EXISTS                                   Handle        = 0xC026258D
	ERROR_GRAPHICS_DDCCI_CURRENT_CURRENT_VALUE_GREATER_THAN_MAXIMUM_VALUE     Handle        = 0xC02625D8
	ERROR_GRAPHICS_MCA_INVALID_VCP_VERSION                                    Handle        = 0xC02625D9
	ERROR_GRAPHICS_MCA_MONITOR_VIOLATES_MCCS_SPECIFICATION                    Handle        = 0xC02625DA
	ERROR_GRAPHICS_MCA_MCCS_VERSION_MISMATCH                                  Handle        = 0xC02625DB
	ERROR_GRAPHICS_MCA_UNSUPPORTED_MCCS_VERSION                               Handle        = 0xC02625DC
	ERROR_GRAPHICS_MCA_INVALID_TECHNOLOGY_TYPE_RETURNED                       Handle        = 0xC02625DE
	ERROR_GRAPHICS_MCA_UNSUPPORTED_COLOR_TEMPERATURE                          Handle        = 0xC02625DF
	ERROR_GRAPHICS_ONLY_CONSOLE_SESSION_SUPPORTED                             Handle        = 0xC02625E0
	ERROR_GRAPHICS_NO_DISPLAY_DEVICE_CORRESPONDS_TO_NAME                      Handle        = 0xC02625E1
	ERROR_GRAPHICS_DISPLAY_DEVICE_NOT_ATTACHED_TO_DESKTOP                     Handle        = 0xC02625E2
	ERROR_GRAPHICS_MIRRORING_DEVICES_NOT_SUPPORTED                            Handle        = 0xC02625E3
	ERROR_GRAPHICS_INVALID_POINTER                                            Handle        = 0xC02625E4
	ERROR_GRAPHICS_NO_MONITORS_CORRESPOND_TO_DISPLAY_DEVICE                   Handle        = 0xC02625E5
	ERROR_GRAPHICS_PARAMETER_ARRAY_TOO_SMALL                                  Handle        = 0xC02625E6
	ERROR_GRAPHICS_INTERNAL_ERROR                                             Handle        = 0xC02625E7
	ERROR_GRAPHICS_SESSION_TYPE_CHANGE_IN_PROGRESS                            Handle        = 0xC02605E8
	NAP_E_INVALID_PACKET                                                      Handle        = 0x80270001
	NAP_E_MISSING_SOH                                                         Handle        = 0x80270002
	NAP_E_CONFLICTING_ID                                                      Handle        = 0x80270003
	NAP_E_NO_CACHED_SOH                                                       Handle        = 0x80270004
	NAP_E_STILL_BOUND                                                         Handle        = 0x80270005
	NAP_E_NOT_REGISTERED                                                      Handle        = 0x80270006
	NAP_E_NOT_INITIALIZED                                                     Handle        = 0x80270007
	NAP_E_MISMATCHED_ID                                                       Handle        = 0x80270008
	NAP_E_NOT_PENDING                                                         Handle        = 0x80270009
	NAP_E_ID_NOT_FOUND                                                        Handle        = 0x8027000A
	NAP_E_MAXSIZE_TOO_SMALL                                                   Handle        = 0x8027000B
	NAP_E_SERVICE_NOT_RUNNING                                                 Handle        = 0x8027000C
	NAP_S_CERT_ALREADY_PRESENT                                                Handle        = 0x0027000D
	NAP_E_ENTITY_DISABLED                                                     Handle        = 0x8027000E
	NAP_E_NETSH_GROUPPOLICY_ERROR                                             Handle        = 0x8027000F
	NAP_E_TOO_MANY_CALLS                                                      Handle        = 0x80270010
	NAP_E_SHV_CONFIG_EXISTED                                                  Handle        = 0x80270011
	NAP_E_SHV_CONFIG_NOT_FOUND                                                Handle        = 0x80270012
	NAP_E_SHV_TIMEOUT                                                         Handle        = 0x80270013
	TPM_E_ERROR_MASK                                                          Handle        = 0x80280000
	TPM_E_AUTHFAIL                                                            Handle        = 0x80280001
	TPM_E_BADINDEX                                                            Handle        = 0x80280002
	TPM_E_BAD_PARAMETER                                                       Handle        = 0x80280003
	TPM_E_AUDITFAILURE                                                        Handle        = 0x80280004
	TPM_E_CLEAR_DISABLED                                                      Handle        = 0x80280005
	TPM_E_DEACTIVATED                                                         Handle        = 0x80280006
	TPM_E_DISABLED                                                            Handle        = 0x80280007
	TPM_E_DISABLED_CMD                                                        Handle        = 0x80280008
	TPM_E_FAIL                                                                Handle        = 0x80280009
	TPM_E_BAD_ORDINAL                                                         Handle        = 0x8028000A
	TPM_E_INSTALL_DISABLED                                                    Handle        = 0x8028000B
	TPM_E_INVALID_KEYHANDLE                                                   Handle        = 0x8028000C
	TPM_E_KEYNOTFOUND                                                         Handle        = 0x8028000D
	TPM_E_INAPPROPRIATE_ENC                                                   Handle        = 0x8028000E
	TPM_E_MIGRATEFAIL                                                         Handle        = 0x8028000F
	TPM_E_INVALID_PCR_INFO                                                    Handle        = 0x80280010
	TPM_E_NOSPACE                                                             Handle        = 0x80280011
	TPM_E_NOSRK                                                               Handle        = 0x80280012
	TPM_E_NOTSEALED_BLOB                                                      Handle        = 0x80280013
	TPM_E_OWNER_SET                                                           Handle        = 0x80280014
	TPM_E_RESOURCES                                                           Handle        = 0x80280015
	TPM_E_SHORTRANDOM                                                         Handle        = 0x80280016
	TPM_E_SIZE                                                                Handle        = 0x80280017
	TPM_E_WRONGPCRVAL                                                         Handle        = 0x80280018
	TPM_E_BAD_PARAM_SIZE                                                      Handle        = 0x80280019
	TPM_E_SHA_THREAD                                                          Handle        = 0x8028001A
	TPM_E_SHA_ERROR                                                           Handle        = 0x8028001B
	TPM_E_FAILEDSELFTEST                                                      Handle        = 0x8028001C
	TPM_E_AUTH2FAIL                                                           Handle        = 0x8028001D
	TPM_E_BADTAG                                                              Handle        = 0x8028001E
	TPM_E_IOERROR                                                             Handle        = 0x8028001F
	TPM_E_ENCRYPT_ERROR                                                       Handle        = 0x80280020
	TPM_E_DECRYPT_ERROR                                                       Handle        = 0x80280021
	TPM_E_INVALID_AUTHHANDLE                                                  Handle        = 0x80280022
	TPM_E_NO_ENDORSEMENT                                                      Handle        = 0x80280023
	TPM_E_INVALID_KEYUSAGE                                                    Handle        = 0x80280024
	TPM_E_WRONG_ENTITYTYPE                                                    Handle        = 0x80280025
	TPM_E_INVALID_POSTINIT                                                    Handle        = 0x80280026
	TPM_E_INAPPROPRIATE_SIG                                                   Handle        = 0x80280027
	TPM_E_BAD_KEY_PROPERTY                                                    Handle        = 0x80280028
	TPM_E_BAD_MIGRATION                                                       Handle        = 0x80280029
	TPM_E_BAD_SCHEME                                                          Handle        = 0x8028002A
	TPM_E_BAD_DATASIZE                                                        Handle        = 0x8028002B
	TPM_E_BAD_MODE                                                            Handle        = 0x8028002C
	TPM_E_BAD_PRESENCE                                                        Handle        = 0x8028002D
	TPM_E_BAD_VERSION                                                         Handle        = 0x8028002E
	TPM_E_NO_WRAP_TRANSPORT                                                   Handle        = 0x8028002F
	TPM_E_AUDITFAIL_UNSUCCESSFUL                                              Handle        = 0x80280030
	TPM_E_AUDITFAIL_SUCCESSFUL                                                Handle        = 0x80280031
	TPM_E_NOTRESETABLE                                                        Handle        = 0x80280032
	TPM_E_NOTLOCAL                                                            Handle        = 0x80280033
	TPM_E_BAD_TYPE                                                            Handle        = 0x80280034
	TPM_E_INVALID_RESOURCE                                                    Handle        = 0x80280035
	TPM_E_NOTFIPS                                                             Handle        = 0x80280036
	TPM_E_INVALID_FAMILY                                                      Handle        = 0x80280037
	TPM_E_NO_NV_PERMISSION                                                    Handle        = 0x80280038
	TPM_E_REQUIRES_SIGN                                                       Handle        = 0x80280039
	TPM_E_KEY_NOTSUPPORTED                                                    Handle        = 0x8028003A
	TPM_E_AUTH_CONFLICT                                                       Handle        = 0x8028003B
	TPM_E_AREA_LOCKED                                                         Handle        = 0x8028003C
	TPM_E_BAD_LOCALITY                                                        Handle        = 0x8028003D
	TPM_E_READ_ONLY                                                           Handle        = 0x8028003E
	TPM_E_PER_NOWRITE                                                         Handle        = 0x8028003F
	TPM_E_FAMILYCOUNT                                                         Handle        = 0x80280040
	TPM_E_WRITE_LOCKED                                                        Handle        = 0x80280041
	TPM_E_BAD_ATTRIBUTES                                                      Handle        = 0x80280042
	TPM_E_INVALID_STRUCTURE                                                   Handle        = 0x80280043
	TPM_E_KEY_OWNER_CONTROL                                                   Handle        = 0x80280044
	TPM_E_BAD_COUNTER                                                         Handle        = 0x80280045
	TPM_E_NOT_FULLWRITE                                                       Handle        = 0x80280046
	TPM_E_CONTEXT_GAP                                                         Handle        = 0x80280047
	TPM_E_MAXNVWRITES                                                         Handle        = 0x80280048
	TPM_E_NOOPERATOR                                                          Handle        = 0x80280049
	TPM_E_RESOURCEMISSING                                                     Handle        = 0x8028004A
	TPM_E_DELEGATE_LOCK                                                       Handle        = 0x8028004B
	TPM_E_DELEGATE_FAMILY                                                     Handle        = 0x8028004C
	TPM_E_DELEGATE_ADMIN                                                      Handle        = 0x8028004D
	TPM_E_TRANSPORT_NOTEXCLUSIVE                                              Handle        = 0x8028004E
	TPM_E_OWNER_CONTROL                                                       Handle        = 0x8028004F
	TPM_E_DAA_RESOURCES                                                       Handle        = 0x80280050
	TPM_E_DAA_INPUT_DATA0                                                     Handle        = 0x80280051
	TPM_E_DAA_INPUT_DATA1                                                     Handle        = 0x80280052
	TPM_E_DAA_ISSUER_SETTINGS                                                 Handle        = 0x80280053
	TPM_E_DAA_TPM_SETTINGS                                                    Handle        = 0x80280054
	TPM_E_DAA_STAGE                                                           Handle        = 0x80280055
	TPM_E_DAA_ISSUER_VALIDITY                                                 Handle        = 0x80280056
	TPM_E_DAA_WRONG_W                                                         Handle        = 0x80280057
	TPM_E_BAD_HANDLE                                                          Handle        = 0x80280058
	TPM_E_BAD_DELEGATE                                                        Handle        = 0x80280059
	TPM_E_BADCONTEXT                                                          Handle        = 0x8028005A
	TPM_E_TOOMANYCONTEXTS                                                     Handle        = 0x8028005B
	TPM_E_MA_TICKET_SIGNATURE                                                 Handle        = 0x8028005C
	TPM_E_MA_DESTINATION                                                      Handle        = 0x8028005D
	TPM_E_MA_SOURCE                                                           Handle        = 0x8028005E
	TPM_E_MA_AUTHORITY                                                        Handle        = 0x8028005F
	TPM_E_PERMANENTEK                                                         Handle        = 0x80280061
	TPM_E_BAD_SIGNATURE                                                       Handle        = 0x80280062
	TPM_E_NOCONTEXTSPACE                                                      Handle        = 0x80280063
	TPM_20_E_ASYMMETRIC                                                       Handle        = 0x80280081
	TPM_20_E_ATTRIBUTES                                                       Handle        = 0x80280082
	TPM_20_E_HASH                                                             Handle        = 0x80280083
	TPM_20_E_VALUE                                                            Handle        = 0x80280084
	TPM_20_E_HIERARCHY                                                        Handle        = 0x80280085
	TPM_20_E_KEY_SIZE                                                         Handle        = 0x80280087
	TPM_20_E_MGF                                                              Handle        = 0x80280088
	TPM_20_E_MODE                                                             Handle        = 0x80280089
	TPM_20_E_TYPE                                                             Handle        = 0x8028008A
	TPM_20_E_HANDLE                                                           Handle        = 0x8028008B
	TPM_20_E_KDF                                                              Handle        = 0x8028008C
	TPM_20_E_RANGE                                                            Handle        = 0x8028008D
	TPM_20_E_AUTH_FAIL                                                        Handle        = 0x8028008E
	TPM_20_E_NONCE                                                            Handle        = 0x8028008F
	TPM_20_E_PP                                                               Handle        = 0x80280090
	TPM_20_E_SCHEME                                                           Handle        = 0x80280092
	TPM_20_E_SIZE                                                             Handle        = 0x80280095
	TPM_20_E_SYMMETRIC                                                        Handle        = 0x80280096
	TPM_20_E_TAG                                                              Handle        = 0x80280097
	TPM_20_E_SELECTOR                                                         Handle        = 0x80280098
	TPM_20_E_INSUFFICIENT                                                     Handle        = 0x8028009A
	TPM_20_E_SIGNATURE                                                        Handle        = 0x8028009B
	TPM_20_E_KEY                                                              Handle        = 0x8028009C
	TPM_20_E_POLICY_FAIL                                                      Handle        = 0x8028009D
	TPM_20_E_INTEGRITY                                                        Handle        = 0x8028009F
	TPM_20_E_TICKET                                                           Handle        = 0x802800A0
	TPM_20_E_RESERVED_BITS                                                    Handle        = 0x802800A1
	TPM_20_E_BAD_AUTH                                                         Handle        = 0x802800A2
	TPM_20_E_EXPIRED                                                          Handle        = 0x802800A3
	TPM_20_E_POLICY_CC                                                        Handle        = 0x802800A4
	TPM_20_E_BINDING                                                          Handle        = 0x802800A5
	TPM_20_E_CURVE                                                            Handle        = 0x802800A6
	TPM_20_E_ECC_POINT                                                        Handle        = 0x802800A7
	TPM_20_E_INITIALIZE                                                       Handle        = 0x80280100
	TPM_20_E_FAILURE                                                          Handle        = 0x80280101
	TPM_20_E_SEQUENCE                                                         Handle        = 0x80280103
	TPM_20_E_PRIVATE                                                          Handle        = 0x8028010B
	TPM_20_E_HMAC                                                             Handle        = 0x80280119
	TPM_20_E_DISABLED                                                         Handle        = 0x80280120
	TPM_20_E_EXCLUSIVE                                                        Handle        = 0x80280121
	TPM_20_E_ECC_CURVE                                                        Handle        = 0x80280123
	TPM_20_E_AUTH_TYPE                                                        Handle        = 0x80280124
	TPM_20_E_AUTH_MISSING                                                     Handle        = 0x80280125
	TPM_20_E_POLICY                                                           Handle        = 0x80280126
	TPM_20_E_PCR                                                              Handle        = 0x80280127
	TPM_20_E_PCR_CHANGED                                                      Handle        = 0x80280128
	TPM_20_E_UPGRADE                                                          Handle        = 0x8028012D
	TPM_20_E_TOO_MANY_CONTEXTS                                                Handle        = 0x8028012E
	TPM_20_E_AUTH_UNAVAILABLE                                                 Handle        = 0x8028012F
	TPM_20_E_REBOOT                                                           Handle        = 0x80280130
	TPM_20_E_UNBALANCED                                                       Handle        = 0x80280131
	TPM_20_E_COMMAND_SIZE                                                     Handle        = 0x80280142
	TPM_20_E_COMMAND_CODE                                                     Handle        = 0x80280143
	TPM_20_E_AUTHSIZE                                                         Handle        = 0x80280144
	TPM_20_E_AUTH_CONTEXT                                                     Handle        = 0x80280145
	TPM_20_E_NV_RANGE                                                         Handle        = 0x80280146
	TPM_20_E_NV_SIZE                                                          Handle        = 0x80280147
	TPM_20_E_NV_LOCKED                                                        Handle        = 0x80280148
	TPM_20_E_NV_AUTHORIZATION                                                 Handle        = 0x80280149
	TPM_20_E_NV_UNINITIALIZED                                                 Handle        = 0x8028014A
	TPM_20_E_NV_SPACE                                                         Handle        = 0x8028014B
	TPM_20_E_NV_DEFINED                                                       Handle        = 0x8028014C
	TPM_20_E_BAD_CONTEXT                                                      Handle        = 0x80280150
	TPM_20_E_CPHASH                                                           Handle        = 0x80280151
	TPM_20_E_PARENT                                                           Handle        = 0x80280152
	TPM_20_E_NEEDS_TEST                                                       Handle        = 0x80280153
	TPM_20_E_NO_RESULT                                                        Handle        = 0x80280154
	TPM_20_E_SENSITIVE                                                        Handle        = 0x80280155
	TPM_E_COMMAND_BLOCKED                                                     Handle        = 0x80280400
	TPM_E_INVALID_HANDLE                                                      Handle        = 0x80280401
	TPM_E_DUPLICATE_VHANDLE                                                   Handle        = 0x80280402
	TPM_E_EMBEDDED_COMMAND_BLOCKED                                            Handle        = 0x80280403
	TPM_E_EMBEDDED_COMMAND_UNSUPPORTED                                        Handle        = 0x80280404
	TPM_E_RETRY                                                               Handle        = 0x80280800
	TPM_E_NEEDS_SELFTEST                                                      Handle        = 0x80280801
	TPM_E_DOING_SELFTEST                                                      Handle        = 0x80280802
	TPM_E_DEFEND_LOCK_RUNNING                                                 Handle        = 0x80280803
	TPM_20_E_CONTEXT_GAP                                                      Handle        = 0x80280901
	TPM_20_E_OBJECT_MEMORY                                                    Handle        = 0x80280902
	TPM_20_E_SESSION_MEMORY                                                   Handle        = 0x80280903
	TPM_20_E_MEMORY                                                           Handle        = 0x80280904
	TPM_20_E_SESSION_HANDLES                                                  Handle        = 0x80280905
	TPM_20_E_OBJECT_HANDLES                                                   Handle        = 0x80280906
	TPM_20_E_LOCALITY                                                         Handle        = 0x80280907
	TPM_20_E_YIELDED                                                          Handle        = 0x80280908
	TPM_20_E_CANCELED                                                         Handle        = 0x80280909
	TPM_20_E_TESTING                                                          Handle        = 0x8028090A
	TPM_20_E_NV_RATE                                                          Handle        = 0x80280920
	TPM_20_E_LOCKOUT                                                          Handle        = 0x80280921
	TPM_20_E_RETRY                                                            Handle        = 0x80280922
	TPM_20_E_NV_UNAVAILABLE                                                   Handle        = 0x80280923
	TBS_E_INTERNAL_ERROR                                                      Handle        = 0x80284001
	TBS_E_BAD_PARAMETER                                                       Handle        = 0x80284002
	TBS_E_INVALID_OUTPUT_POINTER                                              Handle        = 0x80284003
	TBS_E_INVALID_CONTEXT                                                     Handle        = 0x80284004
	TBS_E_INSUFFICIENT_BUFFER                                                 Handle        = 0x80284005
	TBS_E_IOERROR                                                             Handle        = 0x80284006
	TBS_E_INVALID_CONTEXT_PARAM                                               Handle        = 0x80284007
	TBS_E_SERVICE_NOT_RUNNING                                                 Handle        = 0x80284008
	TBS_E_TOO_MANY_TBS_CONTEXTS                                               Handle        = 0x80284009
	TBS_E_TOO_MANY_RESOURCES                                                  Handle        = 0x8028400A
	TBS_E_SERVICE_START_PENDING                                               Handle        = 0x8028400B
	TBS_E_PPI_NOT_SUPPORTED                                                   Handle        = 0x8028400C
	TBS_E_COMMAND_CANCELED                                                    Handle        = 0x8028400D
	TBS_E_BUFFER_TOO_LARGE                                                    Handle        = 0x8028400E
	TBS_E_TPM_NOT_FOUND                                                       Handle        = 0x8028400F
	TBS_E_SERVICE_DISABLED                                                    Handle        = 0x80284010
	TBS_E_NO_EVENT_LOG                                                        Handle        = 0x80284011
	TBS_E_ACCESS_DENIED                                                       Handle        = 0x80284012
	TBS_E_PROVISIONING_NOT_ALLOWED                                            Handle        = 0x80284013
	TBS_E_PPI_FUNCTION_UNSUPPORTED                                            Handle        = 0x80284014
	TBS_E_OWNERAUTH_NOT_FOUND                                                 Handle        = 0x80284015
	TBS_E_PROVISIONING_INCOMPLETE                                             Handle        = 0x80284016
	TPMAPI_E_INVALID_STATE                                                    Handle        = 0x80290100
	TPMAPI_E_NOT_ENOUGH_DATA                                                  Handle        = 0x80290101
	TPMAPI_E_TOO_MUCH_DATA                                                    Handle        = 0x80290102
	TPMAPI_E_INVALID_OUTPUT_POINTER                                           Handle        = 0x80290103
	TPMAPI_E_INVALID_PARAMETER                                                Handle        = 0x80290104
	TPMAPI_E_OUT_OF_MEMORY                                                    Handle        = 0x80290105
	TPMAPI_E_BUFFER_TOO_SMALL                                                 Handle        = 0x80290106
	TPMAPI_E_INTERNAL_ERROR                                                   Handle        = 0x80290107
	TPMAPI_E_ACCESS_DENIED                                                    Handle        = 0x80290108
	TPMAPI_E_AUTHORIZATION_FAILED                                             Handle        = 0x80290109
	TPMAPI_E_INVALID_CONTEXT_HANDLE                                           Handle        = 0x8029010A
	TPMAPI_E_TBS_COMMUNICATION_ERROR                                          Handle        = 0x8029010B
	TPMAPI_E_TPM_COMMAND_ERROR                                                Handle        = 0x8029010C
	TPMAPI_E_MESSAGE_TOO_LARGE                                                Handle        = 0x8029010D
	TPMAPI_E_INVALID_ENCODING                                                 Handle        = 0x8029010E
	TPMAPI_E_INVALID_KEY_SIZE                                                 Handle        = 0x8029010F
	TPMAPI_E_ENCRYPTION_FAILED                                                Handle        = 0x80290110
	TPMAPI_E_INVALID_KEY_PARAMS                                               Handle        = 0x80290111
	TPMAPI_E_INVALID_MIGRATION_AUTHORIZATION_BLOB                             Handle        = 0x80290112
	TPMAPI_E_INVALID_PCR_INDEX                                                Handle        = 0x80290113
	TPMAPI_E_INVALID_DELEGATE_BLOB                                            Handle        = 0x80290114
	TPMAPI_E_INVALID_CONTEXT_PARAMS                                           Handle        = 0x80290115
	TPMAPI_E_INVALID_KEY_BLOB                                                 Handle        = 0x80290116
	TPMAPI_E_INVALID_PCR_DATA                                                 Handle        = 0x80290117
	TPMAPI_E_INVALID_OWNER_AUTH                                               Handle        = 0x80290118
	TPMAPI_E_FIPS_RNG_CHECK_FAILED                                            Handle        = 0x80290119
	TPMAPI_E_EMPTY_TCG_LOG                                                    Handle        = 0x8029011A
	TPMAPI_E_INVALID_TCG_LOG_ENTRY                                            Handle        = 0x8029011B
	TPMAPI_E_TCG_SEPARATOR_ABSENT                                             Handle        = 0x8029011C
	TPMAPI_E_TCG_INVALID_DIGEST_ENTRY                                         Handle        = 0x8029011D
	TPMAPI_E_POLICY_DENIES_OPERATION                                          Handle        = 0x8029011E
	TPMAPI_E_NV_BITS_NOT_DEFINED                                              Handle        = 0x8029011F
	TPMAPI_E_NV_BITS_NOT_READY                                                Handle        = 0x80290120
	TPMAPI_E_SEALING_KEY_NOT_AVAILABLE                                        Handle        = 0x80290121
	TPMAPI_E_NO_AUTHORIZATION_CHAIN_FOUND                                     Handle        = 0x80290122
	TPMAPI_E_SVN_COUNTER_NOT_AVAILABLE                                        Handle        = 0x80290123
	TPMAPI_E_OWNER_AUTH_NOT_NULL                                              Handle        = 0x80290124
	TPMAPI_E_ENDORSEMENT_AUTH_NOT_NULL                                        Handle        = 0x80290125
	TPMAPI_E_AUTHORIZATION_REVOKED                                            Handle        = 0x80290126
	TPMAPI_E_MALFORMED_AUTHORIZATION_KEY                                      Handle        = 0x80290127
	TPMAPI_E_AUTHORIZING_KEY_NOT_SUPPORTED                                    Handle        = 0x80290128
	TPMAPI_E_INVALID_AUTHORIZATION_SIGNATURE                                  Handle        = 0x80290129
	TPMAPI_E_MALFORMED_AUTHORIZATION_POLICY                                   Handle        = 0x8029012A
	TPMAPI_E_MALFORMED_AUTHORIZATION_OTHER                                    Handle        = 0x8029012B
	TPMAPI_E_SEALING_KEY_CHANGED                                              Handle        = 0x8029012C
	TBSIMP_E_BUFFER_TOO_SMALL                                                 Handle        = 0x80290200
	TBSIMP_E_CLEANUP_FAILED                                                   Handle        = 0x80290201
	TBSIMP_E_INVALID_CONTEXT_HANDLE                                           Handle        = 0x80290202
	TBSIMP_E_INVALID_CONTEXT_PARAM                                            Handle        = 0x80290203
	TBSIMP_E_TPM_ERROR                                                        Handle        = 0x80290204
	TBSIMP_E_HASH_BAD_KEY                                                     Handle        = 0x80290205
	TBSIMP_E_DUPLICATE_VHANDLE                                                Handle        = 0x80290206
	TBSIMP_E_INVALID_OUTPUT_POINTER                                           Handle        = 0x80290207
	TBSIMP_E_INVALID_PARAMETER                                                Handle        = 0x80290208
	TBSIMP_E_RPC_INIT_FAILED                                                  Handle        = 0x80290209
	TBSIMP_E_SCHEDULER_NOT_RUNNING                                            Handle        = 0x8029020A
	TBSIMP_E_COMMAND_CANCELED                                                 Handle        = 0x8029020B
	TBSIMP_E_OUT_OF_MEMORY                                                    Handle        = 0x8029020C
	TBSIMP_E_LIST_NO_MORE_ITEMS                                               Handle        = 0x8029020D
	TBSIMP_E_LIST_NOT_FOUND                                                   Handle        = 0x8029020E
	TBSIMP_E_NOT_ENOUGH_SPACE                                                 Handle        = 0x8029020F
	TBSIMP_E_NOT_ENOUGH_TPM_CONTEXTS                                          Handle        = 0x80290210
	TBSIMP_E_COMMAND_FAILED                                                   Handle        = 0x80290211
	TBSIMP_E_UNKNOWN_ORDINAL                                                  Handle        = 0x80290212
	TBSIMP_E_RESOURCE_EXPIRED                                                 Handle        = 0x80290213
	TBSIMP_E_INVALID_RESOURCE                                                 Handle        = 0x80290214
	TBSIMP_E_NOTHING_TO_UNLOAD                                                Handle        = 0x80290215
	TBSIMP_E_HASH_TABLE_FULL                                                  Handle        = 0x80290216
	TBSIMP_E_TOO_MANY_TBS_CONTEXTS                                            Handle        = 0x80290217
	TBSIMP_E_TOO_MANY_RESOURCES                                               Handle        = 0x80290218
	TBSIMP_E_PPI_NOT_SUPPORTED                                                Handle        = 0x80290219
	TBSIMP_E_TPM_INCOMPATIBLE                                                 Handle        = 0x8029021A
	TBSIMP_E_NO_EVENT_LOG                                                     Handle        = 0x8029021B
	TPM_E_PPI_ACPI_FAILURE                                                    Handle        = 0x80290300
	TPM_E_PPI_USER_ABORT                                                      Handle        = 0x80290301
	TPM_E_PPI_BIOS_FAILURE                                                    Handle        = 0x80290302
	TPM_E_PPI_NOT_SUPPORTED                                                   Handle        = 0x80290303
	TPM_E_PPI_BLOCKED_IN_BIOS                                                 Handle        = 0x80290304
	TPM_E_PCP_ERROR_MASK                                                      Handle        = 0x80290400
	TPM_E_PCP_DEVICE_NOT_READY                                                Handle        = 0x80290401
	TPM_E_PCP_INVALID_HANDLE                                                  Handle        = 0x80290402
	TPM_E_PCP_INVALID_PARAMETER                                               Handle        = 0x80290403
	TPM_E_PCP_FLAG_NOT_SUPPORTED                                              Handle        = 0x80290404
	TPM_E_PCP_NOT_SUPPORTED                                                   Handle        = 0x80290405
	TPM_E_PCP_BUFFER_TOO_SMALL                                                Handle        = 0x80290406
	TPM_E_PCP_INTERNAL_ERROR                                                  Handle        = 0x80290407
	TPM_E_PCP_AUTHENTICATION_FAILED                                           Handle        = 0x80290408
	TPM_E_PCP_AUTHENTICATION_IGNORED                                          Handle        = 0x80290409
	TPM_E_PCP_POLICY_NOT_FOUND                                                Handle        = 0x8029040A
	TPM_E_PCP_PROFILE_NOT_FOUND                                               Handle        = 0x8029040B
	TPM_E_PCP_VALIDATION_FAILED                                               Handle        = 0x8029040C
	TPM_E_PCP_WRONG_PARENT                                                    Handle        = 0x8029040E
	TPM_E_KEY_NOT_LOADED                                                      Handle        = 0x8029040F
	TPM_E_NO_KEY_CERTIFICATION                                                Handle        = 0x80290410
	TPM_E_KEY_NOT_FINALIZED                                                   Handle        = 0x80290411
	TPM_E_ATTESTATION_CHALLENGE_NOT_SET                                       Handle        = 0x80290412
	TPM_E_NOT_PCR_BOUND                                                       Handle        = 0x80290413
	TPM_E_KEY_ALREADY_FINALIZED                                               Handle        = 0x80290414
	TPM_E_KEY_USAGE_POLICY_NOT_SUPPORTED                                      Handle        = 0x80290415
	TPM_E_KEY_USAGE_POLICY_INVALID                                            Handle        = 0x80290416
	TPM_E_SOFT_KEY_ERROR                                                      Handle        = 0x80290417
	TPM_E_KEY_NOT_AUTHENTICATED                                               Handle        = 0x80290418
	TPM_E_PCP_KEY_NOT_AIK                                                     Handle        = 0x80290419
	TPM_E_KEY_NOT_SIGNING_KEY                                                 Handle        = 0x8029041A
	TPM_E_LOCKED_OUT                                                          Handle        = 0x8029041B
	TPM_E_CLAIM_TYPE_NOT_SUPPORTED                                            Handle        = 0x8029041C
	TPM_E_VERSION_NOT_SUPPORTED                                               Handle        = 0x8029041D
	TPM_E_BUFFER_LENGTH_MISMATCH                                              Handle        = 0x8029041E
	TPM_E_PCP_IFX_RSA_KEY_CREATION_BLOCKED                                    Handle        = 0x8029041F
	TPM_E_PCP_TICKET_MISSING                                                  Handle        = 0x80290420
	TPM_E_PCP_RAW_POLICY_NOT_SUPPORTED                                        Handle        = 0x80290421
	TPM_E_PCP_KEY_HANDLE_INVALIDATED                                          Handle        = 0x80290422
	TPM_E_PCP_UNSUPPORTED_PSS_SALT                                            Handle        = 0x40290423
	TPM_E_ZERO_EXHAUST_ENABLED                                                Handle        = 0x80290500
	PLA_E_DCS_NOT_FOUND                                                       Handle        = 0x80300002
	PLA_E_DCS_IN_USE                                                          Handle        = 0x803000AA
	PLA_E_TOO_MANY_FOLDERS                                                    Handle        = 0x80300045
	PLA_E_NO_MIN_DISK                                                         Handle        = 0x80300070
	PLA_E_DCS_ALREADY_EXISTS                                                  Handle        = 0x803000B7
	PLA_S_PROPERTY_IGNORED                                                    Handle        = 0x00300100
	PLA_E_PROPERTY_CONFLICT                                                   Handle        = 0x80300101
	PLA_E_DCS_SINGLETON_REQUIRED                                              Handle        = 0x80300102
	PLA_E_CREDENTIALS_REQUIRED                                                Handle        = 0x80300103
	PLA_E_DCS_NOT_RUNNING                                                     Handle        = 0x80300104
	PLA_E_CONFLICT_INCL_EXCL_API                                              Handle        = 0x80300105
	PLA_E_NETWORK_EXE_NOT_VALID                                               Handle        = 0x80300106
	PLA_E_EXE_ALREADY_CONFIGURED                                              Handle        = 0x80300107
	PLA_E_EXE_PATH_NOT_VALID                                                  Handle        = 0x80300108
	PLA_E_DC_ALREADY_EXISTS                                                   Handle        = 0x80300109
	PLA_E_DCS_START_WAIT_TIMEOUT                                              Handle        = 0x8030010A
	PLA_E_DC_START_WAIT_TIMEOUT                                               Handle        = 0x8030010B
	PLA_E_REPORT_WAIT_TIMEOUT                                                 Handle        = 0x8030010C
	PLA_E_NO_DUPLICATES                                                       Handle        = 0x8030010D
	PLA_E_EXE_FULL_PATH_REQUIRED                                              Handle        = 0x8030010E
	PLA_E_INVALID_SESSION_NAME                                                Handle        = 0x8030010F
	PLA_E_PLA_CHANNEL_NOT_ENABLED                                             Handle        = 0x80300110
	PLA_E_TASKSCHED_CHANNEL_NOT_ENABLED                                       Handle        = 0x80300111
	PLA_E_RULES_MANAGER_FAILED                                                Handle        = 0x80300112
	PLA_E_CABAPI_FAILURE                                                      Handle        = 0x80300113
	FVE_E_LOCKED_VOLUME                                                       Handle        = 0x80310000
	FVE_E_NOT_ENCRYPTED                                                       Handle        = 0x80310001
	FVE_E_NO_TPM_BIOS                                                         Handle        = 0x80310002
	FVE_E_NO_MBR_METRIC                                                       Handle        = 0x80310003
	FVE_E_NO_BOOTSECTOR_METRIC                                                Handle        = 0x80310004
	FVE_E_NO_BOOTMGR_METRIC                                                   Handle        = 0x80310005
	FVE_E_WRONG_BOOTMGR                                                       Handle        = 0x80310006
	FVE_E_SECURE_KEY_REQUIRED                                                 Handle        = 0x80310007
	FVE_E_NOT_ACTIVATED                                                       Handle        = 0x80310008
	FVE_E_ACTION_NOT_ALLOWED                                                  Handle        = 0x80310009
	FVE_E_AD_SCHEMA_NOT_INSTALLED                                             Handle        = 0x8031000A
	FVE_E_AD_INVALID_DATATYPE                                                 Handle        = 0x8031000B
	FVE_E_AD_INVALID_DATASIZE                                                 Handle        = 0x8031000C
	FVE_E_AD_NO_VALUES                                                        Handle        = 0x8031000D
	FVE_E_AD_ATTR_NOT_SET                                                     Handle        = 0x8031000E
	FVE_E_AD_GUID_NOT_FOUND                                                   Handle        = 0x8031000F
	FVE_E_BAD_INFORMATION                                                     Handle        = 0x80310010
	FVE_E_TOO_SMALL                                                           Handle        = 0x80310011
	FVE_E_SYSTEM_VOLUME                                                       Handle        = 0x80310012
	FVE_E_FAILED_WRONG_FS                                                     Handle        = 0x80310013
	FVE_E_BAD_PARTITION_SIZE                                                  Handle        = 0x80310014
	FVE_E_NOT_SUPPORTED                                                       Handle        = 0x80310015
	FVE_E_BAD_DATA                                                            Handle        = 0x80310016
	FVE_E_VOLUME_NOT_BOUND                                                    Handle        = 0x80310017
	FVE_E_TPM_NOT_OWNED                                                       Handle        = 0x80310018
	FVE_E_NOT_DATA_VOLUME                                                     Handle        = 0x80310019
	FVE_E_AD_INSUFFICIENT_BUFFER                                              Handle        = 0x8031001A
	FVE_E_CONV_READ                                                           Handle        = 0x8031001B
	FVE_E_CONV_WRITE                                                          Handle        = 0x8031001C
	FVE_E_KEY_REQUIRED                                                        Handle        = 0x8031001D
	FVE_E_CLUSTERING_NOT_SUPPORTED                                            Handle        = 0x8031001E
	FVE_E_VOLUME_BOUND_ALREADY                                                Handle        = 0x8031001F
	FVE_E_OS_NOT_PROTECTED                                                    Handle        = 0x80310020
	FVE_E_PROTECTION_DISABLED                                                 Handle        = 0x80310021
	FVE_E_RECOVERY_KEY_REQUIRED                                               Handle        = 0x80310022
	FVE_E_FOREIGN_VOLUME                                                      Handle        = 0x80310023
	FVE_E_OVERLAPPED_UPDATE                                                   Handle        = 0x80310024
	FVE_E_TPM_SRK_AUTH_NOT_ZERO                                               Handle        = 0x80310025
	FVE_E_FAILED_SECTOR_SIZE                                                  Handle        = 0x80310026
	FVE_E_FAILED_AUTHENTICATION                                               Handle        = 0x80310027
	FVE_E_NOT_OS_VOLUME                                                       Handle        = 0x80310028
	FVE_E_AUTOUNLOCK_ENABLED                                                  Handle        = 0x80310029
	FVE_E_WRONG_BOOTSECTOR                                                    Handle        = 0x8031002A
	FVE_E_WRONG_SYSTEM_FS                                                     Handle        = 0x8031002B
	FVE_E_POLICY_PASSWORD_REQUIRED                                            Handle        = 0x8031002C
	FVE_E_CANNOT_SET_FVEK_ENCRYPTED                                           Handle        = 0x8031002D
	FVE_E_CANNOT_ENCRYPT_NO_KEY                                               Handle        = 0x8031002E
	FVE_E_BOOTABLE_CDDVD                                                      Handle        = 0x80310030
	FVE_E_PROTECTOR_EXISTS                                                    Handle        = 0x80310031
	FVE_E_RELATIVE_PATH                                                       Handle        = 0x80310032
	FVE_E_PROTECTOR_NOT_FOUND                                                 Handle        = 0x80310033
	FVE_E_INVALID_KEY_FORMAT                                                  Handle        = 0x80310034
	FVE_E_INVALID_PASSWORD_FORMAT                                             Handle        = 0x80310035
	FVE_E_FIPS_RNG_CHECK_FAILED                                               Handle        = 0x80310036
	FVE_E_FIPS_PREVENTS_RECOVERY_PASSWORD                                     Handle        = 0x80310037
	FVE_E_FIPS_PREVENTS_EXTERNAL_KEY_EXPORT                                   Handle        = 0x80310038
	FVE_E_NOT_DECRYPTED                                                       Handle        = 0x80310039
	FVE_E_INVALID_PROTECTOR_TYPE                                              Handle        = 0x8031003A
	FVE_E_NO_PROTECTORS_TO_TEST                                               Handle        = 0x8031003B
	FVE_E_KEYFILE_NOT_FOUND                                                   Handle        = 0x8031003C
	FVE_E_KEYFILE_INVALID                                                     Handle        = 0x8031003D
	FVE_E_KEYFILE_NO_VMK                                                      Handle        = 0x8031003E
	FVE_E_TPM_DISABLED                                                        Handle        = 0x8031003F
	FVE_E_NOT_ALLOWED_IN_SAFE_MODE                                            Handle        = 0x80310040
	FVE_E_TPM_INVALID_PCR                                                     Handle        = 0x80310041
	FVE_E_TPM_NO_VMK                                                          Handle        = 0x80310042
	FVE_E_PIN_INVALID                                                         Handle        = 0x80310043
	FVE_E_AUTH_INVALID_APPLICATION                                            Handle        = 0x80310044
	FVE_E_AUTH_INVALID_CONFIG                                                 Handle        = 0x80310045
	FVE_E_FIPS_DISABLE_PROTECTION_NOT_ALLOWED                                 Handle        = 0x80310046
	FVE_E_FS_NOT_EXTENDED                                                     Handle        = 0x80310047
	FVE_E_FIRMWARE_TYPE_NOT_SUPPORTED                                         Handle        = 0x80310048
	FVE_E_NO_LICENSE                                                          Handle        = 0x80310049
	FVE_E_NOT_ON_STACK                                                        Handle        = 0x8031004A
	FVE_E_FS_MOUNTED                                                          Handle        = 0x8031004B
	FVE_E_TOKEN_NOT_IMPERSONATED                                              Handle        = 0x8031004C
	FVE_E_DRY_RUN_FAILED                                                      Handle        = 0x8031004D
	FVE_E_REBOOT_REQUIRED                                                     Handle        = 0x8031004E
	FVE_E_DEBUGGER_ENABLED                                                    Handle        = 0x8031004F
	FVE_E_RAW_ACCESS                                                          Handle        = 0x80310050
	FVE_E_RAW_BLOCKED                                                         Handle        = 0x80310051
	FVE_E_BCD_APPLICATIONS_PATH_INCORRECT                                     Handle        = 0x80310052
	FVE_E_NOT_ALLOWED_IN_VERSION                                              Handle        = 0x80310053
	FVE_E_NO_AUTOUNLOCK_MASTER_KEY                                            Handle        = 0x80310054
	FVE_E_MOR_FAILED                                                          Handle        = 0x80310055
	FVE_E_HIDDEN_VOLUME                                                       Handle        = 0x80310056
	FVE_E_TRANSIENT_STATE                                                     Handle        = 0x80310057
	FVE_E_PUBKEY_NOT_ALLOWED                                                  Handle        = 0x80310058
	FVE_E_VOLUME_HANDLE_OPEN                                                  Handle        = 0x80310059
	FVE_E_NO_FEATURE_LICENSE                                                  Handle        = 0x8031005A
	FVE_E_INVALID_STARTUP_OPTIONS                                             Handle        = 0x8031005B
	FVE_E_POLICY_RECOVERY_PASSWORD_NOT_ALLOWED                                Handle        = 0x8031005C
	FVE_E_POLICY_RECOVERY_PASSWORD_REQUIRED                                   Handle        = 0x8031005D
	FVE_E_POLICY_RECOVERY_KEY_NOT_ALLOWED                                     Handle        = 0x8031005E
	FVE_E_POLICY_RECOVERY_KEY_REQUIRED                                        Handle        = 0x8031005F
	FVE_E_POLICY_STARTUP_PIN_NOT_ALLOWED                                      Handle        = 0x80310060
	FVE_E_POLICY_STARTUP_PIN_REQUIRED                                         Handle        = 0x80310061
	FVE_E_POLICY_STARTUP_KEY_NOT_ALLOWED                                      Handle        = 0x80310062
	FVE_E_POLICY_STARTUP_KEY_REQUIRED                                         Handle        = 0x80310063
	FVE_E_POLICY_STARTUP_PIN_KEY_NOT_ALLOWED                                  Handle        = 0x80310064
	FVE_E_POLICY_STARTUP_PIN_KEY_REQUIRED                                     Handle        = 0x80310065
	FVE_E_POLICY_STARTUP_TPM_NOT_ALLOWED                                      Handle        = 0x80310066
	FVE_E_POLICY_STARTUP_TPM_REQUIRED                                         Handle        = 0x80310067
	FVE_E_POLICY_INVALID_PIN_LENGTH                                           Handle        = 0x80310068
	FVE_E_KEY_PROTECTOR_NOT_SUPPORTED                                         Handle        = 0x80310069
	FVE_E_POLICY_PASSPHRASE_NOT_ALLOWED                                       Handle        = 0x8031006A
	FVE_E_POLICY_PASSPHRASE_REQUIRED                                          Handle        = 0x8031006B
	FVE_E_FIPS_PREVENTS_PASSPHRASE                                            Handle        = 0x8031006C
	FVE_E_OS_VOLUME_PASSPHRASE_NOT_ALLOWED                                    Handle        = 0x8031006D
	FVE_E_INVALID_BITLOCKER_OID                                               Handle        = 0x8031006E
	FVE_E_VOLUME_TOO_SMALL                                                    Handle        = 0x8031006F
	FVE_E_DV_NOT_SUPPORTED_ON_FS                                              Handle        = 0x80310070
	FVE_E_DV_NOT_ALLOWED_BY_GP                                                Handle        = 0x80310071
	FVE_E_POLICY_USER_CERTIFICATE_NOT_ALLOWED                                 Handle        = 0x80310072
	FVE_E_POLICY_USER_CERTIFICATE_REQUIRED                                    Handle        = 0x80310073
	FVE_E_POLICY_USER_CERT_MUST_BE_HW                                         Handle        = 0x80310074
	FVE_E_POLICY_USER_CONFIGURE_FDV_AUTOUNLOCK_NOT_
```