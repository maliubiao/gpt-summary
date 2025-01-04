Response:
Let's break down the thought process for analyzing this C code. The goal is to understand its functionality, its relation to reverse engineering, its low-level aspects, its logic, potential user errors, and how a user might trigger its execution within the Frida context.

**1. Initial Code Scan & High-Level Understanding:**

* **File Name:** `icon-helpers.c` immediately suggests its purpose: dealing with icons.
* **Includes:**  `<psapi.h>` (Process Status API) and `<shellapi.h>` (Shell API) point to interacting with processes and the Windows shell.
* **Data Structures:** `FindMainWindowCtx` hints at finding the main window of a process.
* **Function Prefixes:** `_frida_` suggests this code is part of the Frida framework.
* **Core Functions:**  `_frida_icon_from_process_or_file`, `_frida_icon_from_process`, `_frida_icon_from_file`, `_frida_icon_from_resource_url`, `_frida_icon_from_native_icon_handle`. These clearly outline the different ways icons can be retrieved.
* **`GVariant`:**  This data type is used for returning icon information. It's likely part of the GLib library, a common dependency for projects like Frida.
* **`FridaIconSize`:** An enum or typedef for icon sizes (small/large).

**2. Deeper Dive into Each Function:**

* **`_frida_icon_from_process_or_file`:**  Simple logic: try getting the icon from a process first, then from a file if that fails.
* **`_frida_icon_from_process`:**
    * **`find_main_window_of_pid`:**  This is key. It finds the main window of a given process ID (PID).
    * **`SendMessageTimeout`:**  Used to send `WM_GETICON` messages to the main window to request its icon. It tries different icon sizes (small, large).
    * **`GetClassLongPtr(main_window, GCLP_HICONSM/GCLP_HICON)`:** If `WM_GETICON` fails, it tries to get the icon associated with the window's class.
    * **`WM_QUERYDRAGICON`:** A fallback for getting the large icon.
    * **`_frida_icon_from_native_icon_handle`:** This likely handles the conversion of the Windows `HICON` to Frida's `GVariant` representation.
* **`_frida_icon_from_file`:**
    * **`SHGetFileInfoW`:**  Uses the Shell API to retrieve the icon associated with a file. This is standard Windows functionality.
    * **`DestroyIcon`:**  Important to clean up resources.
* **`_frida_icon_from_resource_url`:**
    * **`ExpandEnvironmentStringsW`:**  Handles environment variables in the resource URL.
    * **Parsing the URL:**  Looks for a comma to separate the file path from the resource ID.
    * **`Wow64DisableWow64FsRedirection`/`Wow64RevertWow64FsRedirection`:**  Crucial for handling 32-bit processes on 64-bit Windows. File system redirection can cause issues when accessing files.
    * **`ExtractIconExW`:**  Extracts an icon from an executable or DLL file based on its resource ID.
* **`_frida_icon_from_native_icon_handle`:**
    * **`CreateCompatibleDC`:** Creates a device context for drawing.
    * **`GetSystemMetrics(SM_CXSMICON/SM_CXICON)`:** Gets the standard small and large icon dimensions.
    * **`BITMAPV5HEADER`:**  Defines the structure of a bitmap, specifically used for 32-bit RGBA.
    * **`CreateDIBSection`:** Creates a device-independent bitmap (DIB) where the icon data will be copied.
    * **`DrawIconEx`:**  Draws the `HICON` onto the DIB.
    * **BGR to RGB conversion:** The loop that swaps red and blue components. Windows bitmaps are often BGR.
    * **`g_variant_builder`:**  Packages the icon data (format, width, height, image data) into a `GVariant`.
* **`find_main_window_of_pid`:**
    * **`EnumWindows`:**  Iterates through all top-level windows.
    * **`inspect_window`:**  The callback function for `EnumWindows`.
* **`inspect_window`:**
    * **`GetWindowLong(hwnd, GWL_STYLE) & WS_VISIBLE`:** Checks if the window is visible.
    * **`GetWindowThreadProcessId`:** Gets the PID of the process that owns the window.

**3. Identifying Connections to Reverse Engineering, Low-Level Concepts, and Platform Specifics:**

* **Reverse Engineering:**  Frida itself is a reverse engineering tool. This code helps visualize processes by retrieving their icons. Knowing how icons are stored and retrieved is useful in understanding application structure.
* **Binary/Low-Level:**
    * **`HICON`:** A Windows handle to an icon.
    * **`BITMAPV5HEADER` and DIB:**  Directly dealing with bitmap structures.
    * **Pixel manipulation (BGR to RGB):**  Understanding image data formats.
    * **File system redirection (Wow64):** A crucial detail for cross-architecture compatibility.
    * **Resource IDs:** How icons are stored within executable files.
* **Windows Kernel/Framework:**
    * **Window Management:**  `HWND`, `EnumWindows`, `SendMessageTimeout`, `GetClassLongPtr`.
    * **Process Management:** `DWORD pid`, `GetWindowThreadProcessId`.
    * **Shell API:** `SHGetFileInfoW`.
    * **Graphics:** `HDC`, `CreateCompatibleDC`, `DrawIconEx`, `CreateDIBSection`.

**4. Logical Reasoning (Assumptions and Outputs):**

* **Assumption:**  A user provides a valid PID.
* **Output:** The function attempts to retrieve the icon for that process. If successful, it returns a `GVariant` containing the icon data (format, dimensions, RGBA image). If not, it returns `NULL`.
* **Assumption:** A user provides a valid file path.
* **Output:** The function attempts to retrieve the file's icon. If successful, it returns the `GVariant`; otherwise, `NULL`.
* **Assumption:** A user provides a valid resource URL like `"C:\\Windows\\System32\\shell32.dll,3"`.
* **Output:** The function extracts the icon with ID 3 from `shell32.dll`.

**5. Identifying User/Programming Errors:**

* **Invalid PID:** If the provided PID doesn't exist, `find_main_window_of_pid` will return `NULL`, and subsequent icon retrieval attempts might fail or return a default icon.
* **Invalid File Path:**  `_frida_icon_from_file` will likely return `NULL`.
* **Incorrect Resource URL:**  If the URL is malformed (e.g., missing comma, invalid resource ID, incorrect file path), `_frida_icon_from_resource_url` will fail.
* **Permissions Issues:** Frida might not have the necessary permissions to access certain processes or files, causing icon retrieval to fail.
* **Memory Leaks (Less likely but possible):** Although the code has `DestroyIcon` and `g_free`, a logic error could potentially lead to leaks if certain paths aren't taken. (Good practice to always double-check resource cleanup).

**6. Tracing User Operations (Debugging Clues):**

The user interaction would likely be through Frida's API. For example, in a Python script using Frida:

```python
import frida

# Attach to a process by name or PID
session = frida.attach("target_process")  # Or frida.attach(1234)

# Call a Frida function (not directly this C code, but something that *uses* it)
# that retrieves process information, including the icon.
# For example, Frida might have a function to get process details.

# The Frida core (this C code) would be involved in fetching the icon
# when that higher-level API is called.
```

The debugging steps would involve:

* **Setting breakpoints** in this C code (if you have access to the Frida source and are debugging the core).
* **Examining the values** of `pid`, `filename`, `size`, `icon`, etc., at different points in the execution.
* **Checking the return values** of Windows API functions like `SendMessageTimeout`, `SHGetFileInfoW`, `ExtractIconExW`.
* **Verifying the contents of the `GVariant`** being returned.
* **Looking at Frida's logs** for any error messages related to icon retrieval.

By following these steps, the analysis becomes structured and covers the key aspects of the provided code. The process involves understanding the purpose of the code, dissecting its individual components, identifying its interactions with the operating system, and considering how it might be used and what could go wrong.
This C code file, `icon-helpers.c`, part of the Frida dynamic instrumentation toolkit for Windows, focuses on retrieving icons associated with processes, files, or resources. Here's a breakdown of its functionalities and connections to various technical aspects:

**Functionalities:**

1. **Retrieving Icons from Processes:**
    *   `_frida_icon_from_process(DWORD pid, FridaIconSize size)`: This is the core function for fetching an icon for a given process ID (`pid`). It attempts to get the icon in the specified `size` (small or large).
    *   It first tries to find the main window of the process using `find_main_window_of_pid(pid)`.
    *   If the main window is found, it uses `SendMessageTimeout` to send `WM_GETICON` messages to the window to request its icon (both small and large versions).
    *   As fallback, it tries to get the small or large icon from the window's class using `GetClassLongPtr`.
    *   For large icons, it also tries `SendMessageTimeout` with `WM_QUERYDRAGICON`.

2. **Retrieving Icons from Files:**
    *   `_frida_icon_from_file(WCHAR * filename, FridaIconSize size)`: This function retrieves the icon associated with a file specified by `filename`.
    *   It uses the Windows Shell API function `SHGetFileInfoW` with the `SHGFI_ICON` flag to get the file's icon.
    *   It handles both small and large icon requests through the `SHGFI_SMALLICON` and `SHGFI_LARGEICON` flags.
    *   It's crucial to note that after getting the icon handle, it calls `DestroyIcon` to release the associated resources.

3. **Retrieving Icons from Resource URLs:**
    *   `_frida_icon_from_resource_url(WCHAR * resource_url, FridaIconSize size)`: This function retrieves an icon from a resource embedded within a file (like an executable or DLL).
    *   It parses the `resource_url`, which is expected to be in the format "filepath,resourceid".
    *   It uses `ExpandEnvironmentStringsW` to handle potential environment variables in the file path.
    *   It uses `ExtractIconExW` to extract the specified icon (by `resource_id`) from the given file.
    *   It deals with potential file system redirection issues on 64-bit Windows by using `Wow64DisableWow64FsRedirection` and `Wow64RevertWow64FsRedirection` if the functions are available. This is important when Frida (which might be 32-bit) needs to access resources in a 64-bit process.

4. **Converting Native Icon Handle to Frida's Representation:**
    *   `_frida_icon_from_native_icon_handle(HICON icon, FridaIconSize size)`: This function takes a native Windows icon handle (`HICON`) and converts it into a `GVariant`, which is likely Frida's internal representation for icons.
    *   It creates a compatible device context (`HDC`).
    *   It determines the icon's dimensions based on the requested `size` using `GetSystemMetrics`.
    *   It creates a device-independent bitmap (DIB) using `CreateDIBSection` to hold the icon's pixel data in RGBA format.
    *   It draws the icon onto the DIB using `DrawIconEx`.
    *   It then converts the bitmap data to RGBA format (likely the bitmap is initially in BGRA) by swapping the red and blue color components.
    *   Finally, it builds a `GVariant` containing the icon's format ("rgba"), width, height, and the raw image data.

5. **Finding the Main Window of a Process:**
    *   `find_main_window_of_pid(DWORD pid)`: This helper function iterates through all top-level windows using `EnumWindows`.
    *   For each window, the `inspect_window` callback is called.
    *   `inspect_window(HWND hwnd, LPARAM lparam)`: This callback checks if the window is visible and if its process ID matches the target `pid`. If it matches, it stores the window handle in the context and stops the enumeration.

**Relationship with Reverse Engineering:**

*   **Visualizing Target Processes:** When reverse engineering an application, having its icon can be a quick way to visually identify the process you are targeting within a list of running processes. Frida, as a dynamic instrumentation tool, often needs to present information about the processes it can interact with, and displaying icons enhances the user experience.
*   **Identifying Components:**  If you are reverse engineering a modular application, different modules might have distinct icons. Retrieving these icons can help identify which specific component a certain piece of code belongs to.
*   **Debugging and Exploration:** During debugging sessions, especially when attaching to existing processes, seeing the application's icon can confirm that you've attached to the correct target.

**Example of Reverse Engineering Use:**

Imagine you are using Frida to inspect the behavior of a specific application. Frida might use the functions in `icon-helpers.c` to:

1. List all running processes with their names and icons. This allows the user to easily select the target application.
2. When you attach to a process, Frida might display the application's icon in its interface, providing visual confirmation.
3. If you are inspecting a plugin or module loaded by the target process, and that module has a unique icon as a resource, Frida could potentially retrieve and display that icon to differentiate it.

**Involvement of Binary 底层, Linux, Android Kernel & Framework Knowledge:**

*   **Binary 底层 (Binary Low-Level):**
    *   **Windows API:** The code heavily relies on Windows-specific APIs like `SendMessageTimeout`, `GetClassLongPtr`, `SHGetFileInfoW`, `ExtractIconExW`, `CreateDIBSection`, `DrawIconEx`, `EnumWindows`, etc. These APIs operate directly at the operating system level and deal with fundamental Windows concepts like windows, processes, and graphical resources.
    *   **Icon Handles (`HICON`):** The code manipulates `HICON`, which are integer values representing pointers to icon data in memory managed by the Windows kernel.
    *   **Bitmap Structures (`BITMAPV5HEADER`):**  The code directly works with bitmap structures to extract the raw pixel data of the icon. This involves understanding the layout of bitmap data in memory.
    *   **File System Redirection (Wow64):** The handling of `Wow64DisableWow64FsRedirection` is a low-level detail specific to 64-bit Windows, addressing the differences in file system paths seen by 32-bit and 64-bit processes.

*   **Linux and Android Kernel & Framework Knowledge:**
    *   **Not Directly Involved:** This specific code file is for Windows (`frida-core/src/windows`). The concepts of window management and the specific APIs used are Windows-centric.
    *   **Analogous Concepts:** While the exact implementation differs, the underlying idea of associating icons with applications exists in Linux (e.g., using freedesktop.org standards for icons) and Android (e.g., application icons stored in APK resources). Frida would have separate implementations for these platforms to achieve similar functionality. For instance, on Android, Frida might interact with the Android framework to retrieve application icons.

**Logic Reasoning with Assumptions and Outputs:**

**Scenario 1: Getting the icon of a running process**

*   **Assumption (Input):** `pid` is a valid process ID of a running application with a main window and an associated icon. `size` is `FRIDA_ICON_SMALL`.
*   **Steps:**
    1. `_frida_icon_from_process(pid, FRIDA_ICON_SMALL)` is called.
    2. `find_main_window_of_pid(pid)` successfully finds the main window `hwnd`.
    3. `SendMessageTimeout(hwnd, WM_GETICON, ICON_SMALL2, ...)` might succeed in retrieving a small icon handle.
    4. If step 3 fails, `SendMessageTimeout(hwnd, WM_GETICON, ICON_SMALL, ...)` is attempted.
    5. If step 4 also fails, `GetClassLongPtr(hwnd, GCLP_HICONSM)` is attempted.
    6. Assuming one of the above retrieves a valid `HICON icon`, `_frida_icon_from_native_icon_handle(icon, FRIDA_ICON_SMALL)` is called.
    7. This function converts the `HICON` to a `GVariant` representing the small icon (RGBA format, correct dimensions, image data).
*   **Output:** A `GVariant` containing the small icon of the process.

**Scenario 2: Getting the icon of a file**

*   **Assumption (Input):** `filename` is a valid path to an executable file. `size` is `FRIDA_ICON_LARGE`.
*   **Steps:**
    1. `_frida_icon_from_file(filename, FRIDA_ICON_LARGE)` is called.
    2. `SHGetFileInfoW(filename, 0, &shfi, sizeof(shfi), SHGFI_ICON | SHGFI_LARGEICON)` is called.
    3. Assuming the file has an icon, `shfi.hIcon` will contain a valid large icon handle.
    4. `_frida_icon_from_native_icon_handle(shfi.hIcon, FRIDA_ICON_LARGE)` is called.
    5. The icon handle is converted to a `GVariant` representing the large icon.
    6. `DestroyIcon(shfi.hIcon)` is called to release the icon handle.
*   **Output:** A `GVariant` containing the large icon of the file.

**Scenario 3: Getting an icon from a resource URL**

*   **Assumption (Input):** `resource_url` is `"C:\\Windows\\System32\\shell32.dll,3"` and `size` is `FRIDA_ICON_SMALL`.
*   **Steps:**
    1. `_frida_icon_from_resource_url(L"C:\\Windows\\System32\\shell32.dll,3", FRIDA_ICON_SMALL)` is called.
    2. `ExpandEnvironmentStringsW` resolves the path (if needed).
    3. The URL is parsed to extract the filename and resource ID (3).
    4. `ExtractIconExW(L"C:\\Windows\\System32\\shell32.dll", 3, NULL, &icon, 1)` is called (for small icon).
    5. Assuming the resource exists, `icon` will contain the handle to the small icon.
    6. `_frida_icon_from_native_icon_handle(icon, FRIDA_ICON_SMALL)` converts it.
    7. `DestroyIcon(icon)` is called.
*   **Output:** A `GVariant` containing the small icon from the specified resource.

**User or Programming Common Usage Errors:**

1. **Invalid PID:** Providing a non-existent or incorrect process ID to `_frida_icon_from_process`. This will likely result in `find_main_window_of_pid` returning `NULL`, and the function will return `NULL` (no icon).
2. **Invalid File Path:** Providing an incorrect or inaccessible file path to `_frida_icon_from_file`. `SHGetFileInfoW` will likely fail, and the function will return `NULL`.
3. **Malformed Resource URL:** Providing an incorrect format for the resource URL to `_frida_icon_from_resource_url` (e.g., missing comma, non-numeric resource ID, invalid file path). The parsing logic will fail, or `ExtractIconExW` will fail, resulting in a `NULL` return.
4. **Incorrect Icon Size:**  While not strictly an error that crashes the program, requesting a specific icon size might not always yield a result. For example, a process might only have a large icon and no small icon defined. The code attempts fallbacks, but if none are available, `NULL` might be returned.
5. **Permissions Issues:** Frida might not have the necessary permissions to access the target process, file, or resource. This could lead to API calls failing (e.g., `SendMessageTimeout`, `SHGetFileInfoW`, `ExtractIconExW`) and the icon retrieval failing.
6. **Resource Leaks (Potential Programming Error):** Although the code includes `DestroyIcon` to release icon handles, a logic error (e.g., an early return in some error condition before `DestroyIcon` is called) could potentially lead to resource leaks.

**User Operation Steps to Reach This Code (Debugging Clues):**

A user would typically interact with Frida through its API, often in Python or JavaScript. Here's a likely scenario:

1. **User Initiates Process Enumeration:** A user might use a Frida API function to list all running processes on the system. For example, in Python:

    ```python
    import frida

    session = frida.attach("explorer.exe") # Or attach to any process
    processes = frida.enumerate_processes()
    for process in processes:
        print(f"PID: {process.pid}, Name: {process.name}")
        # Internally, Frida might try to get the icon for each process here
    ```

2. **Frida Core Attempts Icon Retrieval:**  The Frida core, when implementing `frida.enumerate_processes()`, would iterate through the running processes and attempt to fetch their icons to provide more information to the user. This is where the functions in `icon-helpers.c` would be called. Specifically, `_frida_icon_from_process(process.pid, ...)` would be invoked.

3. **User Requests Process Details with Icon:**  A user might request more detailed information about a specific process, including its icon.

    ```python
    import frida

    process = frida.get_process("explorer.exe") # Or by PID
    if process and process.icon:
        print(f"Process Icon: {process.icon}") # The 'icon' attribute would be populated using this C code
    ```

4. **Directly Requesting File Icons:**  Frida might offer functionality to get the icon of a specific file path, which would directly call `_frida_icon_from_file`.

5. **Debugging Scenario:** If a user is experiencing issues with Frida displaying process icons, they might set breakpoints or add logging within the `icon-helpers.c` file (if they have access to the Frida source code) to understand why icon retrieval is failing for a specific process or file. They might check:
    *   The value of `pid` or `filename` being passed to the functions.
    *   The return values of Windows API calls like `SendMessageTimeout` or `SHGetFileInfoW`.
    *   Whether `find_main_window_of_pid` is successfully finding the main window.
    *   If permissions are being denied.

In essence, this `icon-helpers.c` file acts as a low-level utility within Frida to provide a richer user experience by displaying visual representations of processes and files. When a user interacts with Frida in ways that require displaying or working with process or file information, this code is likely to be involved.

Prompt: 
```
这是目录为frida/subprojects/frida-core/src/windows/icon-helpers.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
#include "icon-helpers.h"

#include <psapi.h>
#include <shellapi.h>

typedef struct _FindMainWindowCtx FindMainWindowCtx;

typedef BOOL (WINAPI * Wow64DisableWow64FsRedirectionFunc) (PVOID * OldValue);
typedef BOOL (WINAPI * Wow64RevertWow64FsRedirectionFunc) (PVOID OldValue);

struct _FindMainWindowCtx
{
  DWORD pid;
  HWND main_window;
};

static HWND find_main_window_of_pid (DWORD pid);
static BOOL CALLBACK inspect_window (HWND hwnd, LPARAM lparam);

GVariant *
_frida_icon_from_process_or_file (DWORD pid, WCHAR * filename, FridaIconSize size)
{
  GVariant * icon;

  icon = _frida_icon_from_process (pid, size);
  if (icon == NULL)
    icon = _frida_icon_from_file (filename, size);

  return icon;
}

GVariant *
_frida_icon_from_process (DWORD pid, FridaIconSize size)
{
  GVariant * result = NULL;
  HICON icon = NULL;
  HWND main_window;

  main_window = find_main_window_of_pid (pid);
  if (main_window != NULL)
  {
    UINT flags, timeout;

    flags = SMTO_ABORTIFHUNG | SMTO_BLOCK;
    timeout = 100;

    if (size == FRIDA_ICON_SMALL)
    {
      SendMessageTimeout (main_window, WM_GETICON, ICON_SMALL2, 0,
          flags, timeout, (PDWORD_PTR) &icon);

      if (icon == NULL)
      {
        SendMessageTimeout (main_window, WM_GETICON, ICON_SMALL, 0,
            flags, timeout, (PDWORD_PTR) &icon);
      }

      if (icon == NULL)
        icon = (HICON) GetClassLongPtr (main_window, GCLP_HICONSM);
    }
    else if (size == FRIDA_ICON_LARGE)
    {
      SendMessageTimeout (main_window, WM_GETICON, ICON_BIG, 0,
          flags, timeout, (PDWORD_PTR) &icon);

      if (icon == NULL)
        icon = (HICON) GetClassLongPtr (main_window, GCLP_HICON);

      if (icon == NULL)
      {
        SendMessageTimeout (main_window, WM_QUERYDRAGICON, 0, 0,
            flags, timeout, (PDWORD_PTR) &icon);
      }
    }
    else
    {
      g_assert_not_reached ();
    }
  }

  if (icon != NULL)
    result = _frida_icon_from_native_icon_handle (icon, size);

  return result;
}

GVariant *
_frida_icon_from_file (WCHAR * filename, FridaIconSize size)
{
  GVariant * result = NULL;
  SHFILEINFOW shfi = { 0, };
  UINT flags;

  flags = SHGFI_ICON;
  if (size == FRIDA_ICON_SMALL)
    flags |= SHGFI_SMALLICON;
  else if (size == FRIDA_ICON_LARGE)
    flags |= SHGFI_LARGEICON;
  else
    g_assert_not_reached ();

  SHGetFileInfoW (filename, 0, &shfi, sizeof (shfi), flags);
  if (shfi.hIcon != NULL)
  {
    result = _frida_icon_from_native_icon_handle (shfi.hIcon, size);

    DestroyIcon (shfi.hIcon);
  }

  return result;
}

GVariant *
_frida_icon_from_resource_url (WCHAR * resource_url, FridaIconSize size)
{
  static gboolean api_initialized = FALSE;
  static Wow64DisableWow64FsRedirectionFunc Wow64DisableWow64FsRedirectionImpl = NULL;
  static Wow64RevertWow64FsRedirectionFunc Wow64RevertWow64FsRedirectionImpl = NULL;
  GVariant * result = NULL;
  WCHAR * resource_file = NULL;
  DWORD resource_file_length;
  WCHAR * p;
  gint resource_id;
  PVOID old_redirection_value = NULL;
  UINT ret;
  HICON icon = NULL;

  if (!api_initialized)
  {
    HMODULE kmod;

    kmod = GetModuleHandleW (L"kernel32.dll");
    g_assert (kmod != NULL);

    Wow64DisableWow64FsRedirectionImpl = (Wow64DisableWow64FsRedirectionFunc) GetProcAddress (kmod, "Wow64DisableWow64FsRedirection");
    Wow64RevertWow64FsRedirectionImpl = (Wow64RevertWow64FsRedirectionFunc) GetProcAddress (kmod, "Wow64RevertWow64FsRedirection");
    g_assert ((Wow64DisableWow64FsRedirectionImpl != NULL) == (Wow64RevertWow64FsRedirectionImpl != NULL));

    api_initialized = TRUE;
  }

  resource_file_length = ExpandEnvironmentStringsW (resource_url, NULL, 0);
  if (resource_file_length == 0)
    goto beach;
  resource_file = (WCHAR *) g_malloc ((resource_file_length + 1) * sizeof (WCHAR));
  if (ExpandEnvironmentStringsW (resource_url, resource_file, resource_file_length) == 0)
    goto beach;

  p = wcsrchr (resource_file, L',');
  if (p == NULL)
    goto beach;
  *p = L'\0';

  resource_id = wcstol (p + 1, NULL, 10);

  if (Wow64DisableWow64FsRedirectionImpl != NULL)
    Wow64DisableWow64FsRedirectionImpl (&old_redirection_value);

  ret = ExtractIconExW (resource_file, resource_id, (size == FRIDA_ICON_LARGE) ? &icon : NULL, (size == FRIDA_ICON_SMALL) ? &icon : NULL, 1);

  if (Wow64RevertWow64FsRedirectionImpl != NULL)
    Wow64RevertWow64FsRedirectionImpl (old_redirection_value);

  if (ret != 1)
    goto beach;

  result = _frida_icon_from_native_icon_handle (icon, size);

beach:
  if (icon != NULL)
    DestroyIcon (icon);
  g_free (resource_file);

  return result;
}

GVariant *
_frida_icon_from_native_icon_handle (HICON icon, FridaIconSize size)
{
  GVariant * result;
  HDC dc;
  gint width = -1, height = -1;
  BITMAPV5HEADER bi = { 0, };
  guint rowstride;
  guchar * data = NULL;
  HBITMAP bm;
  guint i;
  GVariantBuilder builder;

  dc = CreateCompatibleDC (NULL);

  if (size == FRIDA_ICON_SMALL)
  {
    width = GetSystemMetrics (SM_CXSMICON);
    height = GetSystemMetrics (SM_CYSMICON);
  }
  else if (size == FRIDA_ICON_LARGE)
  {
    width = GetSystemMetrics (SM_CXICON);
    height = GetSystemMetrics (SM_CYICON);
  }
  else
  {
    g_assert_not_reached ();
  }

  bi.bV5Size = sizeof (bi);
  bi.bV5Width = width;
  bi.bV5Height = -height;
  bi.bV5Planes = 1;
  bi.bV5BitCount = 32;
  bi.bV5Compression = BI_BITFIELDS;
  bi.bV5RedMask   = 0x00ff0000;
  bi.bV5GreenMask = 0x0000ff00;
  bi.bV5BlueMask  = 0x000000ff;
  bi.bV5AlphaMask = 0xff000000;

  rowstride = width * (bi.bV5BitCount / 8);

  bm = CreateDIBSection (dc, (BITMAPINFO *) &bi, DIB_RGB_COLORS, (void **) &data, NULL, 0);

  SelectObject (dc, bm);
  DrawIconEx (dc, 0, 0, icon, width, height, 0, NULL, DI_NORMAL);
  GdiFlush ();

  for (i = 0; i != rowstride * height; i += 4)
  {
    guchar hold;

    hold = data[i + 0];
    data[i + 0] = data[i + 2];
    data[i + 2] = hold;
  }

  g_variant_builder_init (&builder, G_VARIANT_TYPE_VARDICT);
  g_variant_builder_add (&builder, "{sv}", "format", g_variant_new_string ("rgba"));
  g_variant_builder_add (&builder, "{sv}", "width", g_variant_new_int64 (width));
  g_variant_builder_add (&builder, "{sv}", "height", g_variant_new_int64 (height));
  g_variant_builder_add (&builder, "{sv}", "image",
      g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE, data, rowstride * height, sizeof (guint8)));
  result = g_variant_ref_sink (g_variant_builder_end (&builder));

  DeleteObject (bm);

  DeleteDC (dc);

  return result;
}

static HWND
find_main_window_of_pid (DWORD pid)
{
  FindMainWindowCtx ctx;

  ctx.pid = pid;
  ctx.main_window = NULL;

  EnumWindows (inspect_window, (LPARAM) &ctx);

  return ctx.main_window;
}

static BOOL CALLBACK
inspect_window (HWND hwnd, LPARAM lparam)
{
  if ((GetWindowLong (hwnd, GWL_STYLE) & WS_VISIBLE) != 0)
  {
    FindMainWindowCtx * ctx = (FindMainWindowCtx *) lparam;
    DWORD pid;

    GetWindowThreadProcessId (hwnd, &pid);
    if (pid == ctx->pid)
    {
      ctx->main_window = hwnd;
      return FALSE;
    }
  }

  return TRUE;
}

"""

```