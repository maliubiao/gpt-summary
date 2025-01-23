Response:
The user wants a summary of the functionalities present in the provided Python code snippet. This is the second part of the code, so I need to consider the context from the first part (which I don't have). However, I can still analyze the current code.

The code defines several classes, all inheriting from `DynamicLinker` or related classes. Each class represents a specific linker (like `gcc`, `ld`, `link.exe`, etc.) and implements methods to generate linker command-line arguments.

Here's a breakdown of how to approach the prompt's specific requirements:

1. **List functionalities:** Go through each class and its methods, explaining what each method is designed to do in the context of linking.
2. **Relation to reverse engineering:** Consider if any linker options or functionalities could be relevant in a reverse engineering context. This often involves examining symbols, libraries, or debugging information.
3. **Binary/OS/Kernel knowledge:** Linker behavior is inherently tied to the underlying operating system and binary format (like ELF or PE). Identify parts of the code that demonstrate this connection.
4. **Logical reasoning:**  Look for methods that construct arguments based on specific conditions or input. Provide example inputs and expected outputs for these.
5. **Common user errors:** Think about how users might incorrectly configure their build system or interact with the linker in ways that would lead to issues.
6. **User operation to reach this code:**  Consider the build process that leads to the execution of this linker code within the Frida build system.
7. **Overall summary:** Provide a concise overview of the purpose of the code.
这是 frida-gum 工具的 `linkers.py` 文件的第二部分，延续了第一部分定义的不同链接器类的实现。这些类都继承自 `DynamicLinker` 或其子类，并为特定的链接器提供了生成命令行参数的功能。以下是对这部分代码功能的归纳：

**主要功能：**

这部分代码定义了针对各种特定编译器和平台的动态链接器类，每个类都封装了特定链接器的命令行参数生成逻辑。这些类负责将通用的链接操作（例如指定输出文件、库搜索路径、共享库选项等）转换为特定链接器能够理解的命令行参数。

**各个链接器类的功能：**

* **`Xc16DynamicLinker`:**  用于 Microchip XC16 编译器的链接器。
    * 定义了 XC16 链接器的 ID。
    * 实现了获取链接整个归档文件的参数。
    * 指明 XC16 链接器不支持响应文件和搜索目录参数。
    * 实现了获取输出文件参数。
    * 指明 XC16 链接器不支持 soname。
    * `build_rpath_args` 方法返回空列表，说明 XC16 链接器不处理 rpath。

* **`CompCertDynamicLinker`:** 用于 CompCert C 编译器的链接器。
    * 定义了 CompCert 链接器的 ID。
    * 实现了获取链接整个归档文件的参数。
    * 指明 CompCert 链接器不支持响应文件。
    * 实现了获取库前缀、标准共享库参数和输出文件参数。
    * 实现了获取搜索目录参数。
    * 抛出异常表明 CompCert 链接器不支持共享库。
    * `build_rpath_args` 方法返回空列表，说明 CompCert 链接器不处理 rpath。

* **`TIDynamicLinker`:**  用于 Texas Instruments 编译器系列的链接器。
    * 定义了 TI 链接器的 ID。
    * 实现了获取链接整个归档文件的参数。
    * 指明 TI 链接器不支持响应文件和搜索目录参数。
    * 实现了获取库前缀、标准共享库参数和输出文件参数。
    * `get_always_args` 方法返回空列表，表示没有始终添加的参数。

* **`C2000DynamicLinker` 和 `C6000DynamicLinker`:**  分别是 TI C2000 和 C6000 编译器的链接器，继承自 `TIDynamicLinker` 并覆盖了 `id` 属性。

* **`ArmDynamicLinker`:** 用于 ARM 编译器的链接器。
    * 定义了 ARM 链接器的 ID。
    * 指明 ARM 链接器不支持响应文件和共享库。
    * 实现了获取允许未定义符号的参数。

* **`ArmClangDynamicLinker`:** 用于 ARM Clang 分支的链接器，继承自 `ArmDynamicLinker`。
    * 实现了导出动态符号和导入库的参数。

* **`QualcommLLVMDynamicLinker`:**  来自 Snapdragon LLVM ARM 编译器的 ARM 链接器，继承自 `LLVMDynamicLinker` 并覆盖了 `id` 属性。

* **`NAGDynamicLinker`:**  用于 NAG Fortran 链接器，通过 `gcc` 间接调用 `ld`。
    * 定义了 NAG 链接器的 ID。
    * 实现了构建 rpath 参数的特殊逻辑，通过 `-Wl,-Wl,,-rpath,` 传递给底层的 `ld`。
    * 实现了获取允许未定义符号和标准共享库参数的方法，其中标准共享库参数包含了 NAG Fortran 编译器的静默选项和 `-Wl,-shared`。

* **`PGIDynamicLinker`:** 用于 PGI 编译器的链接器。
    * 定义了 PGI 链接器的 ID。
    * 实现了获取允许未定义符号和 soname 的参数。
    * 实现了获取标准共享库参数，针对 Windows 和 Linux 有不同的参数。
    * 实现了构建 rpath 参数，在非 Windows 平台使用 `-R` 参数。

* **`NvidiaHPC_DynamicLinker` 和 `NvidiaHPC_StaticLinker`:**  分别是 Nvidia HPC 工具包的动态链接器和静态链接器，直接复用了 `PGIDynamicLinker` 和 `PGIStaticLinker`。

* **`VisualStudioLikeLinkerMixin`:**  一个混入类，为类似 Microsoft `link.exe` 的动态链接器提供通用功能。
    * 定义了优化级别对应的链接器参数。
    * 初始化方法中处理了可执行文件列表、目标机器、参数前缀、始终添加的参数等。
    * 实现了获取输出文件、始终添加的参数、库搜索路径、标准共享库参数、debug 文件名和参数、链接整个归档文件的参数。
    * 指明需要子类实现获取允许未定义符号和 soname 的参数。
    * 实现了导入库的参数。
    * 指定响应文件语法为 MSVC。

* **`MSVCDynamicLinker`:**  代表 Microsoft 的 `link.exe`，继承自 `VisualStudioLikeLinkerMixin`。
    * 定义了链接器的 ID。
    * 实现了获取始终添加的参数（`/release`）。
    * 实现了获取 Windows 子系统参数。

* **`ClangClDynamicLinker`:**  代表 Clang 的 `lld-link.exe`，继承自 `VisualStudioLikeLinkerMixin`。
    * 定义了链接器的 ID。
    * 重写了 `get_output_args` 方法，如果 `machine` 为 `None` 则不添加 `/MACHINE` 参数。
    * 实现了获取 Windows 子系统参数和 ThinLTO 缓存参数。

* **`XilinkDynamicLinker`:** 代表 Intel 的 `xilink.exe`，继承自 `VisualStudioLikeLinkerMixin`。
    * 定义了链接器的 ID。
    * 实现了获取 Windows 子系统参数。

* **`SolarisDynamicLinker`:** 用于 Solaris 和 OpenSolaris 的 Sys-V 派生链接器。
    * 定义了链接器的 ID。
    * 实现了获取链接整个归档文件、PIE、as-needed、no-undefined、allow-undefined 和 fatal-warnings 的参数。
    * 实现了构建 rpath 参数的复杂逻辑，包括处理 `$ORIGIN` 和 padding 以避免重链接。
    * 实现了获取 soname 的参数。

* **`AIXDynamicLinker`:** 用于 AIX 的 Sys-V 派生链接器。
    * 定义了链接器的 ID。
    * 实现了获取始终添加的参数（`-bnoipath`, `-bbigtoc`）、no-undefined 和 allow-undefined 的参数。
    * 实现了获取归档文件名的特殊逻辑，移除了 `.so` 和版本信息。
    * 实现了获取归档共享库的命令。
    * 实现了 `get_link_whole_for`，说明 AIX 链接器总是链接整个归档。
    * 实现了构建 rpath 参数的逻辑，包括添加系统库路径。
    * 实现了获取线程相关的编译标志。

* **`OptlinkDynamicLinker`:**  用于 Windows 的 Digital Mars 动态链接器。
    * 定义了链接器的 ID。
    * 指明不支持获取未定义符号的参数。
    * 指明 Optlink 不生成 pdb 文件。
    * `get_always_args` 返回空列表。

* **`CudaLinker`:**  用于 Cuda 链接器 (nvlink)。
    * 定义了链接器的 ID。
    * 实现了静态方法 `parse_version` 来获取 nvlink 的版本信息。
    * 指明 nvlink 不支持响应文件。
    * 实现了获取库前缀，特殊处理了 Windows 和 Linux 平台。
    * 实现了获取 fatal-warnings 和 allow-undefined 的参数。
    * 指明不支持获取 soname 的参数。

* **`MetrowerksLinker`:** 用于 Metrowerks 编译器的链接器。
    * 实现了获取 fatal-warnings 和 allow-undefined 的参数。
    * 指明支持响应文件。
    * 实现了获取库前缀、始终添加的链接器参数、输出文件参数和搜索目录参数。
    * 指明不是由编译器直接调用。
    * 指定响应文件语法为 GCC。

* **`MetrowerksLinkerARM` 和 `MetrowerksLinkerEmbeddedPowerPC`:**  分别是 Metrowerks ARM 和 Embedded PowerPC 编译器的链接器，继承自 `MetrowerksLinker` 并覆盖了 `id` 属性。

**与逆向方法的关联及举例：**

* **符号信息 (`get_debugfile_args`)：** 链接器通常负责生成包含调试符号的文件（例如 `.pdb` 文件在 Windows 上），这些符号信息对于逆向工程至关重要，可以帮助理解代码结构和变量。例如，`MSVCDynamicLinker` 的 `get_debugfile_args` 方法会生成 `/DEBUG` 和 `/PDB:` 参数，指示链接器生成调试信息。逆向工程师可以使用这些 `.pdb` 文件来调试和分析程序。
* **导出符号 (`export_dynamic_args` in `ArmClangDynamicLinker`)：**  动态链接器可以控制哪些符号被导出到动态链接库中。逆向工程师通常关注导出的符号，因为这些是库提供的公共接口。`ArmClangDynamicLinker` 的 `export_dynamic_args` 方法生成 `--export_dynamic` 参数，确保所有全局符号都被导出，这对于需要与该库交互的逆向分析很有用。
* **库依赖和 RPATH (`build_rpath_args`)：**  链接器处理库的依赖关系，并设置 RPATH（运行时库搜索路径）。逆向工程师可以通过分析 RPATH 来了解程序运行时会加载哪些库以及从哪些位置加载。例如，`SolarisDynamicLinker` 的 `build_rpath_args` 方法会生成 `-rpath` 参数，其中包含了库的搜索路径。
* **未定义符号 (`get_allow_undefined_args`, `no_undefined_args`)：**  链接器可以允许或禁止存在未定义的符号。在某些逆向场景中，可能需要分析包含未定义符号的中间链接产物。`AIXDynamicLinker` 的 `get_allow_undefined_args` 和 `no_undefined_args` 方法分别生成 `-berok` 和 `-bernotok` 参数来控制是否允许未定义的符号。

**涉及二进制底层、Linux、Android 内核及框架的知识：**

* **共享库和 `.so` 文件 (`get_std_shared_lib_args`, `get_soname_args`)：**  链接器负责生成共享库（在 Linux 上通常是 `.so` 文件）。`get_std_shared_lib_args` 方法生成创建共享库所需的参数（例如 `-shared` 在 GCC 中）。`get_soname_args` 方法生成设置共享库真实名称（SONAME）的参数，SONAME 是库的版本标识，对动态链接和版本管理至关重要。例如，`SolarisDynamicLinker` 的 `get_soname_args` 方法生成 `-soname` 参数。
* **RPATH 和 `$ORIGIN` (`build_rpath_args`)：**  RPATH 是一种在可执行文件中嵌入库搜索路径的技术。`$ORIGIN` 是 RPATH 中的一个特殊占位符，代表可执行文件所在的目录。`NAGDynamicLinker` 和 `SolarisDynamicLinker` 的 `build_rpath_args` 方法展示了如何处理 `$ORIGIN` 来构建相对路径的 RPATH。这对于理解程序如何在运行时查找依赖库非常重要。
* **PIE (Position Independent Executable) (`get_pie_args` in `SolarisDynamicLinker`)：**  PIE 是一种安全特性，使得可执行文件可以加载到内存的任意地址，从而增加地址空间布局随机化（ASLR）的有效性。`SolarisDynamicLinker` 的 `get_pie_args` 方法会检查链接器是否支持 PIE，并生成相应的参数。
* **链接整个归档 (`get_link_whole_for`)：** 某些链接器允许或要求链接整个静态库，而不是只链接需要的对象。这在处理某些特殊的库依赖关系时很有用。例如，`CompCertDynamicLinker` 的 `get_link_whole_for` 方法生成 `-Wl,--whole-archive` 和 `-Wl,--no-whole-archive` 参数。
* **Windows 子系统 (`get_win_subsystem_args` in `MSVCDynamicLinker`, `ClangClDynamicLinker`, `XilinkDynamicLinker`)：** 在 Windows 上，链接器需要指定可执行文件的子系统（例如 `WINDOWS`, `CONSOLE`）。`MSVCDynamicLinker` 等类的 `get_win_subsystem_args` 方法生成 `/SUBSYSTEM:` 参数来实现这一点。

**逻辑推理的假设输入与输出：**

* **假设输入 (`NAGDynamicLinker.build_rpath_args`):**
    * `rpath_paths`: `('.', 'lib')`
    * `build_dir`: `/path/to/build`
    * `from_dir`: `/path/to/source`
    * `build_rpath`: ''
    * `install_rpath`: '/usr/local/lib'

* **预期输出:**
    * `(['-Wl,-Wl,,-rpath,,"$ORIGIN"', '-Wl,-Wl,,-rpath,,"$ORIGIN/lib"'], set())`

* **解释:**  `prepare_rpaths` 函数会将相对路径转换为相对于 `build_dir` 的路径。然后，`NAGDynamicLinker` 会为每个路径添加 `"$ORIGIN"` 前缀，并使用 `-Wl,-Wl,,-rpath,` 将其传递给底层的 `ld`。

**涉及用户或编程常见的使用错误及举例：**

* **未设置正确的库搜索路径：** 用户可能忘记设置或错误配置库搜索路径，导致链接器找不到所需的库文件。例如，如果用户没有为使用了第三方库的项目设置正确的 `-L` 路径（对应于 `get_search_args` 方法），链接过程会失败。
* **链接器类型选择错误：** 用户可能在构建配置中选择了错误的链接器，导致链接参数不兼容。例如，如果用户在 Windows 上尝试使用 GCC 的链接器来链接 MSVC 编译的对象文件，就会出现链接错误。
* **共享库版本命名不当：**  在创建共享库时，用户可能没有正确设置 SONAME，导致运行时库加载失败。例如，如果用户没有在 Linux 上使用 `-Wl,-soname` 选项（对应于 `get_soname_args` 方法）来指定共享库的 SONAME，可能会导致其他程序无法正确加载该库。
* **忘记链接所需的库：** 用户可能在链接命令中遗漏了某些必要的库文件，导致出现未定义的符号错误。这与 `get_allow_undefined_args` 和 `no_undefined_args` 方法控制的行为有关。如果链接器配置为不允许未定义的符号，则会报错。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **配置构建系统 (Meson):** 用户使用 Meson 定义项目的构建配置，包括指定使用的编译器、链接器选项、依赖库等。
2. **执行 Meson 配置:**  用户运行 `meson setup builddir` 命令，Meson 会根据构建定义和系统环境，生成用于实际构建的文件（例如 Ninja 构建文件）。
3. **执行构建命令 (Ninja):** 用户运行 `ninja` 或 `ninja -C builddir` 命令，Ninja 会读取 Meson 生成的构建文件，并执行编译和链接等构建步骤。
4. **链接步骤:** 在链接步骤中，Meson 会根据配置选择合适的链接器类（例如 `MSVCDynamicLinker` 或 `GnuLikeDynamicLinker`）。
5. **调用链接器类的方法:**  Meson 会调用所选链接器类的方法，例如 `get_output_args`、`get_search_args`、`get_std_shared_lib_args` 等，来生成特定于该链接器的命令行参数。
6. **执行链接器:**  Meson 使用生成的命令行参数调用实际的链接器程序（例如 `link.exe` 或 `ld`）。
7. **调试线索:** 如果链接过程中出现错误，例如链接器找不到库文件，或者出现未定义的符号，开发者可以检查 Meson 生成的链接命令，以及 `linkers.py` 文件中对应链接器类的实现，来了解参数是如何生成的，从而找到问题所在。例如，可以检查 `get_search_args` 方法是否正确包含了库文件的路径，或者 `get_lib_prefix` 方法是否与库文件的命名约定一致。

总而言之，这部分 `linkers.py` 代码的核心功能是为 Frida 构建系统提供一个抽象层，使其能够支持多种不同的动态链接器，并能够根据不同的链接器生成正确的命令行参数，从而实现跨平台和跨编译器的构建。

### 提示词
```
这是目录为frida/subprojects/frida-gum/releng/meson/mesonbuild/linkers/linkers.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```python
hineChoice,
                 *, version: str = 'unknown version'):
        super().__init__(['rlink.exe'], for_machine, '', [],
                         version=version)

    def get_accepts_rsp(self) -> bool:
        return False

    def get_lib_prefix(self) -> str:
        return '-lib='

    def get_std_shared_lib_args(self) -> T.List[str]:
        return []

    def get_output_args(self, outputname: str) -> T.List[str]:
        return [f'-output={outputname}']

    def get_search_args(self, dirname: str) -> 'T.NoReturn':
        raise OSError('rlink.exe does not have a search dir argument')

    def get_allow_undefined_args(self) -> T.List[str]:
        return []

    def get_soname_args(self, env: 'Environment', prefix: str, shlib_name: str,
                        suffix: str, soversion: str, darwin_versions: T.Tuple[str, str]) -> T.List[str]:
        return []


class Xc16DynamicLinker(DynamicLinker):

    """Linker for Microchip XC16 compiler."""

    id = 'xc16-gcc'

    def __init__(self, for_machine: mesonlib.MachineChoice,
                 *, version: str = 'unknown version'):
        super().__init__(['xc16-gcc'], for_machine, '', [],
                         version=version)

    def get_link_whole_for(self, args: T.List[str]) -> T.List[str]:
        if len(args) < 2:
            return args
        return self._apply_prefix('--start-group') + args + self._apply_prefix('--end-group')

    def get_accepts_rsp(self) -> bool:
        return False

    def get_lib_prefix(self) -> str:
        return ''

    def get_std_shared_lib_args(self) -> T.List[str]:
        return []

    def get_output_args(self, outputname: str) -> T.List[str]:
        return [f'-o{outputname}']

    def get_search_args(self, dirname: str) -> 'T.NoReturn':
        raise OSError('xc16-gcc does not have a search dir argument')

    def get_allow_undefined_args(self) -> T.List[str]:
        return []

    def get_soname_args(self, env: 'Environment', prefix: str, shlib_name: str,
                        suffix: str, soversion: str, darwin_versions: T.Tuple[str, str]) -> T.List[str]:
        return []

    def build_rpath_args(self, env: 'Environment', build_dir: str, from_dir: str,
                         rpath_paths: T.Tuple[str, ...], build_rpath: str,
                         install_rpath: str) -> T.Tuple[T.List[str], T.Set[bytes]]:
        return ([], set())

class CompCertDynamicLinker(DynamicLinker):

    """Linker for CompCert C compiler."""

    id = 'ccomp'

    def __init__(self, for_machine: mesonlib.MachineChoice,
                 *, version: str = 'unknown version'):
        super().__init__(['ccomp'], for_machine, '', [],
                         version=version)

    def get_link_whole_for(self, args: T.List[str]) -> T.List[str]:
        if not args:
            return args
        return self._apply_prefix('-Wl,--whole-archive') + args + self._apply_prefix('-Wl,--no-whole-archive')

    def get_accepts_rsp(self) -> bool:
        return False

    def get_lib_prefix(self) -> str:
        return ''

    def get_std_shared_lib_args(self) -> T.List[str]:
        return []

    def get_output_args(self, outputname: str) -> T.List[str]:
        return [f'-o{outputname}']

    def get_search_args(self, dirname: str) -> T.List[str]:
        return [f'-L{dirname}']

    def get_allow_undefined_args(self) -> T.List[str]:
        return []

    def get_soname_args(self, env: 'Environment', prefix: str, shlib_name: str,
                        suffix: str, soversion: str, darwin_versions: T.Tuple[str, str]) -> T.List[str]:
        raise MesonException(f'{self.id} does not support shared libraries.')

    def build_rpath_args(self, env: 'Environment', build_dir: str, from_dir: str,
                         rpath_paths: T.Tuple[str, ...], build_rpath: str,
                         install_rpath: str) -> T.Tuple[T.List[str], T.Set[bytes]]:
        return ([], set())

class TIDynamicLinker(DynamicLinker):

    """Linker for Texas Instruments compiler family."""

    id = 'ti'

    def __init__(self, exelist: T.List[str], for_machine: mesonlib.MachineChoice,
                 *, version: str = 'unknown version'):
        super().__init__(exelist, for_machine, '', [],
                         version=version)

    def get_link_whole_for(self, args: T.List[str]) -> T.List[str]:
        if len(args) < 2:
            return args
        return self._apply_prefix('--start-group') + args + self._apply_prefix('--end-group')

    def get_accepts_rsp(self) -> bool:
        return False

    def get_lib_prefix(self) -> str:
        return '-l='

    def get_std_shared_lib_args(self) -> T.List[str]:
        return []

    def get_output_args(self, outputname: str) -> T.List[str]:
        return ['-z', f'--output_file={outputname}']

    def get_search_args(self, dirname: str) -> 'T.NoReturn':
        raise OSError('TI compilers do not have a search dir argument')

    def get_allow_undefined_args(self) -> T.List[str]:
        return []

    def get_always_args(self) -> T.List[str]:
        return []


class C2000DynamicLinker(TIDynamicLinker):
    # Required for backwards compat with projects created before ti-cgt support existed
    id = 'cl2000'

class C6000DynamicLinker(TIDynamicLinker):
    id = 'cl6000'


class ArmDynamicLinker(PosixDynamicLinkerMixin, DynamicLinker):

    """Linker for the ARM compiler."""

    id = 'armlink'

    def __init__(self, for_machine: mesonlib.MachineChoice,
                 *, version: str = 'unknown version'):
        super().__init__(['armlink'], for_machine, '', [],
                         version=version)

    def get_accepts_rsp(self) -> bool:
        return False

    def get_std_shared_lib_args(self) -> 'T.NoReturn':
        raise MesonException('The Arm Linkers do not support shared libraries')

    def get_allow_undefined_args(self) -> T.List[str]:
        return []


class ArmClangDynamicLinker(ArmDynamicLinker):

    """Linker used with ARM's clang fork.

    The interface is similar enough to the old ARM ld that it inherits and
    extends a few things as needed.
    """

    def export_dynamic_args(self, env: 'Environment') -> T.List[str]:
        return ['--export_dynamic']

    def import_library_args(self, implibname: str) -> T.List[str]:
        return ['--symdefs=' + implibname]

class QualcommLLVMDynamicLinker(LLVMDynamicLinker):

    """ARM Linker from Snapdragon LLVM ARM Compiler."""

    id = 'ld.qcld'


class NAGDynamicLinker(PosixDynamicLinkerMixin, DynamicLinker):

    """NAG Fortran linker, ld via gcc indirection.

    Using nagfor -Wl,foo passes option foo to a backend gcc invocation.
    (This linking gathers the correct objects needed from the nagfor runtime
    system.)
    To pass gcc -Wl,foo options (i.e., to ld) one must apply indirection
    again: nagfor -Wl,-Wl,,foo
    """

    id = 'nag'

    def build_rpath_args(self, env: 'Environment', build_dir: str, from_dir: str,
                         rpath_paths: T.Tuple[str, ...], build_rpath: str,
                         install_rpath: str) -> T.Tuple[T.List[str], T.Set[bytes]]:
        if not rpath_paths and not install_rpath and not build_rpath:
            return ([], set())
        args: T.List[str] = []
        origin_placeholder = '$ORIGIN'
        processed_rpaths = prepare_rpaths(rpath_paths, build_dir, from_dir)
        all_paths = mesonlib.OrderedSet([os.path.join(origin_placeholder, p) for p in processed_rpaths])
        if build_rpath != '':
            all_paths.add(build_rpath)
        for rp in all_paths:
            args.extend(self._apply_prefix('-Wl,-Wl,,-rpath,,' + rp))

        return (args, set())

    def get_allow_undefined_args(self) -> T.List[str]:
        return []

    def get_std_shared_lib_args(self) -> T.List[str]:
        from ..compilers.fortran import NAGFortranCompiler
        return NAGFortranCompiler.get_nagfor_quiet(self.version) + ['-Wl,-shared']


class PGIDynamicLinker(PosixDynamicLinkerMixin, DynamicLinker):

    """PGI linker."""

    id = 'pgi'

    def get_allow_undefined_args(self) -> T.List[str]:
        return []

    def get_soname_args(self, env: 'Environment', prefix: str, shlib_name: str,
                        suffix: str, soversion: str, darwin_versions: T.Tuple[str, str]) -> T.List[str]:
        return []

    def get_std_shared_lib_args(self) -> T.List[str]:
        # PGI -shared is Linux only.
        if mesonlib.is_windows():
            return ['-Bdynamic', '-Mmakedll']
        elif mesonlib.is_linux():
            return ['-shared']
        return []

    def build_rpath_args(self, env: 'Environment', build_dir: str, from_dir: str,
                         rpath_paths: T.Tuple[str, ...], build_rpath: str,
                         install_rpath: str) -> T.Tuple[T.List[str], T.Set[bytes]]:
        if not env.machines[self.for_machine].is_windows():
            return (['-R' + os.path.join(build_dir, p) for p in rpath_paths], set())
        return ([], set())

NvidiaHPC_DynamicLinker = PGIDynamicLinker


class PGIStaticLinker(StaticLinker):
    def __init__(self, exelist: T.List[str]):
        super().__init__(exelist)
        self.id = 'ar'
        self.std_args = ['-r']

    def get_std_link_args(self, env: 'Environment', is_thin: bool) -> T.List[str]:
        return self.std_args

    def get_output_args(self, target: str) -> T.List[str]:
        return [target]

NvidiaHPC_StaticLinker = PGIStaticLinker


class VisualStudioLikeLinkerMixin(DynamicLinkerBase):

    """Mixin class for dynamic linkers that act like Microsoft's link.exe."""

    if T.TYPE_CHECKING:
        for_machine = MachineChoice.HOST
        def _apply_prefix(self, arg: T.Union[str, T.List[str]]) -> T.List[str]: ...

    _OPTIMIZATION_ARGS: T.Dict[str, T.List[str]] = {
        'plain': [],
        '0': [],
        'g': [],
        '1': [],
        '2': [],
        # The otherwise implicit REF and ICF linker optimisations are disabled by
        # /DEBUG. REF implies ICF.
        '3': ['/OPT:REF'],
        's': ['/INCREMENTAL:NO', '/OPT:REF'],
    }

    def __init__(self, exelist: T.List[str], for_machine: mesonlib.MachineChoice,
                 prefix_arg: T.Union[str, T.List[str]], always_args: T.List[str], *,
                 version: str = 'unknown version', direct: bool = True, machine: str = 'x86'):
        # There's no way I can find to make mypy understand what's going on here
        super().__init__(exelist, for_machine, prefix_arg, always_args, version=version)
        self.machine = machine
        self.direct = direct

    def invoked_by_compiler(self) -> bool:
        return not self.direct

    def get_output_args(self, outputname: str) -> T.List[str]:
        return self._apply_prefix(['/MACHINE:' + self.machine, '/OUT:' + outputname])

    def get_always_args(self) -> T.List[str]:
        parent = super().get_always_args()
        return self._apply_prefix('/nologo') + parent

    def get_search_args(self, dirname: str) -> T.List[str]:
        return self._apply_prefix('/LIBPATH:' + dirname)

    def get_std_shared_lib_args(self) -> T.List[str]:
        return self._apply_prefix('/DLL')

    def get_debugfile_name(self, targetfile: str) -> str:
        return targetfile

    def get_debugfile_args(self, targetfile: str) -> T.List[str]:
        return self._apply_prefix(['/DEBUG', '/PDB:' + self.get_debugfile_name(targetfile)])

    def get_link_whole_for(self, args: T.List[str]) -> T.List[str]:
        # Only since VS2015
        args = mesonlib.listify(args)
        l: T.List[str] = []
        for a in args:
            l.extend(self._apply_prefix('/WHOLEARCHIVE:' + a))
        return l

    def get_allow_undefined_args(self) -> T.List[str]:
        return []

    def get_soname_args(self, env: 'Environment', prefix: str, shlib_name: str,
                        suffix: str, soversion: str, darwin_versions: T.Tuple[str, str]) -> T.List[str]:
        return []

    def import_library_args(self, implibname: str) -> T.List[str]:
        """The command to generate the import library."""
        return self._apply_prefix(['/IMPLIB:' + implibname])

    def rsp_file_syntax(self) -> RSPFileSyntax:
        return RSPFileSyntax.MSVC


class MSVCDynamicLinker(VisualStudioLikeLinkerMixin, DynamicLinker):

    """Microsoft's Link.exe."""

    id = 'link'

    def __init__(self, for_machine: mesonlib.MachineChoice, always_args: T.List[str], *,
                 exelist: T.Optional[T.List[str]] = None,
                 prefix: T.Union[str, T.List[str]] = '',
                 machine: str = 'x86', version: str = 'unknown version',
                 direct: bool = True):
        super().__init__(exelist or ['link.exe'], for_machine,
                         prefix, always_args, machine=machine, version=version, direct=direct)

    def get_always_args(self) -> T.List[str]:
        return self._apply_prefix(['/release']) + super().get_always_args()

    def get_win_subsystem_args(self, value: str) -> T.List[str]:
        return self._apply_prefix([f'/SUBSYSTEM:{value.upper()}'])


class ClangClDynamicLinker(VisualStudioLikeLinkerMixin, DynamicLinker):

    """Clang's lld-link.exe."""

    id = 'lld-link'

    def __init__(self, for_machine: mesonlib.MachineChoice, always_args: T.List[str], *,
                 exelist: T.Optional[T.List[str]] = None,
                 prefix: T.Union[str, T.List[str]] = '',
                 machine: str = 'x86', version: str = 'unknown version',
                 direct: bool = True):
        super().__init__(exelist or ['lld-link.exe'], for_machine,
                         prefix, always_args, machine=machine, version=version, direct=direct)

    def get_output_args(self, outputname: str) -> T.List[str]:
        # If we're being driven indirectly by clang just skip /MACHINE
        # as clang's target triple will handle the machine selection
        if self.machine is None:
            return self._apply_prefix([f"/OUT:{outputname}"])

        return super().get_output_args(outputname)

    def get_win_subsystem_args(self, value: str) -> T.List[str]:
        return self._apply_prefix([f'/SUBSYSTEM:{value.upper()}'])

    def get_thinlto_cache_args(self, path: str) -> T.List[str]:
        return ["/lldltocache:" + path]


class XilinkDynamicLinker(VisualStudioLikeLinkerMixin, DynamicLinker):

    """Intel's Xilink.exe."""

    id = 'xilink'

    def __init__(self, for_machine: mesonlib.MachineChoice, always_args: T.List[str], *,
                 exelist: T.Optional[T.List[str]] = None,
                 prefix: T.Union[str, T.List[str]] = '',
                 machine: str = 'x86', version: str = 'unknown version',
                 direct: bool = True):
        super().__init__(['xilink.exe'], for_machine, '', always_args, version=version)

    def get_win_subsystem_args(self, value: str) -> T.List[str]:
        return self._apply_prefix([f'/SUBSYSTEM:{value.upper()}'])


class SolarisDynamicLinker(PosixDynamicLinkerMixin, DynamicLinker):

    """Sys-V derived linker used on Solaris and OpenSolaris."""

    id = 'ld.solaris'

    def get_link_whole_for(self, args: T.List[str]) -> T.List[str]:
        if not args:
            return args
        return self._apply_prefix('--whole-archive') + args + self._apply_prefix('--no-whole-archive')

    def get_pie_args(self) -> T.List[str]:
        # Available in Solaris 11.2 and later
        pc, stdo, stde = mesonlib.Popen_safe(self.exelist + self._apply_prefix('-zhelp'))
        for line in (stdo + stde).split('\n'):
            if '-z type' in line:
                if 'pie' in line:
                    return ['-z', 'type=pie']
                break
        return []

    def get_asneeded_args(self) -> T.List[str]:
        return self._apply_prefix(['-z', 'ignore'])

    def no_undefined_args(self) -> T.List[str]:
        return ['-z', 'defs']

    def get_allow_undefined_args(self) -> T.List[str]:
        return ['-z', 'nodefs']

    def fatal_warnings(self) -> T.List[str]:
        return ['-z', 'fatal-warnings']

    def build_rpath_args(self, env: 'Environment', build_dir: str, from_dir: str,
                         rpath_paths: T.Tuple[str, ...], build_rpath: str,
                         install_rpath: str) -> T.Tuple[T.List[str], T.Set[bytes]]:
        if not rpath_paths and not install_rpath and not build_rpath:
            return ([], set())
        processed_rpaths = prepare_rpaths(rpath_paths, build_dir, from_dir)
        all_paths = mesonlib.OrderedSet([os.path.join('$ORIGIN', p) for p in processed_rpaths])
        rpath_dirs_to_remove: T.Set[bytes] = set()
        for p in all_paths:
            rpath_dirs_to_remove.add(p.encode('utf8'))
        if build_rpath != '':
            all_paths.add(build_rpath)
            for p in build_rpath.split(':'):
                rpath_dirs_to_remove.add(p.encode('utf8'))

        # In order to avoid relinking for RPATH removal, the binary needs to contain just
        # enough space in the ELF header to hold the final installation RPATH.
        paths = ':'.join(all_paths)
        if len(paths) < len(install_rpath):
            padding = 'X' * (len(install_rpath) - len(paths))
            if not paths:
                paths = padding
            else:
                paths = paths + ':' + padding
        return (self._apply_prefix(f'-rpath,{paths}'), rpath_dirs_to_remove)

    def get_soname_args(self, env: 'Environment', prefix: str, shlib_name: str,
                        suffix: str, soversion: str, darwin_versions: T.Tuple[str, str]) -> T.List[str]:
        sostr = '' if soversion is None else '.' + soversion
        return self._apply_prefix(f'-soname,{prefix}{shlib_name}.{suffix}{sostr}')


class AIXDynamicLinker(PosixDynamicLinkerMixin, DynamicLinker):

    """Sys-V derived linker used on AIX"""

    id = 'ld.aix'

    def get_always_args(self) -> T.List[str]:
        return self._apply_prefix(['-bnoipath', '-bbigtoc']) + super().get_always_args()

    def no_undefined_args(self) -> T.List[str]:
        return self._apply_prefix(['-bernotok'])

    def get_allow_undefined_args(self) -> T.List[str]:
        return self._apply_prefix(['-berok'])

    def get_archive_name(self, filename: str) -> str:
        # In AIX we allow the shared library name to have the lt_version and so_version.
        # But the archive name must just be .a .
        # For Example shared object can have the name libgio.so.0.7200.1 but the archive
        # must have the name libgio.a having libgio.a (libgio.so.0.7200.1) in the
        # archive. This regular expression is to do the same.
        filename = re.sub('[.][a]([.]?([0-9]+))*([.]?([a-z]+))*', '.a', filename.replace('.so', '.a'))
        return filename

    def get_command_to_archive_shlib(self) -> T.List[str]:
        # Archive shared library object and remove the shared library object,
        # since it already exists in the archive.
        command = ['ar', '-q', '-v', '$out', '$in', '&&', 'rm', '-f', '$in']
        return command

    def get_link_whole_for(self, args: T.List[str]) -> T.List[str]:
        # AIX's linker always links the whole archive: "The ld command
        # processes all input files in the same manner, whether they are
        # archives or not."
        return args

    def build_rpath_args(self, env: 'Environment', build_dir: str, from_dir: str,
                         rpath_paths: T.Tuple[str, ...], build_rpath: str,
                         install_rpath: str) -> T.Tuple[T.List[str], T.Set[bytes]]:
        all_paths: mesonlib.OrderedSet[str] = mesonlib.OrderedSet()
        # install_rpath first, followed by other paths, and the system path last
        if install_rpath != '':
            all_paths.add(install_rpath)
        if build_rpath != '':
            all_paths.add(build_rpath)
        for p in rpath_paths:
            all_paths.add(os.path.join(build_dir, p))
        # We should consider allowing the $LIBPATH environment variable
        # to override sys_path.
        sys_path = env.get_compiler_system_lib_dirs(self.for_machine)
        if len(sys_path) == 0:
            # get_compiler_system_lib_dirs doesn't support our compiler.
            # Use the default system library path
            all_paths.update(['/usr/lib', '/lib'])
        else:
            # Include the compiler's default library paths, but filter out paths that don't exist
            for p in sys_path:
                if os.path.isdir(p):
                    all_paths.add(p)
        return (self._apply_prefix('-blibpath:' + ':'.join(all_paths)), set())

    def thread_flags(self, env: 'Environment') -> T.List[str]:
        return ['-pthread']


class OptlinkDynamicLinker(VisualStudioLikeLinkerMixin, DynamicLinker):

    """Digital Mars dynamic linker for windows."""

    id = 'optlink'

    def __init__(self, exelist: T.List[str], for_machine: mesonlib.MachineChoice,
                 *, version: str = 'unknown version'):
        # Use optlink instead of link so we don't interfere with other link.exe
        # implementations.
        super().__init__(exelist, for_machine, '', [], version=version)

    def get_allow_undefined_args(self) -> T.List[str]:
        return []

    def get_debugfile_args(self, targetfile: str) -> T.List[str]:
        # Optlink does not generate pdb files.
        return []

    def get_always_args(self) -> T.List[str]:
        return []


class CudaLinker(PosixDynamicLinkerMixin, DynamicLinker):
    """Cuda linker (nvlink)"""

    id = 'nvlink'

    @staticmethod
    def parse_version() -> str:
        version_cmd = ['nvlink', '--version']
        try:
            _, out, _ = mesonlib.Popen_safe(version_cmd)
        except OSError:
            return 'unknown version'
        # Output example:
        # nvlink: NVIDIA (R) Cuda linker
        # Copyright (c) 2005-2018 NVIDIA Corporation
        # Built on Sun_Sep_30_21:09:22_CDT_2018
        # Cuda compilation tools, release 10.0, V10.0.166
        # we need the most verbose version output. Luckily starting with V
        return out.strip().rsplit('V', maxsplit=1)[-1]

    def get_accepts_rsp(self) -> bool:
        # nvcc does not support response files
        return False

    def get_lib_prefix(self) -> str:
        # nvcc doesn't recognize Meson's default .a extension for static libraries on
        # Windows and passes it to cl as an object file, resulting in 'warning D9024 :
        # unrecognized source file type 'xxx.a', object file assumed'.
        #
        # nvcc's --library= option doesn't help: it takes the library name without the
        # extension and assumes that the extension on Windows is .lib; prefixing the
        # library with -Xlinker= seems to work.
        #
        # On Linux, we have to use rely on -Xlinker= too, since nvcc/nvlink chokes on
        # versioned shared libraries:
        #
        #   nvcc fatal : Don't know what to do with 'subprojects/foo/libbar.so.0.1.2'
        #
        from ..compilers.cuda import CudaCompiler
        return CudaCompiler.LINKER_PREFIX

    def fatal_warnings(self) -> T.List[str]:
        return ['--warning-as-error']

    def get_allow_undefined_args(self) -> T.List[str]:
        return []

    def get_soname_args(self, env: 'Environment', prefix: str, shlib_name: str,
                        suffix: str, soversion: str, darwin_versions: T.Tuple[str, str]) -> T.List[str]:
        return []


class MetrowerksLinker(DynamicLinker):

    def __init__(self, exelist: T.List[str], for_machine: mesonlib.MachineChoice,
                 *, version: str = 'unknown version'):
        super().__init__(exelist, for_machine, '', [],
                         version=version)

    def fatal_warnings(self) -> T.List[str]:
        return ['-w', 'error']

    def get_allow_undefined_args(self) -> T.List[str]:
        return []

    def get_accepts_rsp(self) -> bool:
        return True

    def get_lib_prefix(self) -> str:
        return ""

    def get_linker_always_args(self) -> T.List[str]:
        return []

    def get_output_args(self, outputname: str) -> T.List[str]:
        return ['-o', outputname]

    def get_search_args(self, dirname: str) -> T.List[str]:
        return self._apply_prefix('-L' + dirname)

    def invoked_by_compiler(self) -> bool:
        return False

    def rsp_file_syntax(self) -> RSPFileSyntax:
        return RSPFileSyntax.GCC


class MetrowerksLinkerARM(MetrowerksLinker):
    id = 'mwldarm'


class MetrowerksLinkerEmbeddedPowerPC(MetrowerksLinker):
    id = 'mwldeppc'
```