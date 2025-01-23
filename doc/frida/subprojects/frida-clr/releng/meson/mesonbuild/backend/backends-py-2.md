Response:
The user wants a summary of the functionality of the provided Python code snippet. I need to analyze the methods and their interactions to understand the overall purpose of this file within the Frida project.

Based on the method names and the context ("fridaDynamic instrumentation tool" and "mesonbuild"), it appears this file is part of the build system logic for Frida, specifically dealing with how different types of build targets are handled during the build process.

Here's a breakdown of the key functionalities:

1. **Dependency Management**:  Functions like `get_all_dependencies`, `get_custom_target_provided_by_generated_source`, and `get_custom_target_provided_libraries` are involved in understanding the relationships between different build targets.

2. **Source Handling**:  `get_custom_target_sources` retrieves the source files for custom build targets, handling various source types (strings, files, other targets).

3. **Output Path Determination**: Functions like `get_custom_target_output_dir`, `get_target_dir`, and `get_target_filename` determine where output files are generated.

4. **Command Evaluation**: `eval_custom_target_command` constructs the actual command-line command to execute for custom targets, including variable substitution.

5. **Installation Logic**: A significant portion of the code (functions starting with `generate_`) is dedicated to generating installation metadata, covering targets, headers, man pages, data files, symlinks, and subdirectories. This involves determining installation locations and permissions.

6. **Introspection**: `get_introspection_data` aims to provide structured information about build targets, like source files and compiler commands.

7. **Developer Environment Setup**: `get_devenv` configures environment variables (like PATH and LD_LIBRARY_PATH) to facilitate development and testing.

8. **Utilities**: Helper functions like `get_normpath_target` provide basic path manipulation.

Regarding the user's specific requests:

* **Relationship to Reverse Engineering**: This code is part of the *build system* of Frida. While not directly involved in *performing* reverse engineering, it ensures the correct building and packaging of Frida, which is a tool used for reverse engineering.

* **Binary/Kernel/Framework Knowledge**:  The code deals with concepts like shared libraries, executables, and installation paths (bindir, libdir), which are fundamental to operating systems, including Linux and Android. The installation process places built artifacts in the correct locations for the target system.

* **Logical Reasoning**:  The `eval_custom_target_command` function performs logical reasoning by substituting placeholders in commands based on the types of inputs and outputs. The installation functions make decisions about where to place files based on their type and target settings.

* **User Errors**: Incorrectly defining dependencies or output paths in the build configuration (e.g., in a `meson.build` file) could lead to errors handled by assertions or exceptions within this code. For example, providing an incorrect number of `install_dir` values for a target.

* **User Operations to Reach Here**: A developer working on Frida would typically modify the `meson.build` files that describe how different parts of Frida are built. When the `meson` command is run to configure the build, it parses these files and uses the logic in `backends.py` to understand how to generate the necessary build instructions. If there are errors in the `meson.build` files, the execution might stop within this code, providing debugging clues.
这个 `backends.py` 文件是 Frida 构建系统 (使用 Meson) 的一部分，它负责 **处理和管理不同类型的构建目标 (targets) 并生成构建系统所需的后端信息**。  可以将其视为一个翻译器，将 Meson 的抽象构建定义转换为特定后端（例如 Ninja, Xcode, Visual Studio）能够理解的指令。

**它的主要功能可以归纳为：**

1. **目标依赖关系解析和管理:**
   - `get_all_dependencies`:  遍历构建目标，找到所有依赖项，并以字典形式返回。这对于理解构建顺序至关重要。
   - `get_custom_target_provided_by_generated_source`:  确定由生成源文件提供的自定义目标。
   - `get_custom_target_provided_libraries`: 获取自定义目标提供的库文件。

2. **目标源文件处理:**
   - `get_custom_target_sources`:  获取自定义目标的源文件列表，并处理不同类型的源文件（字符串路径、`File` 对象、其他构建目标或自定义目标）。它会将这些源文件路径转换为相对于构建根目录的路径。

3. **目标输出目录和文件路径管理:**
   - `get_custom_target_output_dir`: 获取自定义目标的输出目录。
   - `get_target_dir`: 获取目标文件的目录。
   - `get_target_filename`: 获取目标文件的完整路径名。
   - `get_target_depend_files`: 获取目标依赖的文件的路径。

4. **自定义目标命令评估和生成:**
   - `eval_custom_target_command`:  这是核心功能之一。它解析自定义目标的命令列表，并进行变量替换，生成最终要执行的命令。它处理各种类型的命令参数，包括其他构建目标、文件对象、字符串等。

5. **安装信息生成:**
   - `create_install_data`:  创建包含所有安装信息的数据对象 `InstallData`。
   - `generate_target_install`: 生成目标文件的安装信息。
   - `generate_header_install`: 生成头文件的安装信息。
   - `generate_man_install`: 生成 man 手册的安装信息。
   - `generate_emptydir_install`: 生成空目录的安装信息。
   - `generate_data_install`: 生成数据文件的安装信息。
   - `generate_symlink_install`: 生成符号链接的安装信息。
   - `generate_custom_install_script`: 生成自定义安装脚本的信息。
   - `generate_subdir_install`: 生成子目录安装的信息。
   - `guess_install_tag`: 尝试猜测安装标签。

6. **构建自省 (Introspection) 数据生成:**
   - `get_introspection_data`:  为构建目标生成自省数据，包括语言、编译器、参数和源文件等信息。这用于提供构建过程的元数据。

7. **开发环境配置:**
   - `get_devenv`:  生成开发环境所需的配置，例如设置 `PATH` 和 `LD_LIBRARY_PATH` 环境变量，以便在开发过程中能正确找到和使用构建的二进制文件和库。

8. **后配置脚本执行:**
   - `run_postconf_scripts`: 运行配置后的脚本。

9. **工具函数:**
   - `get_normpath_target`:  规范化路径。
   - `get_custom_target_dirs`: 获取自定义目标的包含目录。
   - `get_custom_target_dir_include_args`: 获取自定义目标的包含目录的编译器参数。
   - `get_introspect_command`: 获取自省命令。
   - `get_run_target_env`: 获取运行目标的环境变量。
   - `create_install_data_files`: 创建安装数据文件。
   - `compiler_to_generator`: 将编译器转换为生成器（用于某些后端不支持自定义编译器的情况）。

**与逆向方法的关系及举例:**

虽然这个文件本身不直接执行逆向操作，但它是 Frida 构建系统的一部分，而 Frida 是一个动态插桩工具，广泛用于逆向工程。这个文件确保 Frida 能够正确地被构建和打包，从而为逆向工程师提供工具。

**举例:**

- 当 Frida 的开发者定义了一个新的自定义构建目标，用于生成 Frida Agent 的一部分时，`eval_custom_target_command` 函数会负责解析该目标的命令，例如可能包含编译代码、打包资源等操作。
- 安装部分的功能确保 Frida 的核心库 (`.so` 或 `.dll`) 被安装到正确的系统目录下，这样逆向工程师才能在目标进程中加载 Frida Agent。
- 自省数据可以帮助开发者了解 Frida 构建的结构和依赖关系，这对于调试和维护 Frida 本身很有用。

**涉及二进制底层、Linux、Android 内核及框架的知识的举例:**

- **二进制底层:**  `get_target_filename_for_linking` 涉及到链接库的命名约定，例如在 Windows 上区分 `.lib` 和 `.dll` 文件。安装功能需要了解不同平台下可执行文件和库文件的存放位置。
- **Linux:**  `get_devenv` 中设置 `LD_LIBRARY_PATH` 环境变量是 Linux 系统中加载动态链接库的常见方式。
- **Android:** 虽然代码没有直接提及 Android 特有的 API，但 Frida 可以运行在 Android 上，因此这个文件生成的构建结果最终会影响 Frida 在 Android 系统上的运行。例如，安装路径需要符合 Android 的文件系统结构。
- **框架:** Frida 的构建可能涉及到一些框架的依赖，例如用于处理特定的通信协议或数据格式。这个文件会处理这些依赖项的构建和链接。

**逻辑推理的假设输入与输出举例:**

假设有一个自定义目标 `my_agent_builder`，它的 `command` 定义如下：

```python
command = [
    '/path/to/my_builder',
    '--input', '@INPUT@',
    '--output', '@OUTPUT@'
]
```

并且它的 `sources` 是 `agent.c`，`outputs` 是 `my_agent.so`。

**假设输入 (在 `eval_custom_target_command` 函数中):**

- `target.command`: `['/path/to/my_builder', '--input', '@INPUT@', '--output', '@OUTPUT@']`
- `target.get_sources()`: `['agent.c']`
- `target.get_outputs()`: `['my_agent.so']`
- `target.get_source_subdir()`: `'src/agent'`

**预期输出 (部分):**

- `inputs`: `['src/agent/agent.c']` (假设 `absolute_paths` 为 False)
- `outputs`: `['<build_dir>/src/agent/my_agent.so']` (假设默认输出目录)
- `cmd`: `['/path/to/my_builder', '--input', 'src/agent/agent.c', '--output', '<build_dir>/src/agent/my_agent.so']`

**涉及用户或编程常见的使用错误的举例:**

- **安装路径错误:** 用户在 `meson.build` 中指定了错误的安装路径，例如将一个可执行文件安装到了库目录下。这个文件中的安装逻辑可能会尝试将文件复制到该路径，但最终可能导致系统错误或者程序无法正常运行。
- **自定义目标命令错误:**  用户在自定义目标的 `command` 中使用了错误的命令或参数，导致 `eval_custom_target_command` 生成的命令无法执行成功。例如，拼写错误的工具名称或缺少必要的输入文件。
- **依赖声明错误:** 用户在 `meson.build` 中没有正确声明目标之间的依赖关系，导致 `get_all_dependencies` 无法正确解析，最终可能导致构建顺序错误。

**用户操作如何一步步到达这里作为调试线索:**

1. **用户修改了 `meson.build` 文件:** 用户可能添加、修改或删除了构建目标、依赖项、安装规则等。
2. **用户运行 `meson` 命令:**  用户执行 `meson <build_directory>` 命令来配置构建。
3. **Meson 解析 `meson.build` 文件:** Meson 读取并解析用户的构建定义。
4. **调用 `backends.py` 中的代码:** Meson 会根据构建定义调用 `backends.py` 中的相关函数，例如创建 `InstallData` 对象，评估自定义目标命令等。
5. **出现错误:** 如果用户的 `meson.build` 文件存在错误，或者构建过程中遇到了问题，例如找不到依赖项、命令执行失败等，错误信息可能会指向 `backends.py` 中的特定行，帮助开发者定位问题所在。例如，如果 `eval_custom_target_command` 在解析命令时遇到未知类型的参数，就会抛出 `RuntimeError`。

**归纳其功能 (第3部分):**

这个 `backends.py` 文件的这部分主要负责 **详细处理构建目标的属性和命令，并生成用于安装和自省的数据**。它深入到每个构建目标的细节，例如源文件、输出文件、依赖关系、执行命令和安装位置，并将这些信息转换为后端构建系统可以理解的形式。  特别是，`eval_custom_target_command` 是一个关键功能，它负责将用户定义的抽象命令转换为实际的命令行操作。此外，它还开始构建安装所需的数据结构，为后续的安装过程做准备。

### 提示词
```
这是目录为frida/subprojects/frida-clr/releng/meson/mesonbuild/backend/backends.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共4部分，请归纳一下它的功能
```

### 源代码
```python
= arg
            for dep in t.depends:
                assert isinstance(dep, (build.CustomTarget, build.BuildTarget))
                result[dep.get_id()] = dep
        return result

    @lru_cache(maxsize=None)
    def get_custom_target_provided_by_generated_source(self, generated_source: build.CustomTarget) -> 'ImmutableListProtocol[str]':
        libs: T.List[str] = []
        for f in generated_source.get_outputs():
            if self.environment.is_library(f):
                libs.append(os.path.join(self.get_target_dir(generated_source), f))
        return libs

    @lru_cache(maxsize=None)
    def get_custom_target_provided_libraries(self, target: T.Union[build.BuildTarget, build.CustomTarget]) -> 'ImmutableListProtocol[str]':
        libs: T.List[str] = []
        for t in target.get_generated_sources():
            if not isinstance(t, build.CustomTarget):
                continue
            libs.extend(self.get_custom_target_provided_by_generated_source(t))
        return libs

    def get_custom_target_sources(self, target: build.CustomTarget) -> T.List[str]:
        '''
        Custom target sources can be of various object types; strings, File,
        BuildTarget, even other CustomTargets.
        Returns the path to them relative to the build root directory.
        '''
        srcs: T.List[str] = []
        for i in target.get_sources():
            if isinstance(i, str):
                fname = [os.path.join(self.build_to_src, target.get_source_subdir(), i)]
            elif isinstance(i, build.BuildTarget):
                fname = [self.get_target_filename(i)]
            elif isinstance(i, (build.CustomTarget, build.CustomTargetIndex)):
                fname = [os.path.join(self.get_custom_target_output_dir(i), p) for p in i.get_outputs()]
            elif isinstance(i, build.GeneratedList):
                fname = [os.path.join(self.get_target_private_dir(target), p) for p in i.get_outputs()]
            elif isinstance(i, build.ExtractedObjects):
                fname = self.determine_ext_objs(i)
            elif isinstance(i, programs.ExternalProgram):
                assert i.found(), "This shouldn't be possible"
                assert i.path is not None, 'for mypy'
                fname = [i.path]
            else:
                fname = [i.rel_to_builddir(self.build_to_src)]
            if target.absolute_paths:
                fname = [os.path.join(self.environment.get_build_dir(), f) for f in fname]
            srcs += fname
        return srcs

    def get_target_depend_files(self, target: T.Union[build.CustomTarget, build.BuildTarget], absolute_paths: bool = False) -> T.List[str]:
        deps: T.List[str] = []
        for i in target.depend_files:
            if isinstance(i, mesonlib.File):
                if absolute_paths:
                    deps.append(i.absolute_path(self.environment.get_source_dir(),
                                                self.environment.get_build_dir()))
                else:
                    deps.append(i.rel_to_builddir(self.build_to_src))
            else:
                if absolute_paths:
                    deps.append(os.path.join(self.environment.get_source_dir(), target.get_output_subdir(), i))
                else:
                    deps.append(os.path.join(self.build_to_src, target.get_output_subdir(), i))
        return deps

    def get_custom_target_output_dir(self, target: T.Union[build.Target, build.CustomTargetIndex]) -> str:
        # The XCode backend is special. A target foo/bar does
        # not go to ${BUILDDIR}/foo/bar but instead to
        # ${BUILDDIR}/${BUILDTYPE}/foo/bar.
        # Currently we set the include dir to be the former,
        # and not the latter. Thus we need this extra customisation
        # point. If in the future we make include dirs et al match
        # ${BUILDDIR}/${BUILDTYPE} instead, this becomes unnecessary.
        return self.get_target_dir(target)

    @lru_cache(maxsize=None)
    def get_normpath_target(self, source: str) -> str:
        return os.path.normpath(source)

    def get_custom_target_dirs(self, target: build.CustomTarget, compiler: 'Compiler', *,
                               absolute_path: bool = False) -> T.List[str]:
        custom_target_include_dirs: T.List[str] = []
        for i in target.get_generated_sources():
            # Generator output goes into the target private dir which is
            # already in the include paths list. Only custom targets have their
            # own target build dir.
            if not isinstance(i, (build.CustomTarget, build.CustomTargetIndex)):
                continue
            idir = self.get_normpath_target(self.get_custom_target_output_dir(i))
            if not idir:
                idir = '.'
            if absolute_path:
                idir = os.path.join(self.environment.get_build_dir(), idir)
            if idir not in custom_target_include_dirs:
                custom_target_include_dirs.append(idir)
        return custom_target_include_dirs

    def get_custom_target_dir_include_args(
            self, target: build.CustomTarget, compiler: 'Compiler', *,
            absolute_path: bool = False) -> T.List[str]:
        incs: T.List[str] = []
        for i in self.get_custom_target_dirs(target, compiler, absolute_path=absolute_path):
            incs += compiler.get_include_args(i, False)
        return incs

    def eval_custom_target_command(
            self, target: build.CustomTarget, absolute_outputs: bool = False) -> \
            T.Tuple[T.List[str], T.List[str], T.List[str]]:
        # We want the outputs to be absolute only when using the VS backend
        # XXX: Maybe allow the vs backend to use relative paths too?
        source_root = self.build_to_src
        build_root = '.'
        outdir = self.get_custom_target_output_dir(target)
        if absolute_outputs:
            source_root = self.environment.get_source_dir()
            build_root = self.environment.get_build_dir()
            outdir = os.path.join(self.environment.get_build_dir(), outdir)
        outputs = [os.path.join(outdir, i) for i in target.get_outputs()]
        inputs = self.get_custom_target_sources(target)
        # Evaluate the command list
        cmd: T.List[str] = []
        for i in target.command:
            if isinstance(i, build.BuildTarget):
                cmd += self.build_target_to_cmd_array(i)
                continue
            elif isinstance(i, build.CustomTarget):
                # GIR scanner will attempt to execute this binary but
                # it assumes that it is in path, so always give it a full path.
                tmp = i.get_outputs()[0]
                i = os.path.join(self.get_custom_target_output_dir(i), tmp)
            elif isinstance(i, mesonlib.File):
                i = i.rel_to_builddir(self.build_to_src)
                if target.absolute_paths or absolute_outputs:
                    i = os.path.join(self.environment.get_build_dir(), i)
            # FIXME: str types are blindly added ignoring 'target.absolute_paths'
            # because we can't know if they refer to a file or just a string
            elif isinstance(i, str):
                if '@SOURCE_ROOT@' in i:
                    i = i.replace('@SOURCE_ROOT@', source_root)
                if '@BUILD_ROOT@' in i:
                    i = i.replace('@BUILD_ROOT@', build_root)
                if '@CURRENT_SOURCE_DIR@' in i:
                    i = i.replace('@CURRENT_SOURCE_DIR@', os.path.join(source_root, target.get_source_subdir()))
                if '@DEPFILE@' in i:
                    if target.depfile is None:
                        msg = f'Custom target {target.name!r} has @DEPFILE@ but no depfile ' \
                              'keyword argument.'
                        raise MesonException(msg)
                    dfilename = os.path.join(outdir, target.depfile)
                    i = i.replace('@DEPFILE@', dfilename)
                if '@PRIVATE_DIR@' in i:
                    if target.absolute_paths:
                        pdir = self.get_target_private_dir_abs(target)
                    else:
                        pdir = self.get_target_private_dir(target)
                    i = i.replace('@PRIVATE_DIR@', pdir)
            else:
                raise RuntimeError(f'Argument {i} is of unknown type {type(i)}')
            cmd.append(i)
        # Substitute the rest of the template strings
        values = mesonlib.get_filenames_templates_dict(inputs, outputs)
        cmd = mesonlib.substitute_values(cmd, values)
        # This should not be necessary but removing it breaks
        # building GStreamer on Windows. The underlying issue
        # is problems with quoting backslashes on Windows
        # which is the seventh circle of hell. The downside is
        # that this breaks custom targets whose command lines
        # have backslashes. If you try to fix this be sure to
        # check that it does not break GST.
        #
        # The bug causes file paths such as c:\foo to get escaped
        # into c:\\foo.
        #
        # Unfortunately we have not been able to come up with an
        # isolated test case for this so unless you manage to come up
        # with one, the only way is to test the building with Gst's
        # setup. Note this in your MR or ping us and we will get it
        # fixed.
        #
        # https://github.com/mesonbuild/meson/pull/737
        cmd = [i.replace('\\', '/') for i in cmd]
        return inputs, outputs, cmd

    def get_introspect_command(self) -> str:
        return ' '.join(shlex.quote(x) for x in self.environment.get_build_command() + ['introspect'])

    def get_run_target_env(self, target: build.RunTarget) -> mesonlib.EnvironmentVariables:
        env = target.env if target.env else mesonlib.EnvironmentVariables()
        if target.default_env:
            env.set('MESON_SOURCE_ROOT', [self.environment.get_source_dir()])
            env.set('MESON_BUILD_ROOT', [self.environment.get_build_dir()])
            env.set('MESON_SUBDIR', [target.get_source_subdir()])
            env.set('MESONINTROSPECT', [self.get_introspect_command()])
        return env

    def run_postconf_scripts(self) -> None:
        from ..scripts.meson_exe import run_exe
        env = {'MESON_SOURCE_ROOT': self.environment.get_source_dir(),
               'MESON_BUILD_ROOT': self.environment.get_build_dir(),
               'MESONINTROSPECT': self.get_introspect_command(),
               }

        for s in self.build.postconf_scripts:
            name = ' '.join(s.cmd_args)
            mlog.log(f'Running postconf script {name!r}')
            rc = run_exe(s, env)
            if rc != 0:
                raise MesonException(f'Postconf script \'{name}\' failed with exit code {rc}.')

    def create_install_data(self) -> InstallData:
        strip_bin = self.environment.lookup_binary_entry(MachineChoice.HOST, 'strip')
        if strip_bin is None:
            if self.environment.is_cross_build():
                mlog.warning('Cross file does not specify strip binary, result will not be stripped.')
            else:
                # TODO go through all candidates, like others
                strip_bin = [detect.defaults['strip'][0]]

        umask = self.environment.coredata.get_option(OptionKey('install_umask'))
        assert isinstance(umask, (str, int)), 'for mypy'

        d = InstallData(self.environment.get_source_dir(),
                        self.environment.get_build_dir(),
                        self.environment.get_prefix(),
                        self.environment.get_libdir(),
                        strip_bin,
                        umask,
                        self.environment.get_build_command() + ['introspect'],
                        self.environment.coredata.version)
        self.generate_depmf_install(d)
        self.generate_target_install(d)
        self.generate_header_install(d)
        self.generate_man_install(d)
        self.generate_emptydir_install(d)
        self.generate_data_install(d)
        self.generate_symlink_install(d)
        self.generate_custom_install_script(d)
        self.generate_subdir_install(d)
        return d

    def create_install_data_files(self) -> None:
        install_data_file = os.path.join(self.environment.get_scratch_dir(), 'install.dat')
        with open(install_data_file, 'wb') as ofile:
            pickle.dump(self.create_install_data(), ofile)

    def guess_install_tag(self, fname: str, outdir: T.Optional[str] = None) -> T.Optional[str]:
        prefix = self.environment.get_prefix()
        bindir = Path(prefix, self.environment.get_bindir())
        libdir = Path(prefix, self.environment.get_libdir())
        incdir = Path(prefix, self.environment.get_includedir())
        _ldir = self.environment.coredata.get_option(mesonlib.OptionKey('localedir'))
        assert isinstance(_ldir, str), 'for mypy'
        localedir = Path(prefix, _ldir)
        dest_path = Path(prefix, outdir, Path(fname).name) if outdir else Path(prefix, fname)
        if bindir in dest_path.parents:
            return 'runtime'
        elif libdir in dest_path.parents:
            if dest_path.suffix in {'.a', '.pc'}:
                return 'devel'
            elif dest_path.suffix in {'.so', '.dll'}:
                return 'runtime'
        elif incdir in dest_path.parents:
            return 'devel'
        elif localedir in dest_path.parents:
            return 'i18n'
        elif 'installed-tests' in dest_path.parts:
            return 'tests'
        elif 'systemtap' in dest_path.parts:
            return 'systemtap'
        mlog.debug('Failed to guess install tag for', dest_path)
        return None

    def generate_target_install(self, d: InstallData) -> None:
        for t in self.build.get_targets().values():
            if not t.should_install():
                continue
            outdirs, install_dir_names, custom_install_dir = t.get_install_dir()
            # Sanity-check the outputs and install_dirs
            num_outdirs, num_out = len(outdirs), len(t.get_outputs())
            if num_outdirs not in {1, num_out}:
                m = 'Target {!r} has {} outputs: {!r}, but only {} "install_dir"s were found.\n' \
                    "Pass 'false' for outputs that should not be installed and 'true' for\n" \
                    'using the default installation directory for an output.'
                raise MesonException(m.format(t.name, num_out, t.get_outputs(), num_outdirs))
            assert len(t.install_tag) == num_out
            install_mode = t.get_custom_install_mode()
            # because mypy gets confused type narrowing in lists
            first_outdir = outdirs[0]
            first_outdir_name = install_dir_names[0]

            # Install the target output(s)
            if isinstance(t, build.BuildTarget):
                # In general, stripping static archives is tricky and full of pitfalls.
                # Wholesale stripping of static archives with a command such as
                #
                #   strip libfoo.a
                #
                # is broken, as GNU's strip will remove *every* symbol in a static
                # archive. One solution to this nonintuitive behaviour would be
                # to only strip local/debug symbols. Unfortunately, strip arguments
                # are not specified by POSIX and therefore not portable. GNU's `-g`
                # option (i.e. remove debug symbols) is equivalent to Apple's `-S`.
                #
                # TODO: Create GNUStrip/AppleStrip/etc. hierarchy for more
                #       fine-grained stripping of static archives.
                can_strip = not isinstance(t, build.StaticLibrary)
                should_strip = can_strip and t.get_option(OptionKey('strip'))
                assert isinstance(should_strip, bool), 'for mypy'
                # Install primary build output (library/executable/jar, etc)
                # Done separately because of strip/aliases/rpath
                if first_outdir is not False:
                    tag = t.install_tag[0] or ('devel' if isinstance(t, build.StaticLibrary) else 'runtime')
                    mappings = t.get_link_deps_mapping(d.prefix)
                    i = TargetInstallData(self.get_target_filename(t), first_outdir,
                                          first_outdir_name,
                                          should_strip, mappings, t.rpath_dirs_to_remove,
                                          t.install_rpath, install_mode, t.subproject,
                                          tag=tag, can_strip=can_strip)
                    d.targets.append(i)

                    for alias, to, tag in t.get_aliases():
                        alias = os.path.join(first_outdir, alias)
                        s = InstallSymlinkData(to, alias, first_outdir, t.subproject, tag, allow_missing=True)
                        d.symlinks.append(s)

                    if isinstance(t, (build.SharedLibrary, build.SharedModule, build.Executable)):
                        # On toolchains/platforms that use an import library for
                        # linking (separate from the shared library with all the
                        # code), we need to install that too (dll.a/.lib).
                        if t.get_import_filename():
                            if custom_install_dir:
                                # If the DLL is installed into a custom directory,
                                # install the import library into the same place so
                                # it doesn't go into a surprising place
                                implib_install_dir = first_outdir
                            else:
                                implib_install_dir = self.environment.get_import_lib_dir()
                            # Install the import library; may not exist for shared modules
                            i = TargetInstallData(self.get_target_filename_for_linking(t),
                                                  implib_install_dir, first_outdir_name,
                                                  False, {}, set(), '', install_mode,
                                                  t.subproject, optional=isinstance(t, build.SharedModule),
                                                  tag='devel')
                            d.targets.append(i)

                        if not should_strip and t.get_debug_filename():
                            debug_file = os.path.join(self.get_target_dir(t), t.get_debug_filename())
                            i = TargetInstallData(debug_file, first_outdir,
                                                  first_outdir_name,
                                                  False, {}, set(), '',
                                                  install_mode, t.subproject,
                                                  optional=True, tag='devel')
                            d.targets.append(i)
                # Install secondary outputs. Only used for Vala right now.
                if num_outdirs > 1:
                    for output, outdir, outdir_name, tag in zip(t.get_outputs()[1:], outdirs[1:], install_dir_names[1:], t.install_tag[1:]):
                        # User requested that we not install this output
                        if outdir is False:
                            continue
                        f = os.path.join(self.get_target_dir(t), output)
                        i = TargetInstallData(f, outdir, outdir_name, False, {}, set(), None,
                                              install_mode, t.subproject,
                                              tag=tag)
                        d.targets.append(i)
            elif isinstance(t, build.CustomTarget):
                # If only one install_dir is specified, assume that all
                # outputs will be installed into it. This is for
                # backwards-compatibility and because it makes sense to
                # avoid repetition since this is a common use-case.
                #
                # To selectively install only some outputs, pass `false` as
                # the install_dir for the corresponding output by index
                #
                # XXX: this wouldn't be needed if we just always matches outdirs
                # to the length of outputs…
                if num_outdirs == 1 and num_out > 1:
                    if first_outdir is not False:
                        for output, tag in zip(t.get_outputs(), t.install_tag):
                            tag = tag or self.guess_install_tag(output, first_outdir)
                            f = os.path.join(self.get_target_dir(t), output)
                            i = TargetInstallData(f, first_outdir, first_outdir_name,
                                                  False, {}, set(), None, install_mode,
                                                  t.subproject, optional=not t.build_by_default,
                                                  tag=tag)
                            d.targets.append(i)
                else:
                    for output, outdir, outdir_name, tag in zip(t.get_outputs(), outdirs, install_dir_names, t.install_tag):
                        # User requested that we not install this output
                        if outdir is False:
                            continue
                        tag = tag or self.guess_install_tag(output, outdir)
                        f = os.path.join(self.get_target_dir(t), output)
                        i = TargetInstallData(f, outdir, outdir_name,
                                              False, {}, set(), None, install_mode,
                                              t.subproject, optional=not t.build_by_default,
                                              tag=tag)
                        d.targets.append(i)

    def generate_custom_install_script(self, d: InstallData) -> None:
        d.install_scripts = self.build.install_scripts
        for i in d.install_scripts:
            if not i.tag:
                mlog.debug('Failed to guess install tag for install script:', ' '.join(i.cmd_args))

    def generate_header_install(self, d: InstallData) -> None:
        incroot = self.environment.get_includedir()
        headers = self.build.get_headers()

        srcdir = self.environment.get_source_dir()
        builddir = self.environment.get_build_dir()
        for h in headers:
            outdir = outdir_name = h.get_custom_install_dir()
            if outdir is None:
                subdir = h.get_install_subdir()
                if subdir is None:
                    outdir = incroot
                    outdir_name = '{includedir}'
                else:
                    outdir = os.path.join(incroot, subdir)
                    outdir_name = os.path.join('{includedir}', subdir)

            for f in h.get_sources():
                abspath = f.absolute_path(srcdir, builddir)
                i = InstallDataBase(abspath, outdir, outdir_name, h.get_custom_install_mode(), h.subproject, tag='devel', follow_symlinks=h.follow_symlinks)
                d.headers.append(i)

    def generate_man_install(self, d: InstallData) -> None:
        manroot = self.environment.get_mandir()
        man = self.build.get_man()
        for m in man:
            for f in m.get_sources():
                num = f.split('.')[-1]
                subdir = m.get_custom_install_dir()
                if subdir is None:
                    if m.locale:
                        subdir = os.path.join('{mandir}', m.locale, 'man' + num)
                    else:
                        subdir = os.path.join('{mandir}', 'man' + num)
                fname = f.fname
                if m.locale: # strip locale from file name
                    fname = fname.replace(f'.{m.locale}', '')
                srcabs = f.absolute_path(self.environment.get_source_dir(), self.environment.get_build_dir())
                dstname = os.path.join(subdir, os.path.basename(fname))
                dstabs = dstname.replace('{mandir}', manroot)
                i = InstallDataBase(srcabs, dstabs, dstname, m.get_custom_install_mode(), m.subproject, tag='man')
                d.man.append(i)

    def generate_emptydir_install(self, d: InstallData) -> None:
        emptydir: T.List[build.EmptyDir] = self.build.get_emptydir()
        for e in emptydir:
            tag = e.install_tag or self.guess_install_tag(e.path)
            i = InstallEmptyDir(e.path, e.install_mode, e.subproject, tag)
            d.emptydir.append(i)

    def generate_data_install(self, d: InstallData) -> None:
        data = self.build.get_data()
        srcdir = self.environment.get_source_dir()
        builddir = self.environment.get_build_dir()
        for de in data:
            assert isinstance(de, build.Data)
            subdir = de.install_dir
            subdir_name = de.install_dir_name
            for src_file, dst_name in zip(de.sources, de.rename):
                assert isinstance(src_file, mesonlib.File)
                dst_abs = os.path.join(subdir, dst_name)
                dstdir_name = os.path.join(subdir_name, dst_name)
                tag = de.install_tag or self.guess_install_tag(dst_abs)
                i = InstallDataBase(src_file.absolute_path(srcdir, builddir), dst_abs, dstdir_name,
                                    de.install_mode, de.subproject, tag=tag, data_type=de.data_type,
                                    follow_symlinks=de.follow_symlinks)
                d.data.append(i)

    def generate_symlink_install(self, d: InstallData) -> None:
        links: T.List[build.SymlinkData] = self.build.get_symlinks()
        for l in links:
            assert isinstance(l, build.SymlinkData)
            install_dir = l.install_dir
            name_abs = os.path.join(install_dir, l.name)
            tag = l.install_tag or self.guess_install_tag(name_abs)
            s = InstallSymlinkData(l.target, name_abs, install_dir, l.subproject, tag)
            d.symlinks.append(s)

    def generate_subdir_install(self, d: InstallData) -> None:
        for sd in self.build.get_install_subdirs():
            if sd.from_source_dir:
                from_dir = self.environment.get_source_dir()
            else:
                from_dir = self.environment.get_build_dir()
            src_dir = os.path.join(from_dir,
                                   sd.source_subdir,
                                   sd.installable_subdir).rstrip('/')
            dst_dir = os.path.join(self.environment.get_prefix(),
                                   sd.install_dir)
            dst_name = os.path.join('{prefix}', sd.install_dir)
            if sd.install_dir != sd.install_dir_name:
                dst_name = sd.install_dir_name
            if not sd.strip_directory:
                dst_dir = os.path.join(dst_dir, os.path.basename(src_dir))
                dst_name = os.path.join(dst_name, os.path.basename(src_dir))
            tag = sd.install_tag or self.guess_install_tag(os.path.join(sd.install_dir, 'dummy'))
            i = SubdirInstallData(src_dir, dst_dir, dst_name, sd.install_mode, sd.exclude, sd.subproject, tag,
                                  follow_symlinks=sd.follow_symlinks)
            d.install_subdirs.append(i)

    def get_introspection_data(self, target_id: str, target: build.Target) -> T.List['TargetIntrospectionData']:
        '''
        Returns a list of source dicts with the following format for a given target:
        [
            {
                "language": "<LANG>",
                "compiler": ["result", "of", "comp.get_exelist()"],
                "parameters": ["list", "of", "compiler", "parameters],
                "sources": ["list", "of", "all", "<LANG>", "source", "files"],
                "generated_sources": ["list", "of", "generated", "source", "files"]
            }
        ]

        This is a limited fallback / reference implementation. The backend should override this method.
        '''
        if isinstance(target, (build.CustomTarget, build.BuildTarget)):
            source_list_raw = target.sources
            source_list = []
            for j in source_list_raw:
                if isinstance(j, mesonlib.File):
                    source_list += [j.absolute_path(self.source_dir, self.build_dir)]
                elif isinstance(j, str):
                    source_list += [os.path.join(self.source_dir, j)]
                elif isinstance(j, (build.CustomTarget, build.BuildTarget)):
                    source_list += [os.path.join(self.build_dir, j.get_output_subdir(), o) for o in j.get_outputs()]
            source_list = [os.path.normpath(s) for s in source_list]

            compiler: T.List[str] = []
            if isinstance(target, build.CustomTarget):
                tmp_compiler = target.command
                for j in tmp_compiler:
                    if isinstance(j, mesonlib.File):
                        compiler += [j.absolute_path(self.source_dir, self.build_dir)]
                    elif isinstance(j, str):
                        compiler += [j]
                    elif isinstance(j, (build.BuildTarget, build.CustomTarget)):
                        compiler += j.get_outputs()
                    else:
                        raise RuntimeError(f'Type "{type(j).__name__}" is not supported in get_introspection_data. This is a bug')

            return [{
                'language': 'unknown',
                'compiler': compiler,
                'parameters': [],
                'sources': source_list,
                'generated_sources': []
            }]

        return []

    def get_devenv(self) -> mesonlib.EnvironmentVariables:
        env = mesonlib.EnvironmentVariables()
        extra_paths = set()
        library_paths = set()
        build_machine = self.environment.machines[MachineChoice.BUILD]
        host_machine = self.environment.machines[MachineChoice.HOST]
        need_wine = not build_machine.is_windows() and host_machine.is_windows()
        for t in self.build.get_targets().values():
            in_default_dir = t.should_install() and not t.get_install_dir()[2]
            if t.for_machine != MachineChoice.HOST or not in_default_dir:
                continue
            tdir = os.path.join(self.environment.get_build_dir(), self.get_target_dir(t))
            if isinstance(t, build.Executable):
                # Add binaries that are going to be installed in bindir into PATH
                # so they get used by default instead of searching on system when
                # in developer environment.
                extra_paths.add(tdir)
                if host_machine.is_windows() or host_machine.is_cygwin():
                    # On windows we cannot rely on rpath to run executables from build
                    # directory. We have to add in PATH the location of every DLL needed.
                    library_paths.update(self.determine_windows_extra_paths(t, []))
            elif isinstance(t, build.SharedLibrary):
                # Add libraries that are going to be installed in libdir into
                # LD_LIBRARY_PATH. This allows running system applications using
                # that library.
                library_paths.add(tdir)
        if need_wine:
            # Executable paths should be in both PATH and WINEPATH.
            # - Having them in PATH makes bash completion find it,
            #   and make running "foo.exe" find it when wine-binfmt is installed.
            # - Having them in WINEPATH makes "wine foo.exe" find it.
            library_paths.update(extra_paths)
        if library_paths:
            if need_wine:
                env.prepend('WINEPATH', list(library_paths), separator=';')
            elif host_machine.is_windows() or host_machine.is_cygwin():
                extra_paths.update(library_paths)
            elif host_machine.is_darwin():
                env.prepend('DYLD_LIBRARY_PATH', list(library_paths))
            else:
                env.prepend('LD_LIBRARY_PATH', list(library_paths))
        if extra_paths:
            env.prepend('PATH', list(extra_paths))
        return env

    def compiler_to_generator(self, target: build.BuildTarget,
                              compiler: 'Compiler',
                              sources: _ALL_SOURCES_TYPE,
                              output_templ: str,
                              depends: T.Optional[T.List[T.Union[build.BuildTarget, build.CustomTarget, build.CustomTargetIndex]]] = None,
                              ) -> build.GeneratedList:
        '''
        Some backends don't support custom compilers. This is a convenience
        method to conve
```