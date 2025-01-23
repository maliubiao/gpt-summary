Response:
Let's break down the request and the provided Python code step-by-step to construct a comprehensive answer.

**1. Understanding the Core Request:**

The main goal is to analyze the Python code for `external_project.py` within the Frida project and explain its functionality, especially its relevance to reverse engineering, low-level aspects, logic, potential user errors, and debugging.

**2. Initial Code Scan and High-Level Understanding:**

First, I'd read through the code to grasp its primary purpose. Keywords like `ExternalProject`, `configure_command`, `make`, `dependency`, and `add_project` suggest it's about integrating external build systems (like Autotools or Waf) into the Meson build process. This is a common task when a project depends on a library or tool built with a different system.

**3. Functionality Breakdown:**

I'd go function by function, noting the purpose of each.

* `ExternalProject.__init__`: Initializes the object, sets up paths, and calls `_configure`.
* `ExternalProject._configure`:  Handles the configuration step of the external project (running `configure`, `autogen.sh`, or `waf`). Crucially, it sets up environment variables.
* `ExternalProject._quote_and_join`: A utility for quoting and joining shell command arguments.
* `ExternalProject._validate_configure_options`: Ensures basic configuration options (like prefix) are passed.
* `ExternalProject._format_options`:  Performs variable substitution in configure options.
* `ExternalProject._run`: Executes shell commands and handles logging and error checking.
* `ExternalProject._create_targets`: Defines Meson build targets for the external project (a `CustomTarget` to trigger the build and an `InstallDir` to handle installation).
* `ExternalProject.dependency_method`: Creates an `InternalDependency` object, allowing other parts of the Meson build to depend on the external project's output.
* `ExternalProjectModule.add_project`: The main entry point for using the `external_project` module in a `meson.build` file. It creates an `ExternalProject` instance.
* `initialize`: The standard entry point for a Meson extension module.

**4. Connecting to Reverse Engineering:**

Now, the crucial step is to relate the functionalities to reverse engineering.

* **External Libraries:** Reverse engineering often involves analyzing and interacting with closed-source libraries. This module facilitates the inclusion of such libraries in a Frida build, even if they use different build systems.
* **Instrumentation Tooling:** Frida is an instrumentation tool. This module likely helps integrate components needed for instrumentation (e.g., a custom runtime or support library) that might be built separately.
* **Target Environment Setup:**  The configuration and environment variable handling are relevant for targeting specific environments (like Android).

**5. Identifying Low-Level/Kernel/Framework Aspects:**

This requires looking for code elements that touch upon these areas.

* **Cross-Compilation:** The `cross_configure_options` and the handling of `host` architecture strongly indicate support for cross-compilation, which is essential for targeting embedded systems like Android.
* **Environment Variables:**  The manipulation of environment variables (CFLAGS, CC, LDFLAGS, LD) directly interacts with the compiler and linker, which are fundamental low-level tools.
* **Android Context (Implied):** While not explicit in the code, the fact that this is part of the Frida project, which is heavily used for Android instrumentation, implies that this module is likely used in Android-related scenarios.

**6. Logical Reasoning (Hypothetical Input/Output):**

Here, I'd create a simple scenario:

* **Input:** A `meson.build` file calling `external_project.add_project('configure', configure_options=['--enable-foo'])`.
* **Process:** The `_configure` method would be invoked, executing the `configure` script with the `--enable-foo` option.
* **Output:**  If successful, the `build` directory would be created, and a `Makefile` (or equivalent) would be generated. If `dependency_method` is called later, it would create an `InternalDependency` pointing to the installed headers and libraries.

**7. Common User Errors:**

Think about how a user might misuse this module.

* **Incorrect `configure_command`:**  Specifying a non-existent script.
* **Missing Dependencies:** The external project might require tools not present in the environment.
* **Incorrect Options:** Passing invalid configuration options to the external project.
* **Path Issues:** Problems with source or build directories.

**8. Debugging Trace:**

Imagine a user reports an issue. How would they arrive at this code?

* **Problem:** An external dependency isn't being built or linked correctly.
* **Meson Execution:** The user runs `meson build` or `ninja`.
* **External Project Invocation:** Meson executes the `CustomTarget` created by `_create_targets`, which internally calls the `make` command.
* **Configuration Issues:**  Errors during the `configure` step would manifest in the `_configure` method, particularly in the `_run` function's error handling.
* **Dependency Issues:** Problems with linking would likely stem from the `dependency_method` not generating the correct link flags.

**9. Structuring the Answer:**

Finally, organize the information logically, using headings and bullet points for clarity. Provide code snippets where relevant and explain the connection to reverse engineering, low-level aspects, etc., clearly. Use examples to illustrate concepts.

By following this systematic approach, I could generate the detailed and informative answer provided previously. The key is to understand the code's purpose, then specifically connect it to the various aspects requested in the prompt.
This Python code file, `external_project.py`, is a module within the Meson build system that enables the integration of external projects (those using different build systems like Autotools or Make) into a Meson-based build. It's part of Frida's build process, likely used for including dependencies or components that aren't built directly with Meson.

Here's a breakdown of its functionality, along with connections to reverse engineering, low-level aspects, and potential user errors:

**Core Functionality:**

1. **Defining an `ExternalProject` Class:** This class encapsulates the logic for handling an external project. It stores information about the source directory, build directory, install directory, configuration command, options, and dependencies.

2. **Configuration (`_configure` method):**
   - **Discovers the Configuration Command:** It determines the command to run for configuring the external project. This could be a script named 'configure', 'autogen.sh', or even 'waf' (for projects using the Waf build system).
   - **Sets Up Environment Variables:**  It meticulously sets up environment variables crucial for the external project's configuration, including:
     - `PREFIX`, `LIBDIR`, `INCLUDEDIR`:  Standard variables to control the installation location.
     - `HOST`:  Information about the target architecture for cross-compilation.
     - `CFLAGS`, `CC`, `LDFLAGS`, etc.: Compiler and linker flags and executables. It retrieves these from Meson's configuration.
     - Environment variables provided by the user through the `env` keyword.
     - Environment variables related to `pkg-config`.
   - **Executes the Configuration Command:**  It runs the configuration command in the external project's source directory.

3. **Building (`_create_targets` method):**
   - **Creates a Custom Target:** It defines a Meson `CustomTarget` that represents the building and installation of the external project. This target will execute `make` (or the equivalent build command for Waf) in the external project's build directory.
   - **Handles Dependencies:**  It allows specifying dependencies (`extra_depends`) on other Meson targets, ensuring the external project is built after its prerequisites.
   - **Defines Installation:** It creates an `InstallDir` target to specify how the built artifacts of the external project should be installed into the final output directory.

4. **Providing Dependencies (`dependency_method`):**
   - **Creates an `InternalDependency`:** This method allows other parts of the Meson build to depend on the external project. It creates an `InternalDependency` object containing:
     - Include directories from the installed external project.
     - Linker flags (`-L` and `-l`) to link against the external project's libraries.
     - The `CustomTarget` representing the external project build as a source dependency.

5. **`ExternalProjectModule` Class:** This class registers the `add_project` method, making the functionality available in `meson.build` files.

6. **`add_project` Method:** This is the user-facing method called in `meson.build` to integrate an external project. It takes the configuration command and various options as arguments.

**Relation to Reverse Engineering:**

This module is highly relevant to reverse engineering in the context of tools like Frida:

* **Integrating Target Libraries:** When reverse engineering, you often need to interact with or analyze libraries from the target system (e.g., system libraries on Android). This module allows Frida to build and link against these external libraries as part of its own build process. For example, if Frida needs to interact with a specific Android system service, that service's client library might be built as an external project.
* **Building Custom Stubs/Wrappers:** You might need to build custom shared libraries that interact with the target application. These libraries could be built using a traditional build system and integrated into the Frida gadget or agent using this module.
* **Handling Complex Dependencies:** Reverse engineering tools themselves can have complex dependencies on third-party libraries that might not be readily available as Meson subprojects. This module provides a way to include them.

**Example:** Imagine Frida needs to use a specific version of the `libuv` library that's not provided by the system. The `meson.build` might include:

```python
external_project_mod = import('meson.experimental')
libuv_dep = external_project_mod.add_project(
    'configure',
    configure_options=['--prefix=' + meson.build_root() + '/libuv_install'],
    subdir='third_party/libuv',
)

# ... later, when building a Frida component
frida_component = shared_library(
    'frida_component',
    'frida_component.c',
    dependencies: [libuv_dep.get_dependency('uv')],
)
```

This tells Meson to:
1. Go to the `third_party/libuv` directory.
2. Run the `configure` script with the specified prefix.
3. Build and install `libuv`.
4. Create a dependency object (`libuv_dep`) that allows linking against `libuv`.

**In the context of reverse engineering methods, this module facilitates:**

* **Dynamic Instrumentation Setup:**  It helps build the necessary components and dependencies for the dynamic instrumentation framework itself.
* **Target Environment Emulation/Simulation:** If Frida needs to interact with specific libraries or system calls, this module can help build or link against emulated or simulated versions of those components.

**Involvement of Binary 底层, Linux, Android Kernel & Framework Knowledge:**

* **Binary 底层 (Binary Low-Level):**
    - **Compiler and Linker Flags:** The module directly manipulates compiler (`CFLAGS`) and linker (`LDFLAGS`) flags, which are fundamental to binary compilation and linking.
    - **Executable Paths:** It deals with the paths to compilers (`CC`) and other build tools, which operate on binary code.
    - **Cross-Compilation:** The support for `cross_configure_options` is crucial for targeting different architectures (like ARM for Android), requiring knowledge of cross-compilation toolchains and binary compatibility.

* **Linux:**
    - **Standard Build Processes:** The module often interacts with traditional Linux build systems like Autotools (`configure`, `make`).
    - **File System Structure:** Concepts like `PREFIX`, `LIBDIR`, `INCLUDEDIR` are standard in Linux software installation.
    - **Environment Variables:** The reliance on environment variables for configuration is a core principle in Linux.

* **Android Kernel & Framework:**
    - **Cross-Compilation for Android:** Building Frida for Android requires cross-compiling for the ARM architecture, and this module helps manage the configuration for that.
    - **Linking Against Android Libraries:** When instrumenting Android processes, Frida might need to link against specific Android framework libraries. This module allows including those libraries as external projects.
    - **Understanding Android Build Systems:** While Android often uses its own build system (like Soong), some dependencies might use standard Autotools or Make, making this module relevant.

**Logical Reasoning (Hypothetical Input & Output):**

**Hypothetical Input (in `meson.build`):**

```python
ext_proj = external_project_mod.add_project(
    './build_my_lib.sh',  # Custom build script
    subdir='my_external_lib',
    configure_options=['--enable-feature-x'],
    env={'MY_CUSTOM_VAR': 'some_value'}
)
```

**Process:**

1. Meson will identify the `external_project_mod.add_project` call.
2. The `ExternalProject` class will be instantiated.
3. The `_configure` method will be called.
4. It will attempt to execute the script `./build_my_lib.sh` within the `my_external_lib` subdirectory.
5. Before execution, it will set environment variables, including `MY_CUSTOM_VAR` to `some_value`.
6. The script `build_my_lib.sh` is expected to handle the configuration and potentially the build process itself.
7. If the script succeeds, the `_create_targets` method will create a `CustomTarget` for building (which might involve running `make` or commands within the script).

**Potential Output (if successful):**

- A build directory (`build`) will be created within `my_external_lib`.
- Log files for the configuration step will be generated in the Meson log directory.
- A Meson `CustomTarget` named after the subdirectory (`my_external_lib`) will be created.
- If the external project installs files, they will be placed in the specified install directory (likely under the main build directory).

**User or Programming Common Usage Errors:**

1. **Incorrect `configure_command`:** Specifying a non-existent script or the wrong command name. This will lead to an error when Meson tries to execute it.
   ```python
   ext_proj = external_project_mod.add_project('configuree', subdir='my_lib') # Typo in 'configure'
   ```
   **Error:**  Meson will likely fail to find the `configuree` program.

2. **Missing Dependencies for the External Project:** The external project might require specific tools (like `autoconf`, `automake`, compilers) that are not available in the environment where Meson is running.
   ```python
   # Assuming the external project needs autoconf
   ext_proj = external_project_mod.add_project('autogen.sh', subdir='needs_autoconf')
   ```
   **Error:** The `autogen.sh` script might fail because `autoconf` is not found in the `PATH`.

3. **Incorrect `configure_options`:** Providing options that are not recognized by the external project's configuration script.
   ```python
   ext_proj = external_project_mod.add_project('configure', subdir='some_lib', configure_options=['--enable-nonexistent-feature'])
   ```
   **Error:** The `configure` script will likely report an error about the unknown option.

4. **Path Issues:** Incorrect `subdir` or paths within the external project's build scripts.
   ```python
   ext_proj = external_project_mod.add_project('configure', subdir='wrong_path')
   ```
   **Error:** Meson won't find the specified subdirectory.

5. **Environment Variable Conflicts:**  The user-provided `env` variables might conflict with the environment variables Meson sets up, causing unexpected behavior in the external project's build.

**How User Operations Reach This Code (Debugging Clues):**

1. **User adds an external project in `meson.build`:** The user modifies their `meson.build` file and includes a call to `external_project_mod.add_project(...)`.

2. **User runs `meson setup` or `meson configure`:**  Meson parses the `meson.build` file. When it encounters the `add_project` call:
   - The `ExternalProjectModule` is initialized.
   - The `add_project` method is executed.
   - An `ExternalProject` instance is created.
   - The `_configure` method is called, attempting to run the specified configuration command.

3. **User runs `meson compile` or `ninja`:**  When the build is initiated:
   - Meson identifies the `CustomTarget` created for the external project.
   - It executes the build command (typically `make`) within the external project's build directory.
   - If dependencies are involved, Meson ensures the external project is built before targets that depend on it.

**Debugging Scenario:**

Let's say a user reports that an external library is not being built correctly. Here's how they might have arrived at this code as a debugging point:

1. **Problem:**  The build fails with an error message related to the external library (e.g., "cannot find -lmylib").

2. **User investigates `meson.build`:** They find the `external_project_mod.add_project` call for that library.

3. **User checks the Meson logs:** They would look for logs related to the configuration and build steps of the external project. These logs are generated by the `_run` method within this Python file.

4. **User might examine the `_configure` method:** They could be looking to see if the correct configuration options were passed, if the environment variables were set up as expected, or if the configuration command executed successfully.

5. **User might examine the `_create_targets` method:** They could be checking the exact `make` command that Meson is trying to run or the dependencies defined for the external project.

6. **User might examine the `dependency_method`:** If the linking is failing, they would investigate how the `InternalDependency` is being created, checking the include directories and linker flags.

By stepping through the code and examining the logs generated by this module, a developer can pinpoint issues related to the configuration, building, or dependency handling of the external project. This module acts as the bridge between the Meson build system and external build systems, making it a critical point for understanding and debugging such integrations.

### 提示词
```
这是目录为frida/subprojects/frida-python/releng/meson/mesonbuild/modules/external_project.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```python
# SPDX-License-Identifier: Apache-2.0
# Copyright 2020 The Meson development team

from __future__ import annotations

from pathlib import Path
import os
import shlex
import subprocess
import typing as T

from . import ExtensionModule, ModuleReturnValue, NewExtensionModule, ModuleInfo
from .. import mlog, build
from ..compilers.compilers import CFLAGS_MAPPING
from ..envconfig import ENV_VAR_PROG_MAP
from ..dependencies import InternalDependency
from ..dependencies.pkgconfig import PkgConfigInterface
from ..interpreterbase import FeatureNew
from ..interpreter.type_checking import ENV_KW, DEPENDS_KW
from ..interpreterbase.decorators import ContainerTypeInfo, KwargInfo, typed_kwargs, typed_pos_args
from ..mesonlib import (EnvironmentException, MesonException, Popen_safe, MachineChoice,
                        get_variable_regex, do_replacement, join_args, OptionKey)

if T.TYPE_CHECKING:
    from typing_extensions import TypedDict

    from . import ModuleState
    from .._typing import ImmutableListProtocol
    from ..build import BuildTarget, CustomTarget
    from ..interpreter import Interpreter
    from ..interpreterbase import TYPE_var
    from ..mesonlib import EnvironmentVariables
    from ..utils.core import EnvironOrDict

    class Dependency(TypedDict):

        subdir: str

    class AddProject(TypedDict):

        configure_options: T.List[str]
        cross_configure_options: T.List[str]
        verbose: bool
        env: EnvironmentVariables
        depends: T.List[T.Union[BuildTarget, CustomTarget]]


class ExternalProject(NewExtensionModule):

    make: ImmutableListProtocol[str]

    def __init__(self,
                 state: 'ModuleState',
                 configure_command: str,
                 configure_options: T.List[str],
                 cross_configure_options: T.List[str],
                 env: EnvironmentVariables,
                 verbose: bool,
                 extra_depends: T.List[T.Union['BuildTarget', 'CustomTarget']]):
        super().__init__()
        self.methods.update({'dependency': self.dependency_method,
                             })

        self.subdir = Path(state.subdir)
        self.project_version = state.project_version
        self.subproject = state.subproject
        self.env = state.environment
        self.configure_command = configure_command
        self.configure_options = configure_options
        self.cross_configure_options = cross_configure_options
        self.verbose = verbose
        self.user_env = env

        self.src_dir = Path(self.env.get_source_dir(), self.subdir)
        self.build_dir = Path(self.env.get_build_dir(), self.subdir, 'build')
        self.install_dir = Path(self.env.get_build_dir(), self.subdir, 'dist')
        _p = self.env.coredata.get_option(OptionKey('prefix'))
        assert isinstance(_p, str), 'for mypy'
        self.prefix = Path(_p)
        _l = self.env.coredata.get_option(OptionKey('libdir'))
        assert isinstance(_l, str), 'for mypy'
        self.libdir = Path(_l)
        _i = self.env.coredata.get_option(OptionKey('includedir'))
        assert isinstance(_i, str), 'for mypy'
        self.includedir = Path(_i)
        self.name = self.src_dir.name

        # On Windows if the prefix is "c:/foo" and DESTDIR is "c:/bar", `make`
        # will install files into "c:/bar/c:/foo" which is an invalid path.
        # Work around that issue by removing the drive from prefix.
        if self.prefix.drive:
            self.prefix = self.prefix.relative_to(self.prefix.drive)

        # self.prefix is an absolute path, so we cannot append it to another path.
        self.rel_prefix = self.prefix.relative_to(self.prefix.root)

        self._configure(state)

        self.targets = self._create_targets(extra_depends, state.is_build_only_subproject)

    def _configure(self, state: 'ModuleState') -> None:
        if self.configure_command == 'waf':
            FeatureNew('Waf external project', '0.60.0').use(self.subproject, state.current_node)
            waf = state.find_program('waf')
            configure_cmd = waf.get_command()
            configure_cmd += ['configure', '-o', str(self.build_dir)]
            workdir = self.src_dir
            self.make = waf.get_command() + ['build']
        else:
            # Assume it's the name of a script in source dir, like 'configure',
            # 'autogen.sh', etc).
            configure_path = Path(self.src_dir, self.configure_command)
            configure_prog = state.find_program(configure_path.as_posix())
            configure_cmd = configure_prog.get_command()
            workdir = self.build_dir
            self.make = state.find_program('make').get_command()

        d = [('PREFIX', '--prefix=@PREFIX@', self.prefix.as_posix()),
             ('LIBDIR', '--libdir=@PREFIX@/@LIBDIR@', self.libdir.as_posix()),
             ('INCLUDEDIR', None, self.includedir.as_posix()),
             ]
        self._validate_configure_options(d, state)

        configure_cmd += self._format_options(self.configure_options, d)

        if self.env.is_cross_build():
            host = '{}-{}-{}'.format(state.environment.machines.host.cpu,
                                     'pc' if state.environment.machines.host.cpu_family in {"x86", "x86_64"}
                                     else 'unknown',
                                     state.environment.machines.host.system)
            d = [('HOST', None, host)]
            configure_cmd += self._format_options(self.cross_configure_options, d)

        # Set common env variables like CFLAGS, CC, etc.
        link_exelist: T.List[str] = []
        link_args: T.List[str] = []
        self.run_env: EnvironOrDict = os.environ.copy()
        for lang, compiler in self.env.coredata.compilers[MachineChoice.HOST].items():
            if any(lang not in i for i in (ENV_VAR_PROG_MAP, CFLAGS_MAPPING)):
                continue
            cargs = self.env.coredata.get_external_args(MachineChoice.HOST, lang)
            assert isinstance(cargs, list), 'for mypy'
            self.run_env[ENV_VAR_PROG_MAP[lang]] = self._quote_and_join(compiler.get_exelist())
            self.run_env[CFLAGS_MAPPING[lang]] = self._quote_and_join(cargs)
            if not link_exelist:
                link_exelist = compiler.get_linker_exelist()
                _l = self.env.coredata.get_external_link_args(MachineChoice.HOST, lang)
                assert isinstance(_l, list), 'for mypy'
                link_args = _l
        if link_exelist:
            # FIXME: Do not pass linker because Meson uses CC as linker wrapper,
            # but autotools often expects the real linker (e.h. GNU ld).
            # self.run_env['LD'] = self._quote_and_join(link_exelist)
            pass
        self.run_env['LDFLAGS'] = self._quote_and_join(link_args)

        self.run_env = self.user_env.get_env(self.run_env)
        self.run_env = PkgConfigInterface.setup_env(self.run_env, self.env, MachineChoice.HOST,
                                                    uninstalled=True)

        self.build_dir.mkdir(parents=True, exist_ok=True)
        self._run('configure', configure_cmd, workdir)

    def _quote_and_join(self, array: T.List[str]) -> str:
        return ' '.join([shlex.quote(i) for i in array])

    def _validate_configure_options(self, variables: T.List[T.Tuple[str, str, str]], state: 'ModuleState') -> None:
        # Ensure the user at least try to pass basic info to the build system,
        # like the prefix, libdir, etc.
        for key, default, val in variables:
            if default is None:
                continue
            key_format = f'@{key}@'
            for option in self.configure_options:
                if key_format in option:
                    break
            else:
                FeatureNew('Default configure_option', '0.57.0').use(self.subproject, state.current_node)
                self.configure_options.append(default)

    def _format_options(self, options: T.List[str], variables: T.List[T.Tuple[str, str, str]]) -> T.List[str]:
        out: T.List[str] = []
        missing = set()
        regex = get_variable_regex('meson')
        confdata: T.Dict[str, T.Tuple[str, T.Optional[str]]] = {k: (v, None) for k, _, v in variables}
        for o in options:
            arg, missing_vars = do_replacement(regex, o, 'meson', confdata)
            missing.update(missing_vars)
            out.append(arg)
        if missing:
            var_list = ", ".join(repr(m) for m in sorted(missing))
            raise EnvironmentException(
                f"Variables {var_list} in configure options are missing.")
        return out

    def _run(self, step: str, command: T.List[str], workdir: Path) -> None:
        mlog.log(f'External project {self.name}:', mlog.bold(step))
        m = 'Running command ' + str(command) + ' in directory ' + str(workdir) + '\n'
        log_filename = Path(mlog.get_log_dir(), f'{self.name}-{step}.log')
        output = None
        if not self.verbose:
            output = open(log_filename, 'w', encoding='utf-8')
            output.write(m + '\n')
            output.flush()
        else:
            mlog.log(m)
        p, *_ = Popen_safe(command, cwd=workdir, env=self.run_env,
                           stderr=subprocess.STDOUT,
                           stdout=output)
        if p.returncode != 0:
            m = f'{step} step returned error code {p.returncode}.'
            if not self.verbose:
                m += '\nSee logs: ' + str(log_filename)
            raise MesonException(m)

    def _create_targets(self, extra_depends: T.List[T.Union['BuildTarget', 'CustomTarget']], is_build_only_subproject: bool) -> T.List['TYPE_var']:
        cmd = self.env.get_build_command()
        cmd += ['--internal', 'externalproject',
                '--name', self.name,
                '--srcdir', self.src_dir.as_posix(),
                '--builddir', self.build_dir.as_posix(),
                '--installdir', self.install_dir.as_posix(),
                '--logdir', mlog.get_log_dir(),
                '--make', join_args(self.make),
                ]
        if self.verbose:
            cmd.append('--verbose')

        self.target = build.CustomTarget(
            self.name,
            self.subdir.as_posix(),
            self.subproject,
            self.env,
            cmd + ['@OUTPUT@', '@DEPFILE@'],
            [],
            [f'{self.name}.stamp'],
            is_build_only_subproject,
            depfile=f'{self.name}.d',
            console=True,
            extra_depends=extra_depends,
            description='Generating external project {}',
        )

        idir = build.InstallDir(self.subdir.as_posix(),
                                Path('dist', self.rel_prefix).as_posix(),
                                install_dir='.',
                                install_dir_name='.',
                                install_mode=None,
                                exclude=None,
                                strip_directory=True,
                                from_source_dir=False,
                                subproject=self.subproject)

        return [self.target, idir]

    @typed_pos_args('external_project.dependency', str)
    @typed_kwargs('external_project.dependency', KwargInfo('subdir', str, default=''))
    def dependency_method(self, state: 'ModuleState', args: T.Tuple[str], kwargs: 'Dependency') -> InternalDependency:
        libname = args[0]

        abs_includedir = Path(self.install_dir, self.rel_prefix, self.includedir)
        if kwargs['subdir']:
            abs_includedir = Path(abs_includedir, kwargs['subdir'])
        abs_libdir = Path(self.install_dir, self.rel_prefix, self.libdir)

        version = self.project_version
        compile_args = [f'-I{abs_includedir}']
        link_args = [f'-L{abs_libdir}', f'-l{libname}']
        sources = self.target
        dep = InternalDependency(version, [], compile_args, link_args, [],
                                 [], [sources], [], [], {}, [], [], [])
        return dep


class ExternalProjectModule(ExtensionModule):

    INFO = ModuleInfo('External build system', '0.56.0', unstable=True)

    def __init__(self, interpreter: 'Interpreter'):
        super().__init__(interpreter)
        self.methods.update({'add_project': self.add_project,
                             })

    @typed_pos_args('external_project_mod.add_project', str)
    @typed_kwargs(
        'external_project.add_project',
        KwargInfo('configure_options', ContainerTypeInfo(list, str), default=[], listify=True),
        KwargInfo('cross_configure_options', ContainerTypeInfo(list, str), default=['--host=@HOST@'], listify=True),
        KwargInfo('verbose', bool, default=False),
        ENV_KW,
        DEPENDS_KW.evolve(since='0.63.0'),
    )
    def add_project(self, state: 'ModuleState', args: T.Tuple[str], kwargs: 'AddProject') -> ModuleReturnValue:
        configure_command = args[0]
        project = ExternalProject(state,
                                  configure_command,
                                  kwargs['configure_options'],
                                  kwargs['cross_configure_options'],
                                  kwargs['env'],
                                  kwargs['verbose'],
                                  kwargs['depends'])
        return ModuleReturnValue(project, project.targets)


def initialize(interp: 'Interpreter') -> ExternalProjectModule:
    return ExternalProjectModule(interp)
```