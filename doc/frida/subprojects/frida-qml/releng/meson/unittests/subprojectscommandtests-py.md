Response:
Let's break down the thought process for analyzing this Python code and fulfilling the request.

**1. Understanding the Goal:**

The primary goal is to analyze the provided Python code (`subprojectscommandtests.py`) and explain its functionality in the context of Frida, reverse engineering, low-level details, logic, common user errors, and debugging. This requires more than just reading the code; it requires understanding its purpose and how it interacts with the larger Frida ecosystem (even if indirectly).

**2. Initial Skim and Keyword Identification:**

First, I'd skim the code looking for important keywords and patterns. Things that immediately jump out:

* **`frida` in the filename:** This immediately links it to the Frida project.
* **`meson`:**  This indicates the build system being used. Understanding Meson's role in managing dependencies and subprojects is crucial.
* **`unittests`:**  This tells us the code is for testing, not core functionality. It tests how Meson handles subprojects.
* **`SubprojectsCommandTests`:** The class name clearly indicates the focus of the tests.
* **`setUp`, `test_*` methods:**  Standard unittest structure.
* **`_git`, `_wrap_create_*` methods:** Helper functions likely dealing with Git and wrap files (Meson's way of managing external dependencies).
* **`download`, `update`, `foreach`, `purge`:** These are the subcommands being tested.

**3. Deciphering the Functionality:**

Knowing it's a test suite for Meson's subprojects command, the next step is to understand what each test case verifies. I'd go through each `test_*` method:

* **`test_git_update`:** This method clearly tests the `meson subprojects download` and `meson subprojects update` commands, focusing on Git repositories. It covers scenarios like checking out branches, handling local changes, and dealing with tags and specific commits.
* **`test_foreach`:** This tests the `meson subprojects foreach` command, verifying it correctly iterates through different types of subprojects (Git repositories and file-based dependencies) and executes commands within them.
* **`test_purge`:** This tests the `meson subprojects purge` command, confirming it removes subproject directories and optionally clears the package cache.

**4. Connecting to Reverse Engineering (The "Frida Angle"):**

This is where the connection to Frida needs to be made. While this specific file *doesn't directly perform reverse engineering*, it plays a vital role in *managing the dependencies* that Frida itself might rely on, or that Frida *extensions* or *tools* might use.

* **Frida's reliance on libraries:** Frida, as a dynamic instrumentation tool, often needs to interact with various system libraries or have specific dependencies. Meson's subproject management helps ensure these dependencies are correctly fetched and built.
* **Extension/Tool development:** Developers creating Frida extensions might use Meson to manage their own project dependencies. Understanding how Meson handles subprojects is essential for them.

**5. Connecting to Low-Level Details (Kernel, Android):**

Again, this test file itself isn't directly manipulating kernel code or Android frameworks. However, the *purpose* of Frida is deeply intertwined with these low-level concepts.

* **Frida's target:** Frida often targets processes running on Linux, Android, etc. Understanding how to manage the build process for tools that will interact with these operating systems is important.
* **Dependency management:** Some of the dependencies managed by Meson (through these subproject commands) could be libraries that interact directly with the kernel or Android frameworks.

**6. Logical Reasoning and Input/Output Examples:**

For each test case, I'd consider what inputs are being set up and what the expected outputs are. This helps solidify understanding:

* **`test_git_update`:**  Input: Creation of remote Git repos, wrap files with different revisions. Output: Local Git repos are correctly cloned/updated to the specified revision.
* **`test_foreach`:** Input: Different types of subprojects. Output: The `true` command is executed in the correct subproject directories.
* **`test_purge`:** Input: Existing subproject directories and cached files. Output: These directories and files are deleted.

**7. Identifying User Errors:**

This requires thinking about how a user might misuse these commands or set up their project incorrectly:

* **Incorrect wrap file configuration:**  Specifying a non-existent Git repository or an incorrect revision in the wrap file.
* **Trying to update a non-Git subproject without `--reset`:**  This is explicitly tested and highlights a common mistake.
* **Conflicts between local changes and remote updates:**  The test covers how Meson handles this (stashing), but users might be surprised by this behavior if they don't understand Git.

**8. Tracing User Operations (Debugging):**

To understand how a user might end up interacting with this code, I'd think about the typical Frida development workflow:

1. **Installing Frida:** While not directly related to this file, it's the starting point.
2. **Developing a Frida script or extension:**  This might involve creating a new project with dependencies.
3. **Using Meson to build the project:**  This is where the `meson subprojects` commands come into play.
4. **Encountering issues with dependencies:**  If a dependency isn't found or needs to be updated, the user might manually run `meson subprojects download` or `meson subprojects update`.
5. **Cleaning up the project:**  A user might use `meson subprojects purge` to remove downloaded dependencies.

**9. Structuring the Answer:**

Finally, I'd organize the information into clear sections based on the prompt's requirements (functionality, reverse engineering, low-level details, logic, user errors, debugging). Using bullet points and code examples helps make the explanation easier to understand. It's also important to highlight the *indirect* relationship of this test file to Frida's core functionality.

**Self-Correction/Refinement during the process:**

* **Initial thought:** This file directly does reverse engineering.
* **Correction:**  No, it's a test file for Meson's subproject management. It *supports* the development of tools that do reverse engineering.
* **Initial thought:** Focus only on the positive cases.
* **Correction:** Need to also consider potential user errors and how the tests cover error scenarios.
* **Initial thought:**  Explain each line of code.
* **Correction:** Focus on the higher-level functionality and the *purpose* of the tests rather than getting bogged down in implementation details (unless specifically relevant).

By following this thought process, combining code analysis with an understanding of the surrounding ecosystem, I can generate a comprehensive and accurate explanation of the provided Python code.
这个Python源代码文件 `subprojectscommandtests.py` 是 Frida 动态 instrumentation 工具项目 `frida` 中 `frida-qml` 子项目的测试文件。它专门测试 Meson 构建系统中关于子项目管理的命令行工具的功能。更具体地说，它测试了 `meson subprojects` 命令及其各种子命令的行为。

以下是它的功能列表，以及与逆向、底层、用户错误和调试线索相关的说明：

**功能列表：**

1. **`test_git_update()`:** 测试 `meson subprojects download` 和 `meson subprojects update` 命令针对 Git 仓库子项目的行为。它涵盖了以下场景：
   - 下载新的 Git 子项目。
   - 更新 Git 子项目到新的分支。
   - 更新 Git 子项目，即使本地有未提交的更改（验证是否会 stash）。
   - 更新 Git 子项目到特定的标签或 commit ID。
   - 当本地项目不是 Git 仓库时更新 Git 子项目。
   - 下载带有 `depth` 限制的 Git 子项目。

2. **`test_foreach()`:** 测试 `meson subprojects foreach` 命令，该命令允许在每个子项目中执行指定的命令。它测试了以下功能：
   - 在所有类型的子项目中执行命令。
   - 使用 `--types` 参数限制在特定类型的子项目中执行命令（例如，只在 Git 子项目或文件子项目中执行）。

3. **`test_purge()`:** 测试 `meson subprojects purge` 命令，该命令用于删除子项目。它测试了以下功能：
   - 删除子项目目录。
   - 使用 `--include-cache` 参数删除子项目缓存。
   - 使用 `--confirm` 参数进行确认删除。
   - 处理通过 `wrap-redirect` 指向的子项目。

**与逆向的方法的关系及举例说明：**

虽然这个文件本身不是直接进行逆向工程的代码，但它测试的工具是逆向工程流程中重要的一环。Frida 被广泛用于动态分析和修改目标进程的行为。

**举例说明：**

假设你正在逆向一个使用了多个第三方库的 Android 应用程序。这些第三方库可能作为子项目被包含在应用程序的构建系统中（如果开发者使用了像 Meson 这样的构建工具）。

1. **`meson subprojects download`:** 当你首次配置 Frida 环境并尝试构建一个依赖于这些第三方库的 Frida 脚本时，Meson 可能需要下载这些子项目。`test_git_update()` 确保了下载 Git 仓库作为子项目的功能正常。

2. **`meson subprojects update`:** 如果第三方库有更新，你可以使用 `meson subprojects update` 来获取最新的代码。`test_git_update()` 确保了更新子项目到最新版本的功能正常，这对于保持你的逆向环境与目标应用程序所使用的库版本同步非常重要。

3. **`meson subprojects foreach`:**  你可能需要对所有子项目执行一些操作，例如运行特定的静态分析工具或检查特定文件是否存在。`test_foreach()` 确保了在多个子项目上批量执行命令的功能正常。

4. **`meson subprojects purge`:** 当你不再需要某些子项目或者想清理构建环境时，可以使用 `meson subprojects purge` 删除它们。`test_purge()` 确保了清理子项目的功能正常。

**涉及到二进制底层，Linux, Android内核及框架的知识及举例说明：**

这个测试文件本身并不直接操作二进制底层或内核。然而，它所测试的 Meson 构建系统以及 Frida 工具链最终会涉及到这些层面。

**举例说明：**

1. **二进制底层:**  当 Frida attach 到一个进程并进行 instrumentation 时，它会修改目标进程的内存中的二进制代码。Meson 构建系统需要正确地编译和链接 Frida 自身以及相关的组件，生成能够在目标平台上运行的二进制文件。测试子项目管理确保了构建过程中依赖的库能够正确地被获取和使用。

2. **Linux/Android 内核:** Frida 依赖于操作系统提供的 API 来进行进程注入、内存读写等操作。在 Linux 和 Android 上，这涉及到系统调用和内核接口。Meson 构建的 Frida 组件需要能够与这些内核接口正确交互。虽然这个测试文件没有直接测试内核交互，但它确保了构建过程的正确性，这是 Frida 能够正常工作的先决条件。

3. **Android 框架:** 在 Android 平台上进行逆向时，经常需要与 Android 框架的各种服务和组件进行交互。Frida 脚本可能会 hook Android 框架的函数来分析其行为。Meson 构建的 Frida 工具链需要能够处理与 Android 框架相关的依赖和构建配置。

**逻辑推理及假设输入与输出：**

**`test_git_update()` 示例：**

**假设输入：**

- 一个名为 `sub1` 的远程 Git 仓库（`self.root_dir / 'sub1'`）。
- 一个指向该仓库的 `.wrap` 文件（`self.subprojects_dir / 'sub1.wrap'`)，初始指向 `master` 分支。

**操作：**

- 运行 `meson subprojects download`。
- 在远程仓库创建新的 `newbranch` 分支。
- 修改 `.wrap` 文件指向 `newbranch`。
- 运行 `meson subprojects update --reset`。

**预期输出：**

- 首次下载后，在 `self.subprojects_dir / 'sub1'` 目录下会存在一个本地 Git 仓库，且检出的分支为 `master`。
- 更新后，本地仓库检出的分支会变为 `newbranch`，并且本地的 commit ID 与远程 `newbranch` 的 commit ID 相同。

**`test_foreach()` 示例：**

**假设输入：**

- 存在一个文件类型的子项目 `sub_file`。
- 存在一个 Git 类型的子项目 `sub_git`。

**操作：**

- 运行 `meson subprojects foreach true`。

**预期输出：**

- 命令 `true` 会在 `subprojects/sub_file` 和 `subprojects/sub_git` 目录下分别执行一次。测试会检查输出中是否包含执行命令的路径信息。

**涉及用户或者编程常见的使用错误及举例说明：**

1. **在非 Git 仓库的子项目目录下尝试使用 `meson subprojects update` 更新 Git 子项目：**  用户可能手动创建了一个目录，然后尝试使用 wrap 文件将其更新为 Git 仓库。如果用户忘记使用 `--reset` 参数，Meson 会报错，因为本地目录不是一个 Git 仓库。

   **测试代码体现：** `test_git_update()` 中有相关测试用例，模拟了这种情况并验证了错误信息的输出。

2. **Wrap 文件配置错误：** 用户可能在 `.wrap` 文件中指定了不存在的 Git 仓库 URL 或 revision。这将导致 `meson subprojects download` 或 `meson subprojects update` 失败。虽然这个测试文件没有直接测试 wrap 文件配置错误，但这是用户在使用子项目功能时常见的错误。

3. **本地修改与远程更新冲突：** 用户可能在子项目中进行了本地修改但没有提交，然后尝试更新子项目。Meson 会尝试 stash 这些修改，但如果存在冲突，更新可能会失败。

   **测试代码体现：** `test_git_update()` 中测试了当本地有未提交更改时更新子项目的行为，验证了 stash 功能。

**说明用户操作是如何一步步的到达这里，作为调试线索：**

假设一个 Frida 用户在尝试构建一个依赖于某个 Git 仓库的 Frida 扩展时遇到了问题。以下是他们可能的操作步骤，最终可能需要查看这个测试文件以了解问题所在：

1. **创建 Frida 扩展项目：** 用户使用 Meson 初始化了一个新的 Frida 扩展项目，并在 `meson.build` 文件中声明了对一个 Git 仓库的依赖，通过 `.wrap` 文件指定。

2. **配置构建环境：** 用户运行 `meson setup build` 配置构建目录。在这个过程中，Meson 会读取 `.wrap` 文件并尝试下载子项目。

3. **遇到下载或更新问题：**
   - 如果 `.wrap` 文件配置错误，`meson setup` 可能会报错。
   - 如果网络连接有问题，下载可能会失败。
   - 如果远程仓库的 revision 不存在，更新可能会失败。

4. **尝试手动管理子项目：** 用户可能会尝试手动进入 `subprojects` 目录，并尝试使用 `git clone` 或 `git checkout` 来管理子项目。

5. **使用 `meson subprojects` 命令：** 为了解决问题，用户可能会查阅 Meson 的文档，了解可以使用 `meson subprojects` 命令来管理子项目。他们可能会尝试以下命令：
   - `meson subprojects download`: 尝试手动下载子项目。
   - `meson subprojects update`: 尝试更新子项目。
   - `meson subprojects foreach`: 尝试在子项目目录中执行命令来排查问题。
   - `meson subprojects purge`: 尝试清理子项目并重新下载。

6. **查看测试文件作为调试线索：** 如果用户在使用 `meson subprojects` 命令时遇到预期之外的行为，并且怀疑是 Meson 本身的问题，他们可能会查看 Meson 的源代码，特别是 `frida/subprojects/frida-qml/releng/meson/unittests/subprojectscommandtests.py` 这个测试文件。通过阅读测试用例，用户可以了解 `meson subprojects` 命令的预期行为，以及 Meson 开发人员是如何测试这些功能的。这有助于他们理解命令的正确用法，或者发现 Meson 本身的 Bug。例如，如果 `test_git_update()` 中覆盖了用户遇到的场景，但测试用例的预期行为与用户的实际观察不符，那么可能就发现了 Meson 的一个 Bug。

总而言之，`subprojectscommandtests.py` 是 Frida 项目中用于确保 Meson 子项目管理功能正确性的关键测试文件。虽然它不直接涉及逆向操作或底层内核交互，但它保证了构建系统的可靠性，这对于 Frida 工具链的正常工作至关重要，并且可以作为用户调试构建问题的参考。

### 提示词
```
这是目录为frida/subprojects/frida-qml/releng/meson/unittests/subprojectscommandtests.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```python
# SPDX-License-Identifier: Apache-2.0
# Copyright 2016-2021 The Meson development team

import subprocess
import tempfile
import textwrap
import os
from pathlib import Path
import typing as T

from mesonbuild.mesonlib import (
    version_compare, git, search_version
)



from .baseplatformtests import BasePlatformTests
from .helpers import *

class SubprojectsCommandTests(BasePlatformTests):
    def setUp(self):
        super().setUp()
        self.root_dir = Path(self.builddir)

        self.project_dir = self.root_dir / 'src'
        self._create_project(self.project_dir)

        self.subprojects_dir = self.project_dir / 'subprojects'
        os.makedirs(str(self.subprojects_dir))
        self.packagecache_dir = self.subprojects_dir / 'packagecache'
        os.makedirs(str(self.packagecache_dir))

    def _create_project(self, path, project_name='dummy'):
        os.makedirs(str(path), exist_ok=True)
        with open(str(path / 'meson.build'), 'w', encoding='utf-8') as f:
            f.write(f"project('{project_name}')")

    def _git(self, cmd, workdir):
        return git(cmd, str(workdir), check=True)[1].strip()

    def _git_config(self, workdir):
        self._git(['config', 'user.name', 'Meson Test'], workdir)
        self._git(['config', 'user.email', 'meson.test@example.com'], workdir)

    def _git_remote(self, cmd, name):
        return self._git(cmd, self.root_dir / name)

    def _git_local(self, cmd, name):
        return self._git(cmd, self.subprojects_dir / name)

    def _git_local_branch(self, name):
        # Same as `git branch --show-current` but compatible with older git version
        branch = self._git_local(['rev-parse', '--abbrev-ref', 'HEAD'], name)
        return branch if branch != 'HEAD' else ''

    def _git_local_commit(self, name, ref='HEAD'):
        return self._git_local(['rev-parse', ref], name)

    def _git_remote_commit(self, name, ref='HEAD'):
        return self._git_remote(['rev-parse', ref], name)

    def _git_create_repo(self, path):
        # If a user has git configuration init.defaultBranch set we want to override that
        with tempfile.TemporaryDirectory() as d:
            out = git(['--version'], str(d))[1]
        if version_compare(search_version(out), '>= 2.28'):
            extra_cmd = ['--initial-branch', 'master']
        else:
            extra_cmd = []

        self._create_project(path)
        self._git(['init'] + extra_cmd, path)
        self._git_config(path)
        self._git(['add', '.'], path)
        self._git(['commit', '--no-gpg-sign', '-m', 'Initial commit'], path)

    def _git_create_remote_repo(self, name):
        self._git_create_repo(self.root_dir / name)

    def _git_create_local_repo(self, name):
        self._git_create_repo(self.subprojects_dir / name)

    def _git_create_remote_commit(self, name, branch):
        self._git_remote(['checkout', branch], name)
        self._git_remote(['commit', '--no-gpg-sign', '--allow-empty', '-m', f'initial {branch} commit'], name)

    def _git_create_remote_branch(self, name, branch):
        self._git_remote(['checkout', '-b', branch], name)
        self._git_remote(['commit', '--no-gpg-sign', '--allow-empty', '-m', f'initial {branch} commit'], name)

    def _git_create_remote_tag(self, name, tag):
        self._git_remote(['commit', '--no-gpg-sign', '--allow-empty', '-m', f'tag {tag} commit'], name)
        self._git_remote(['tag', '--no-sign', tag], name)

    def _wrap_create_git(self, name, revision='master', depth=None):
        path = self.root_dir / name
        with open(str((self.subprojects_dir / name).with_suffix('.wrap')), 'w', encoding='utf-8') as f:
            if depth is None:
                depth_line = ''
            else:
                depth_line = 'depth = {}'.format(depth)
            f.write(textwrap.dedent(
                '''
                [wrap-git]
                url={}
                revision={}
                {}
                '''.format(os.path.abspath(str(path)), revision, depth_line)))

    def _wrap_create_file(self, name, tarball='dummy.tar.gz'):
        path = self.root_dir / tarball
        with open(str((self.subprojects_dir / name).with_suffix('.wrap')), 'w', encoding='utf-8') as f:
            f.write(textwrap.dedent(
                f'''
                [wrap-file]
                source_url={os.path.abspath(str(path))}
                source_filename={tarball}
                '''))
        Path(self.packagecache_dir / tarball).touch()

    def _subprojects_cmd(self, args):
        return self._run(self.meson_command + ['subprojects'] + args, workdir=str(self.project_dir))

    def test_git_update(self):
        subp_name = 'sub1'

        # Create a fake remote git repository and a wrap file. Checks that
        # "meson subprojects download" works.
        self._git_create_remote_repo(subp_name)
        self._wrap_create_git(subp_name)
        self._subprojects_cmd(['download'])
        self.assertPathExists(str(self.subprojects_dir / subp_name))
        self._git_config(self.subprojects_dir / subp_name)

        # Create a new remote branch and update the wrap file. Checks that
        # "meson subprojects update --reset" checkout the new branch.
        self._git_create_remote_branch(subp_name, 'newbranch')
        self._wrap_create_git(subp_name, 'newbranch')
        self._subprojects_cmd(['update', '--reset'])
        self.assertEqual(self._git_local_branch(subp_name), 'newbranch')
        self.assertEqual(self._git_local_commit(subp_name), self._git_remote_commit(subp_name, 'newbranch'))

        # Update remote newbranch. Checks the new commit is pulled into existing
        # local newbranch. Make sure it does not print spurious 'git stash' message.
        self._git_create_remote_commit(subp_name, 'newbranch')
        out = self._subprojects_cmd(['update', '--reset'])
        self.assertNotIn('No local changes to save', out)
        self.assertEqual(self._git_local_branch(subp_name), 'newbranch')
        self.assertEqual(self._git_local_commit(subp_name), self._git_remote_commit(subp_name, 'newbranch'))

        # Update remote newbranch and switch to another branch. Checks that it
        # switch current branch to newbranch and pull latest commit.
        self._git_local(['checkout', 'master'], subp_name)
        self._git_create_remote_commit(subp_name, 'newbranch')
        self._subprojects_cmd(['update', '--reset'])
        self.assertEqual(self._git_local_branch(subp_name), 'newbranch')
        self.assertEqual(self._git_local_commit(subp_name), self._git_remote_commit(subp_name, 'newbranch'))

        # Stage some local changes then update. Checks that local changes got
        # stashed.
        self._create_project(self.subprojects_dir / subp_name, 'new_project_name')
        self._git_local(['add', '.'], subp_name)
        self._git_create_remote_commit(subp_name, 'newbranch')
        self._subprojects_cmd(['update', '--reset'])
        self.assertEqual(self._git_local_branch(subp_name), 'newbranch')
        self.assertEqual(self._git_local_commit(subp_name), self._git_remote_commit(subp_name, 'newbranch'))
        self.assertTrue(self._git_local(['stash', 'list'], subp_name))

        # Untracked files need to be stashed too, or (re-)applying a patch
        # creating one of those untracked files will fail.
        untracked = self.subprojects_dir / subp_name / 'untracked.c'
        untracked.write_bytes(b'int main(void) { return 0; }')
        self._subprojects_cmd(['update', '--reset'])
        self.assertTrue(self._git_local(['stash', 'list'], subp_name))
        assert not untracked.exists()
        # Ensure it was indeed stashed, and we can get it back.
        self.assertTrue(self._git_local(['stash', 'pop'], subp_name))
        assert untracked.exists()

        # Create a new remote tag and update the wrap file. Checks that
        # "meson subprojects update --reset" checkout the new tag in detached mode.
        self._git_create_remote_tag(subp_name, 'newtag')
        self._wrap_create_git(subp_name, 'newtag')
        self._subprojects_cmd(['update', '--reset'])
        self.assertEqual(self._git_local_branch(subp_name), '')
        self.assertEqual(self._git_local_commit(subp_name), self._git_remote_commit(subp_name, 'newtag'))

        # Create a new remote commit and update the wrap file with the commit id.
        # Checks that "meson subprojects update --reset" checkout the new commit
        # in detached mode.
        self._git_local(['checkout', 'master'], subp_name)
        self._git_create_remote_commit(subp_name, 'newbranch')
        new_commit = self._git_remote(['rev-parse', 'HEAD'], subp_name)
        self._wrap_create_git(subp_name, new_commit)
        self._subprojects_cmd(['update', '--reset'])
        self.assertEqual(self._git_local_branch(subp_name), '')
        self.assertEqual(self._git_local_commit(subp_name), new_commit)

        # Create a local project not in a git repository, then update it with
        # a git wrap. Without --reset it should print error message and return
        # failure. With --reset it should delete existing project and clone the
        # new project.
        subp_name = 'sub2'
        self._create_project(self.subprojects_dir / subp_name)
        self._git_create_remote_repo(subp_name)
        self._wrap_create_git(subp_name)
        with self.assertRaises(subprocess.CalledProcessError) as cm:
            self._subprojects_cmd(['update'])
        self.assertIn('Not a git repository', cm.exception.output)
        self._subprojects_cmd(['update', '--reset'])
        self.assertEqual(self._git_local_commit(subp_name), self._git_remote_commit(subp_name))

        # Create a fake remote git repository and a wrap file targeting
        # HEAD and depth = 1. Checks that "meson subprojects download" works.
        subp_name = 'sub3'
        self._git_create_remote_repo(subp_name)
        self._wrap_create_git(subp_name, revision='head', depth='1')
        self._subprojects_cmd(['download'])
        self.assertPathExists(str(self.subprojects_dir / subp_name))
        self._git_config(self.subprojects_dir / subp_name)

    @skipIfNoExecutable('true')
    def test_foreach(self):
        self._create_project(self.subprojects_dir / 'sub_file')
        self._wrap_create_file('sub_file')
        self._git_create_local_repo('sub_git')
        self._wrap_create_git('sub_git')
        self._git_create_local_repo('sub_git_no_wrap')

        def ran_in(s):
            ret = []
            prefix = 'Executing command in '
            for l in s.splitlines():
                if l.startswith(prefix):
                    ret.append(l[len(prefix):])
            return sorted(ret)

        dummy_cmd = ['true']
        out = self._subprojects_cmd(['foreach'] + dummy_cmd)
        self.assertEqual(ran_in(out), sorted(['subprojects/sub_file', 'subprojects/sub_git', 'subprojects/sub_git_no_wrap']))
        out = self._subprojects_cmd(['foreach', '--types', 'git,file'] + dummy_cmd)
        self.assertEqual(ran_in(out), sorted(['subprojects/sub_file', 'subprojects/sub_git']))
        out = self._subprojects_cmd(['foreach', '--types', 'file'] + dummy_cmd)
        self.assertEqual(ran_in(out), ['subprojects/sub_file'])
        out = self._subprojects_cmd(['foreach', '--types', 'git'] + dummy_cmd)
        self.assertEqual(ran_in(out), ['subprojects/sub_git'])

    def test_purge(self):
        self._create_project(self.subprojects_dir / 'sub_file')
        self._wrap_create_file('sub_file')
        self._git_create_local_repo('sub_git')
        self._wrap_create_git('sub_git')

        sub_file_subprojects_dir = self.subprojects_dir / 'sub_file' / 'subprojects'
        sub_file_subprojects_dir.mkdir(exist_ok=True, parents=True)
        real_dir = Path('sub_file') / 'subprojects' / 'real'

        self._wrap_create_file(real_dir, tarball='dummy2.tar.gz')

        with open(str((self.subprojects_dir / 'redirect').with_suffix('.wrap')), 'w', encoding='utf-8') as f:
            f.write(textwrap.dedent(
                f'''
                [wrap-redirect]
                filename = {real_dir}.wrap
                '''))

        def deleting(s: str) -> T.List[str]:
            ret = []
            prefix = 'Deleting '
            for l in s.splitlines():
                if l.startswith(prefix):
                    ret.append(l[len(prefix):])
            return sorted(ret)

        out = self._subprojects_cmd(['purge'])
        self.assertEqual(deleting(out), sorted([
            str(self.subprojects_dir / 'redirect.wrap'),
            str(self.subprojects_dir / 'sub_file'),
            str(self.subprojects_dir / 'sub_git'),
        ]))
        out = self._subprojects_cmd(['purge', '--include-cache'])
        self.assertEqual(deleting(out), sorted([
            str(self.subprojects_dir / 'sub_git'),
            str(self.subprojects_dir / 'redirect.wrap'),
            str(self.subprojects_dir / 'packagecache' / 'dummy.tar.gz'),
            str(self.subprojects_dir / 'packagecache' / 'dummy2.tar.gz'),
            str(self.subprojects_dir / 'sub_file'),
        ]))
        out = self._subprojects_cmd(['purge', '--include-cache', '--confirm'])
        self.assertEqual(deleting(out), sorted([
            str(self.subprojects_dir / 'sub_git'),
            str(self.subprojects_dir / 'redirect.wrap'),
            str(self.subprojects_dir / 'packagecache' / 'dummy.tar.gz'),
            str(self.subprojects_dir / 'packagecache' / 'dummy2.tar.gz'),
            str(self.subprojects_dir / 'sub_file'),
        ]))
        self.assertFalse(Path(self.subprojects_dir / 'packagecache' / 'dummy.tar.gz').exists())
        self.assertFalse(Path(self.subprojects_dir / 'sub_file').exists())
        self.assertFalse(Path(self.subprojects_dir / 'sub_git').exists())
        self.assertFalse(Path(self.subprojects_dir / 'redirect.wrap').exists())
```