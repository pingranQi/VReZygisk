# ReZygisk

[English](../README.md) | [简体中文](../README.md#简体中文)

ReZygisk 是从 Zygisk Next 分支出来的 Zygisk API 独立实现，为 **KernelSU、APatch 和 Magisk** 提供 Zygisk 兼容支持。

项目使用 C 语言实现，并引入自定义链接器以减少对系统链接器的依赖。ReZygisk 以轻量化和代码可审计性为设计目标。

## 功能特性

- 独立实现 Zygisk API。
- 兼容 KernelSU、APatch 和 Magisk。
- 仅支持 ARM64 架构（**arm64-v8a**）。
- 支持自定义链接器。
- Root 管理器的模块描述会显示运行状态和检测到的 Zygisk 模块名称。
- 不包含 WebUI。

## 兼容性

| 项目 | 支持情况 |
|---|---|
| ABI | 仅 ARM64（arm64-v8a） |
| KernelSU | 支持 |
| APatch | 支持 |
| Magisk | 支持，但必须关闭内置 Zygisk |
| ARM 32 位 / x86 / x86_64 | 不支持 |

构建系统和安装脚本会拒绝非 ARM64 目标。ptracer 仅使用 AArch64 寄存器布局，并且只支持向 64 位 Zygote 注入。

## 安装

1. 从项目的 [GitHub Actions](https://github.com/pingranQi/VReZygisk/actions) 构建产物或正式发布页面下载最新的 **Release** ZIP。
   - **Release**：日常使用推荐版本，启用二进制优化并减少日志输出。
   - **Debug**：包含更详细的日志，仅建议用于问题排查。
2. 打开 KernelSU、APatch 或 Magisk 的“模块”页面，选择 ZIP 文件并安装。
3. 如果使用 Magisk，必须关闭 Magisk 内置的 **Zygisk**，避免发生冲突。
4. 重启设备。

## 验证安装

重启后，在 Root 管理器的模块描述中检查 ReZygisk 的运行状态。描述会显示 monitor 和 64 位 Zygisk 状态，例如：

**[Monitor: ✅, ReZygisk 64-bit: ✅] Standalone implementation of Zygisk.**

具体状态文本可能随运行状态变化。

## 构建

**所需工具链：** Android NDK。

项目构建配置仅面向 **arm64-v8a**。如果尝试选择其他 ABI，构建系统会直接拒绝。

第三方 Native 依赖：

| 依赖项 | 用途 |
|---|---|
| PLTI | Android PLT Hook |
| CSOLoader | Linux 自定义链接器 |

## 故障排查

- **Magisk 提示 Zygisk 冲突：** 关闭 Magisk 内置 Zygisk，然后重启设备。
- **模块描述未显示 monitor 正常运行：** 检查模块安装日志和 Android 日志中的启动错误。
- **Zygisk 模块无法加载：** 确认目标模块支持 64 位进程，并检查 ReZygisk Debug 版本的日志。
- **安装时提示 ABI 不受支持：** 当前构建仅支持 ARM64 设备。

## KernelSU Late Load

KernelSU Late Load 通过 `late-load.sh` 启动 monitor，并请求 init 重新启动 Zygote，使 monitor 能够捕获新的 fork/exec 注入入口。

## 许可证

ReZygisk 使用 [AGPL-3.0](../LICENSE) 许可证。许可证详情参见 [Open Source Initiative](https://opensource.org/license/agpl-v3/)。
