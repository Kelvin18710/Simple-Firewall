# 简易防火墙

这个简易防火墙是一个基于Python的图形用户界面(GUI)应用程序，旨在帮助管理网络访问并提供基本的安全控制。它允许用户配置黑名单和白名单，控制允许或阻止特定IP地址的访问，并提供服务器启动和关闭功能。

## 功能说明

1. **黑名单与白名单配置**: 用户可以添加IP地址到黑名单或白名单中，以控制这些IP地址的访问权限。
2. **动态启用/禁用**: 可以灵活启用或禁用黑名单和白名单，根据网络需求进行配置变更。
3. **实时服务器信息显示**: 提供实时显示服务器状态、IP地址和端口号等信息。
4. **服务器控制**: 允许用户启动和关闭服务器，以便监视和管理网络访问。

## 使用说明

1. **添加到黑名单/白名单**: 输入要添加到黑名单或白名单的IP地址，然后点击相应的按钮进行添加。
2. **批量删除**: 选中要删除的IP地址，然后点击“批量删除”按钮以删除选定的IP地址。
3. **启动/关闭服务器**: 点击“启动服务器”按钮以启动服务器，点击“关闭服务器”按钮以关闭服务器。
4. **启用/禁用黑名单/白名单**: 点击“启用黑名单”或“启用白名单”按钮以启用相应的名单，并可以随时切换。

## 如何运行

确保您的环境中已经安装了Python，并且拥有`tkinter`库。

运行main.py以启动应用程序：

## 注意事项

- 该防火墙应用程序仅限于简单的网络安全管理，不适用于高级或生产环境。
- 在配置防火墙规则时，请确保了解您的网络环境和安全需求。
- 本程序仅提供基本的IP地址过滤功能，不涉及深层次的数据包检查或防火墙规则优化。
