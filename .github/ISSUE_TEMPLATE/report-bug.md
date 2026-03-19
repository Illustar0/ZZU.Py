---
name: 报告 BUG
about: 报告一个 BUG
title: "[BUG]"
labels: bug
assignees: ''

---

**Bug 描述**
请清晰、简洁地描述 bug 的具体内容。

**复现步骤**
复现该问题的步骤：

**预期行为**
请清晰、简洁地描述您预期的行为。

**日志**
如果适用，请附上日志以帮助解释您的问题。
```python
# 启用 TRACE 日志
from loguru import logger
import sys

logger.remove()
logger.add(sys.stderr, level="TRACE")
logger.enable("zzupy")
```


**补充说明**
在此处添加任何关于该问题的其他说明。
