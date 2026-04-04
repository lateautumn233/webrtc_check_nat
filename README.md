# 使用方法

### 依赖

- aiohttp

### 主节点（同时托管HTML）

```bash
python natcheck.py --mode primary --port 8080 --secondary-url http://<辅助节点的IP>:8081
```

### 辅助节点（必须！）

```bash
python natcheck.py --mode secondary --port 8081
```
