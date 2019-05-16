## 腾讯 WiFi设备一键配网协议

# 启用(in rt-thread)
```
//rtconfig.h

#define PKG_USING_AIRKISS_OPEN
#define AIRKISS_OPEN_DEMO_ENABLE /* airkiss应用示例 */
```

# 示例
- [在rt-thread中应用](osdep/rtthread/airkiss_demo.c)
- [电脑模拟测试](osdep/qt/akWorker.cpp)

# 参考
- [博客文章](https://blog.csdn.net/lb5761311/article/details/77945848)

# 测试结果
- [报告](doc/test-report.md)
