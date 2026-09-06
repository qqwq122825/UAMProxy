# v1.123.2 双设备模式数据回溯结果

数据源：本目录正常录制与`run_20260807_141324_613328`重放Live。

```text
录制：iPhone18,2 / 26.5.1 / 1.201.37114(82)
Live：iPad13,4 / 14.6 / 1.201.37114(82)
事件：364
录制池：151
```

## 继承：使用重放设备

此模式保留重放端iPad设备身份，设备专项规则继续进行同设备门控。

```text
PASS_NON_TARGET                   3
PASS_LIVE                       176
REPLACE                         185
SPECIAL_PASS_LIVE               112
DEVICE_CONTEXT_PASS_LIVE         71
CROSS_RECORD_SLOT_REPLACE         1
输出 iPad13,4                     70处
输出 iPhone18,2                    0处
CRC/长度/分片校验异常               0
```

分项：

```text
0x1007  SPECIAL_PASS_LIVE          4
0x1008  SPECIAL_PASS_LIVE         72
0x1009  SPECIAL_PASS_LIVE         24
0x100B  DEVICE_CONTEXT_PASS_LIVE  35
0x100C  SPECIAL_PASS_LIVE         12
0x100F  DEVICE_CONTEXT_PASS_LIVE  36
```

`tfp_called`命中正常`0x01122329`槽，保留Live序号及iPad设备字段。

## 替换：使用录制设备

连接锁定：

```text
template_session_id = 116.162.231.214#1786066391
model               = iPhone18,2
system_version      = 26.5.1
device_idfv         = 566345D1-8FC1-4AAF-AD4D-630C0E4F33DB
device_resolution   = 1320X2868
app_version         = 1.201.37114(82)
app_mach_uuid       = 66A585F8B0-4F34-E9BA-E4B6-FB2A8BBBDE
```

完整回溯：

```text
PASS_NON_TARGET                    3
PASS_LIVE                        134
REPLACE                          227
RECORDED_DEVICE_PROFILE           68个叶子
设备画像字段实际改写                 69个叶子
CROSS_RECORD_SLOT_REPLACE          1
输出 iPad13,4                       0处
输出 iPhone18,2                    70处
CRC/长度/分片校验异常                0
```

设备相关模板全部来自锁定录制会话：

```text
0x1007  SPECIAL_REPLACE_TEMPLATE_NEAREST   4
0x1008  SPECIAL_REPLACE_TEMPLATE_NEAREST  72
0x1009  SPECIAL_REPLACE_TEMPLATE_NEAREST  24
0x100B  SPECIAL_REPLACE_TEMPLATE_NEAREST  35
0x100C  SPECIAL_REPLACE_TEMPLATE_NEAREST  12
0x100F  SPECIAL_REPLACE_TEMPLATE_NEAREST  36
```

替换模式输出中没有发现`iPad13,4`；根设备字段、代码指纹、窗口树和探针均统一为录制
iPhone会话。账号、recordSequence、报告序号及`inc_id/obf_id`继续使用Live值。

## 回归测试

```text
python3 -m unittest discover -s tests
Ran 110 tests
OK (skipped=9)
```
