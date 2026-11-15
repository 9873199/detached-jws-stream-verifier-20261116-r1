独立验收在首轮结束后执行，未修改模型源码。使用Python3.14，先按acceptance-r1/dependency-lock.stdout.log安装依赖。以冻结产物仓库为工作目录并设置PYTHONPATH为仓库根目录，执行 python -m pytest -q jwcrypto/tests.py；再执行 python -m pytest -q verification/acceptance-r1/test_stream_contract.py。录屏中的 python demo.py 对应 verification/acceptance-r1/demo.py，展示真实冻结库调用。精确命令、解释器版本和各自stdout/stderr均随材料提供；本机绝对路径应替换成复现环境路径。

冻结产物提交：https://github.com/9873199/detached-jws-stream-verifier-20261116-r1/commit/f16de4a0bed2d6fa9cf5980f97131f576d452680
这些独立验收文件在模型首轮结束后生成，不是模型原轨中的测试。
