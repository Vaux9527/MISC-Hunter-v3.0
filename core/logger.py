'''logger为Hunter的日志
    用于记录每一步的响应过程'''

from datetime import datetime
class Logger:
    def __init__(self,context):
        self.context = context

    def add_log(self,level,message):
        time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log = f"[{time}][{level}]  {message}"
        self.context.logs.append(log)


#封装函数
#他们将作为封装主添加函数的存在
#显性展示当前日志对应事件性质


    def info(self,message):
        self.add_log("INFO",message)

    def warning(self,message):
        self.add_log("WARNING",message)

    def error(self,message):
        self.add_log("ERROR",message)
