'''context的职能在于:其在多个功能文件互相导出数据且相互需要时
    不用一对一传(这将导致代码冗余且降低可读性)
    context将会作为一个“中央数据库”
    这样各个功能只需要来这里存取文件'''


class AnalysisContext:
    """
    MISC Hunter 分析上下文
    用于保存一次文件分析过程中产生的所有信息。
    """
    def __init__(self,target):
        self.target = target        #当前目标文件
        self.findings = []          #发现的问题
        self.extracted_files = []   #提取的文件
        self.logs = []              #分析日志

    def add_finding(self,code,message,severity="INFO",data=None):

        finding = {
            "code" : code,
            "message" : message,
            "severity" : severity,
            "data" : data
        }

        self.findings.append(finding)