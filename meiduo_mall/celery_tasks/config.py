# Celery 配置文件

# 指定中间人，消息队列，任务队列，容器，使用Redis数据库
broker_url= 'redis://192.168.206.134:6379/10'
# broker_url= 'redis://127.0.0.1:6379/10'
from celery import Celery
# print('咋')
# app = Celery('pro', backend='redis://192.168.206.132:6379/9', broker='redis://192.168.206.132:6379/10')

# app = Celery('pro', backend='redis://localhost:6379/1', broker='redis://localhost:6379/0')

