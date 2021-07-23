# Celery的入口文件
from celery import Celery


# 为celery使用django配置文件进行设置
import os
if not os.getenv('DJANGO_SETTINGS_MODULE'):
    os.environ['DJANGO_SETTINGS_MODULE'] = 'meiduo_mall.settings.dev'



# 创建celery实例,这个celery的实例就是生产者，这个meiduo的名字可以传也可以不传
celery_app=Celery("meiduo",broker='redis://192.168.206.134:6379/10')

# 加载配置
celery_app.config_from_object('celery_tasks.config')

# 注册任务,列表里面放任务包所在的位置,必须以字符串的形式传入
celery_app.autodiscover_tasks(['celery_tasks.sms','celery_tasks.email'])





