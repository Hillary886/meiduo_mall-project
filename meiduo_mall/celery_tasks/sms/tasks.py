# 定义任务，这个文件名字必须加tasks
from celery_tasks.main import celery_app
from celery_tasks.sms import constants
from celery_tasks.sms.constants import SEND_SMS_TEMPLATE_ID
from celery_tasks.sms.yuntongxun.ccp_sms import CCP

# 使用装饰器装饰异步的任务，保证celery识别任务，这个编码是固定模式,如果不命名的话name默认的名字很长
@celery_app.task(name='send_sms_code')
def send_sms_code(mobile,sms_code):
    '''发送短信验证码的异步任务
    mobile:手机号
    sms_code:短信验证码
    return：成功 0 失败 -1
    '''

    send_ret=CCP().send_template_sms(mobile, [sms_code, constants.SMS_CODE_REDIS_EXPIRES // 60], SEND_SMS_TEMPLATE_ID)
    return send_ret