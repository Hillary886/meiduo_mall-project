import logging

from django.core.mail import send_mail
from django.conf import settings
from celery_tasks.main import celery_app




logger=logging.getLogger('django')

# bind:保证task对象会作为第一个参数自动传入
# name:异步任务的别名
# retry_backoff:异常自动重试的时间间隔，第n 次(retry_backoff*2^(n-1))s
# max_retries:异常自动重试次数的上限
@celery_app.task(bind=True,name='send_verify_email',retry_backoff=3)
def send_verify_email(self,email,verify_url):
    """定义发送邮件的任务"""
    # send_mail('标题','普通邮件的正文','发件人','收件人列表','富文本邮件正文html'),
    # 我们因为要发h标签和a标签，所以要用富文本而不是普通文本

    subject = "美多商城邮箱验证"
    html_message = '<p>尊敬的用户您好！</p>' \
                   '<p>感谢您使用美多商城。</p>' \
                   '<p>您的邮箱为：%s 。请点击此链接激活您的邮箱：</p>' \
                   '<p><a href="%s">%s<a></p>' % (email, verify_url, verify_url)
    try:
        send_mail(
        subject=subject,
        message='',
        from_email=settings.EMAIL_FROM,
        recipient_list=[email],
         html_message=html_message)
    except Exception as e:
        logger.error(e)
        # 触发错误重试：最多重试三次
        raise self.retry(exc=e,max_retries=3)
