from django import http
from django.shortcuts import render
import random,logging
from django_redis import get_redis_connection
from . import constants
from meiduo_mall.utils.response_code import RETCODE
# Create your views here.
from django.views import View
from verifications.libs.captcha.captcha import captcha
from celery_tasks.sms.tasks import send_sms_code
from .constants import SEND_SMS_TEMPLATE_ID
from .libs.yuntongxun.ccp_sms import CCP

# 创建日志输出器
logger=logging.getLogger('django')
class ImageCodeView(View):
    '''图形验证码'''
    def get(self,requset,uuid):
        '''

        :param requset:
        :param uuid: 通用唯一识别码，用于唯一标识图形验证码属于哪个用户的
        :return: image/ipg
        '''
        # 接收和校验参数：做完了
        # 实现主体业务逻辑：生成，保存，响应图形验证码
        # 1.1生成图形验证码
        text,image=captcha.generate_captcha()
        # 1.2保存图形验证码,如果不传，默认的是redis 0号库
        redis_conn=get_redis_connection("verify_code")
        # redis_conn.setex("key","expire","value")
        # 数字是魔法数字，有很多不确定性，很忌讳之后修改源代码
        redis_conn.setex('img_%s'%uuid,constants.SMS_CODE_REDIS_EXPIRES,text)
        # 1.3响应图形和验证码
        return http.HttpResponse(image,content_type='image/ipg')
        # 响应结果

class SMSCodeView(View):
    '''短信验证码'''
    def get(self,request,mobile):
        '''
        :param mobile: 手机号
        :return: json
        '''
        # 接收参数,其中uuid和image_code则设置为查询字符串参数，如果都设置为路径参数，则路径参数非常长
        image_code_client=request.GET.get('image_code')
        uuid=request.GET.get('uuid')

        # 校验参数
        if not all([image_code_client,uuid]):
            # 这个指令是不能进入到then的
            return http.HttpResponseForbidden('缺少必传参数')
        # 实现主体业务逻辑

        # 提取图形验证码
        redis_conn = get_redis_connection("verify_code")
        image_code_server=redis_conn.get('img_%s'%uuid)
        if image_code_server is None:
            return http.JsonResponse({"code":RETCODE.IMAGECODEERR,"errmsg":"图形验证码已失效"})
        # 删除图形验证码
        redis_conn.delete('img_%s'%uuid)
        # 对比图形验证码，python3对比python2进行了优化，对于存入和取出的数据都变成bytes类型
        image_code_server=image_code_server.decode()# 将bytes 转成字符串，再比较
        if image_code_client.lower() != image_code_server.lower(): # 转小写再比较
            return http.JsonResponse({"code": RETCODE.IMAGECODEERR, "errmsg": "输入图形验证码有误"})
        # 生成短信验证码, 随机6位数字,000007
        sms_code='%06d'%random.randint(0,999999)
        logger.info(sms_code) # 手动输出日志，输出短信验证码
        # 保存短信验证码
        redis_conn.setex('sms_%s' % mobile, constants.SMS_CODE_REDIS_EXPIRES, sms_code)
        # 发送短信验证码//是取整方法，否则是浮点数5.0
        # t=CCP().send_template_sms(mobile, [sms_code, constants.SMS_CODE_REDIS_EXPIRES//60], SEND_SMS_TEMPLATE_ID)
        # print(t)
        # 使用celery发送短信验证码
        # send_sms_code(mobile,sms_code) # 错误的写法
        send_sms_code.delay(mobile, sms_code) # 千万不要忘记写delay
        # 响应结果
        return http.JsonResponse({"code":RETCODE.OK,"errmsg":"短信发送成功"})
