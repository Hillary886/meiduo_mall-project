import logging
import re

from django import http
from django.conf import settings
from django.contrib.auth import login
from django.db import DatabaseError
from django.shortcuts import render, redirect

# Create your views here.
from django.urls import reverse
from django.views import View

from QQLoginTool.QQtool import OAuthQQ
from django_redis import get_redis_connection

from meiduo_mall.utils.response_code import RETCODE
from oauth.utils import generate_access_token, check_access_token

# 创建日志输出器
from oauth.models import OAuthQQUser
from users.models import User

logger=logging.getLogger('django')


def merge_cart_cookie_to_redis(request, user, response):
    pass


class QQAuthUserView(View):
    """处理QQ登录回调：oauth_callback"""
    def get(self,request):
        """处理QQ回调的业务逻辑"""
        code=request.GET.get('code')
        if not code:
            return http.HttpResponseForbidden('获取code失败')

        # 创建工具对象
        oauth = OAuthQQ(client_id=settings.QQ_CLIENT_ID, client_secret=settings.QQ_CLIENT_SECRET,
                        redirect_uri=settings.QQ_REDIRECT_URI)
        try:
            # 使用code获取access_token
            access_token = oauth.get_access_token(code)

            # 使用access_token获取openid
            openid=oauth.get_open_id(access_token)
        except Exception as e:
            logger.error(e)
            return http.HttpResponseServerError("OAuth2.0认证失败")

        # 使用openid判断该QQ用户是否绑定过美多商城的用户
        # 以下try的方法和使用if 的相似
        try:
            oauth_user = OAuthQQUser.objects.get(openid=openid)
        except OAuthQQUser.DoesNotExist:
            # 如果openid没绑定美多商城用户
            access_token_openid=generate_access_token(openid)
            context={
                'access_token_openid':access_token_openid
            }
            return render(request,'oauth_callback.html',context)
        else:
            # 如果openid已绑定美多商城用户:oauth_user.user表示从QQ登陆的模型类对象中找到对应的用户模型类对象
            login(request,oauth_user.user)
            # 响应绑定结果
            next = request.GET.get('state')
            response = redirect(next)
            # 将用户名写到cookie中
            response.set_cookie('username', oauth_user.user.username, max_age=3600 * 24 * 15)
            # 响应QQ登陆
            return response

    def post(self, request):
        """美多商城用户绑定到openid"""
        # 接收参数
        mobile = request.POST.get('mobile')
        pwd = request.POST.get('password')
        sms_code_client = request.POST.get('sms_code')
        access_token = request.POST.get('access_token')

        # 校验参数
        # 判断参数是否齐全
        if not all([mobile, pwd, sms_code_client]):
            return http.HttpResponseForbidden('缺少必传参数')
        # 判断手机号是否合法
        if not re.match(r'^1[3-9]\d{9}$', mobile):
            return http.HttpResponseForbidden('请输入正确的手机号码')
        # 判断密码是否合格
        if not re.match(r'^[0-9A-Za-z]{8,20}$', pwd):
            return http.HttpResponseForbidden('请输入8-20位的密码')
        # 判断短信验证码是否一致
        redis_conn = get_redis_connection('verify_code')
        sms_code_server = redis_conn.get('sms_%s' % mobile)
        if sms_code_server is None:
            return render(request, 'oauth_callback.html', {'sms_code_errmsg': '无效的短信验证码'})
        if sms_code_client != sms_code_server.decode():
            return render(request, 'oauth_callback.html', {'sms_code_errmsg': '输入短信验证码有误'})
        # 判断openid是否有效：openid使用itsSerializer签名只有600秒的有效期
        # 判断openid是否有效：错误提示放在sms_code_errmsg位置
        openid = check_access_token(access_token)
        if not openid:
            return render(request, 'oauth_callback.html', {'openid_errmsg': '无效的openid'})

        # 保存注册数据
        try:
            user = User.objects.get(mobile=mobile)
        except User.DoesNotExist:
            # 用户不存在,新建用户
            user = User.objects.create_user(username=mobile, password=pwd, mobile=mobile)
        else:
            # 如果用户存在，检查用户密码
            if not user.check_password(pwd):
                return render(request, 'oauth_callback.html', {'account_errmsg': '用户名或密码错误'})

        # 将用户绑定openid
        try:
            oauth_qq_user=OAuthQQUser.objects.create(openid=openid, user=user)
        except Exception as e:
            logger.error(e)
            return render(request, 'oauth_callback.html', {'qq_login_errmsg': 'QQ登录失败'})

        # 实现状态保持
        login(request, oauth_qq_user.user)

        # 响应绑定结果
        next = request.GET.get('state')
        response = redirect(next)

        # 登录时用户名写入到cookie，有效期15天
        response.set_cookie('username', oauth_qq_user.user.username, max_age=3600 * 24 * 15)
        response = merge_cart_cookie_to_redis(request=request, user=user, response=response)
        return response
class QQAuthURLView(View):
    """提供qq登录扫码页面"""
    def get(self,request):
        # 接收参数next
        next=request.GET.get('next')

        # 创建工具对象
        oauth=OAuthQQ(client_id=settings.QQ_CLIENT_ID,client_secret=settings.QQ_CLIENT_SECRET,
                      redirect_uri=settings.QQ_REDIRECT_URI,state=next)
        # 生成QQ登录扫码链接地址
        login_url = oauth.get_qq_url()

        # 响应
        return http.JsonResponse({'code':RETCODE.OK,'errmsg':'OK','login_url':login_url})

'https://graph.qq.com/oauth2.0/authorize?response_type=code&client_id=101518219&redirect_uri=http%3A%2F%2Fwww.meiduo.site%3A8000%2Foauth_callback&state=%2F'