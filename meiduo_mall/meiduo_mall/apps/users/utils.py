# 自定义用户认证的后端:实现多账号登录
from django.contrib.auth.backends import ModelBackend
import re
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer, BadData
from users.models import User
from django.conf import settings
from . import constants
def check_verify_email_token(token):
    """
    反序列化token,获取到user
    :param token: 序列化后的用户信息
    :return: user
    """
    s = Serializer(settings.SECRET_KEY, constants.VERIFY_EMAIL_TOKEN_EXPIRES)
    try:
        data=s.loads(token)
    except BadData:
        return None
    else:
        # 从data中取出user_id和email
        user_id=data.get('user_id')
        email = data.get('email')
        try:
            user=User.objects.get(id=user_id,email=email)
        except User.DoesNotExist:
            return None
        else:
            return user
def generate_verify_email_url(user):
    '''
    :param user: 当前登录的用户
    :return: token
    '''
    """生成商城邮箱激活链接"""
    s=Serializer(settings.SECRET_KEY,constants.VERIFY_EMAIL_TOKEN_EXPIRES)
    data={'user_id':user.id,'email':user.email}
    token=s.dumps(data)
    return settings.EMAIL_VERIFY_URL + '?token=' + token.decode()

def get_user_by_account(account):
    """
    通过账号获取用户
    :param account: 用户名或者手机号
    :return: user
    """
    try:
        if re.match(r'^1[3-9]\d{9}$', account):
            # username == 手机号
            user = User.objects.get(mobile=account)
        else:
            # username == 用户名
            user = User.objects.get(username=account)
    except User.DoesNotExist:
        return None
    else:
        return user


class UsernameMobileBackend(ModelBackend):
    '''自定义用户认证后端'''
    def authenticate(self, request, username=None, password=None, **kwargs):
        """
        重写用户认证方法
        :param username: 用户或者手机号
        :param password: 密码明文
        :param kwargs: 额外参数
        :return: user
        """
        # try:
        #     # is_superuser 判断是否是超级管理用户
        #     user=User.objects.get(username=username,is_superuser=True)
        # except:
        #     user=None
        #     return user
        # if user is not None and user.check_password(password):
        #     return user
        # 使用账号查询用户
        user=get_user_by_account(username)
        # 如果可以查询到用户，需要校验密码是否正确
        if user and user.check_password(password):
            # 返回user
            return user
        else:
            return None