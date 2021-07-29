from django import http
from django.contrib.auth.mixins import LoginRequiredMixin

from meiduo_mall.utils.response_code import RETCODE


class LoginRequiredJSONMixin(LoginRequiredMixin):
    """自定义判断用户是否登录的扩展类：返回json"""
    # 为什么只需要写handle_no_permission?因为判断用户是否登录的操作，父类已经完成
    # 子类只需要关心如果用户未登录对应怎样的操作
    def handle_no_permission(self):
        """直接响应JSON数据"""
        return http.JsonResponse({'code':RETCODE.SESSIONERR,'errmsg':'用户未登录'})
