import re

from django import http
from django.contrib.auth import login, authenticate, logout
# from django.contrib.auth.models import User
from django.contrib.auth.mixins import LoginRequiredMixin

from users.models import User
from django.db import DatabaseError
from django.http import HttpResponse
from django.shortcuts import render, redirect

# Create your views here.
from django.urls import reverse
from django.views import View

from meiduo_mall.utils.response_code import RETCODE


class UserInfoView(LoginRequiredMixin,View):
    '''用户中心'''
    def get(self,request):
        """提供用户中心的页面"""
        # if request.user.is_authenticated:
        #     return render(request,'user_center_info.html')
        # else:
        #     return redirect(reverse('users:login'))
        # 如果LoginRequiredMixin判断出用户已经登录，那么request.user就是登录用户的对象
        # 需要传递两个属性，login_url='/login/',redirect_field_name='redirect_to'
        context={
            'username':request.user.username,
            'mobile':request.user.mobile,
            'email':request.user.email,
            'email_active':request.user.email_active
        }

        return render(request, 'user_center_info.html',context)

class LogoutView(View):
    '''用户退出登录'''
    def get(self,request):
        """实现用户退出登录的逻辑"""
        # 清除状态保持信息
        logout(request)

        # 退出登录后重定向到首页
        response=redirect(reverse('contents:index'))

        # 删除cookie中的用户名
        response.delete_cookie('username')
        # 响应结果
        return response

class LoginView(View):
    '''用户的登录'''
    def get(self,request):
        '''提供用户登录页面'''
        return render(request,'login.html')
    def post(self,request):
        '''实现用户登录逻辑'''
        # 接收参数
        username=request.POST.get('username')
        password=request.POST.get('password')
        remembered=request.POST.get('remembered')
        # 校验参数
        if not all ([username,password]):
            return http.HttpResponseForbidden('缺少必传参数')
        # 判断用户名是否5-20个字符
        if not re.match(r'^[a-zA-Z0-9_-]{5,20}$', username):
            return http.HttpResponseForbidden('请输入5-20个字符的用户名')

        # 判断密码是否是8-20个字符
        if not re.match(r'^[0-9A-Za-z]{8,20}$', password):
            return http.HttpResponseForbidden('请输入8-20位的密码')
        # 认证用户:使用账号查询用户是否存在,如果用户存在，再去校验密码是否正确
        user=authenticate(username=username,password=password)
        # HttpResponseForbidden是响应403,一般在参数错误的时候才会响应403
        # json一般不在post 表单递交时反应
        if user is None:
            return render(request,'login.html',{'account_errmsg':'账号或密码错误'})
        # 状态保持
        login(request,user)
        # 使用remember确定状态保持周期(实现记住登录)
        if remembered !='on':
            # 没有记住登录，状态保持在浏览器会话结束就销毁
            request.session.set_expiry(0)
        else:
            # 记住登录，状态保持信息周期为两周,默认是两周，单位是秒,3600秒
            request.session.set_expiry(None)

        # 响应结果
        # 先取出next
        next=request.GET.get('next')
        if next:
            # 重定向到next
            response=redirect(next)
        else:
            # 重定向到首页
            response = redirect(reverse('contents:index'))
        # 为了实现在首页的右上角展示用户名信息，我们需要将用户名缓存到cookie中
        # response.set_cookie('key','val','expiry')
        response.set_cookie('username',user.username,max_age=3600*24*15)

        # 用户登录成功,合并ccokie购物车到redis购物车
        # merge_cart_cookies_redis(request=request,user=user,response=response)

        return response

class UsernameCountView(View):
    '''判断用户名是否重复注册'''
    def get(self,request,username):
        '''
        :param username: 用户名
        :return: JSON
        '''
        # 接收和校验参数已经由路径参数完成，传递的username已经被传入到get()中
        # 要实现主体业务逻辑：使用username查询对应的记录的条数(filter返回的是满足条件的结果集)
        count=User.objects.filter(username=username).count()
        # "code":"","errmsg":"","count":count 这三个参数是后台规定好的
        # 响应结果
        return http.JsonResponse({"code":RETCODE.OK,"errmsg":"OK","count":count})

class MobileCountView(View):
    def get(self,request,mobile):
        count=User.objects.filter(mobile=mobile).count()
        return http.JsonResponse({"code":RETCODE.OK,"errmsg":"OK","count":count})
class RegisterView(View):
    '''这里是用户的注册'''
    # get一般涉及用户向后端索取数据的行为
    def get(self,request):
        '''提供用户注册页面的,render的第一个参数shi request,第二个是html '''
        return render(request,'register.html')
    def post(self,request):
        '''实现用户注册的业务逻辑'''
        # 第一步：接收参数(表单数据)
        username=request.POST.get('username')
        password=request.POST.get('password')
        password2=request.POST.get('password2')
        mobile=request.POST.get('mobile')
        allow=request.POST.get('allow')

        # 第二步：校验参数:前后端的校验需要分开，避免恶意用户越过前端逻辑发请求，要保证后端的安全,前后端的校验逻辑要相同
        # 判断参数是否齐全all([列表])：会去校验列表中的元素是否为空，只要有一个为空，返回false
        if not all([username,password,password2,mobile,allow]):
            # '如果缺少必传参数，响应错误提示信息，403'
            return http.HttpResponseForbidden('缺少必传参数，也可不写')

        # 判断用户名是否5-20个字符
        if not re.match(r'^[a-zA-Z0-9_-]{5,20}$',username):
            return http.HttpResponseForbidden('请输入5-20个字符的用户名')

        # 判断密码是否是8-20个字符
        if not re.match(r'^[0-9A-Za-z]{8,20}$', password):
            return http.HttpResponseForbidden('请输入8-20位的密码')
        # 判断两次输入的密码是否一致
        if password != password2:
            return http.HttpResponseForbidden('两次输入的密码不一致')
        # 判断手机号是否合法
        if not re.match(r'^1[3-9]\d{9}$', mobile):
            return http.HttpResponseForbidden('请输入正确的手机号码')
        # 判断用户是否勾选协议

        # 判断是否勾选用户协议
        if allow != 'on':
            return http.HttpResponseForbidden('请勾选用户协议')


        # # 第三步：保存注册数据(是注册业务的核心)
        # return render(request, 'register.html', {'register_errmsg': '注册失败'})
        try:
            user=User.objects.create_user(username=username,password=password,mobile=mobile)
            # 内部源码：user=self.model(username=username,email=email,**extra_fields)
            # 相当于user=User(username=username,email=email,**extra_fields)
        except DatabaseError:
            return render(request,'register.html',{'register_errmsg':'注册失败'})
        # 实现状态保持
        login(request,user)
        # # 第四步：响应结果
        # return HttpResponse('注册成功，重定向到首页')
        # return redirect('/')
        # reverse('contents:index')=='/'



        # 响应结果:重定向到首页
        response = redirect(reverse('contents:index'))
        # 为了实现在首页的右上角展示用户名信息，我们需要将用户名缓存到cookie中
        # response.set_cookie('key','val','expiry')
        response.set_cookie('username', user.username, max_age=3600 * 24 * 15)
        return response

