import json
import logging
import re

from django import http
from django.contrib.auth import login, authenticate, logout
# from django.contrib.auth.models import User
from django.contrib.auth.mixins import LoginRequiredMixin
from django_redis import get_redis_connection

from meiduo_mall.utils.views import LoginRequiredJSONMixin

from carts.utils import merge_cart_cookies_redis
from goods.models import SKU
from users.constants import USER_ADDRESS_COUNTS_LIMIT
from users.models import User, Address
from django.db import DatabaseError
from django.http import HttpResponse
from django.shortcuts import render, redirect

# Create your views here.
from django.urls import reverse
from django.views import View
from celery_tasks.email.tasks import send_verify_email
from meiduo_mall.utils.response_code import RETCODE

from users.utils import generate_verify_email_url, check_verify_email_token

logger=logging.getLogger('django')

# 字符串有text/plain,text/html,text/xml,text/json类型
class UserBrowseHistory(LoginRequiredJSONMixin,View):
    """用户浏览记录"""
    def post(self,request):
        """保存商品的浏览记录"""
        # 接收参数
        json_str=request.body.decode()
        json_dict=json.loads(json_str)
        sku_id=json_dict.get('sku_id')
        # 校验参数
        try:
            SKU.objects.get(id=sku_id)
        except SKU.DoesNotExist:
            return http.HttpResponseForbidden('参数sku_id有误')
        # 保存sku_id到redis
        redis_conn=get_redis_connection('history')
        user=request.user
        pl=redis_conn.pipeline()
        # 先去重
        pl.lrem('history_%s'% user.id,0,sku_id)
        # 再保存:最近浏览的商品在最前面
        pl.lpush('history_%s'% user.id,sku_id)
        # 最后截取Serializer
        pl.ltrim('history_%s' % user.id,0,4)

        # 执行
        pl.execute()
        # 响应结果
        return http.JsonResponse({'code':RETCODE.OK,'errmsg':'OK'})

    def get(self,request):
        """查询用户商品浏览记录"""
        # 获取登录用户信息
        user = request.user
        # 创建连接到redis对象
        redis_conn = get_redis_connection('history')
        # 取出列表数据(核心代码)
        sku_ids=redis_conn.lrange('history_%s'% user.id,0,-1) #(0,4)
        # 将模型转字典
        skus=[]
        for sku_id in sku_ids:
            sku=SKU.objects.get(id=sku_id)
            skus.append({
                'id':sku.id,
                'name':sku.name,
                'price':sku.price,
                'default_image_url':sku.default_image.url
            })
        return http.JsonResponse({'code':RETCODE.OK,'errmsg':'OK','skus':skus})
class ChangePasswordView(LoginRequiredMixin, View):
    """修改密码"""

    def get(self, request):
        """展示修改密码界面"""
        return render(request, 'user_center_password.html')

    def post(self, request):
        """实现修改密码逻辑"""
        # 接收参数
        old_password = request.POST.get('old_password')
        new_password = request.POST.get('new_password')
        new_password2 = request.POST.get('new_password2')

        # 校验参数
        if not all([old_password, new_password, new_password2]):
            return http.HttpResponseForbidden('缺少必传参数')
        try:
            request.user.check_password(old_password)
        except Exception as e:
            logger.error(e)
            return render(request, 'user_center_password.html', {'origin_pwd_errmsg':'原始密码错误'})
        if not re.match(r'^[0-9A-Za-z]{8,20}$', new_password):
            return http.HttpResponseForbidden('密码最少8位，最长20位')
        if new_password != new_password2:
            return http.HttpResponseForbidden('两次输入的密码不一致')

        # 修改密码
        try:
            request.user.set_password(new_password)
            request.user.save()
        except Exception as e:
            logger.error(e)
            return render(request, 'user_center_password.html', {'change_pwd_errmsg': '修改密码失败'})

        # 清理状态保持信息
        logout(request)
        response = redirect(reverse('users:login'))
        response.delete_cookie('username')

        # # 响应密码修改结果：重定向到登录界面
        return response



class UpdateTitleAddressView(LoginRequiredJSONMixin, View):
    """设置地址标题"""

    def put(self, request, address_id):
        """设置地址标题"""
        # 接收参数：地址标题
        json_dict = json.loads(request.body.decode())
        title = json_dict.get('title')

        # 校验参数
        if not title:
            return http.HttpResponseForbidden('缺少title')
        try:
            # 查询地址
            address = Address.objects.get(id=address_id)

            # 设置新的地址标题
            address.title = title
            address.save()
        except Exception as e:
            logger.error(e)
            return http.JsonResponse({'code': RETCODE.DBERR, 'errmsg': '设置地址标题失败'})

        # 4.响应删除地址结果
        return http.JsonResponse({'code': RETCODE.OK, 'errmsg': '设置地址标题成功'})

class DefaultAddressView(LoginRequiredJSONMixin, View):
    """设置默认地址"""

    def put(self, request, address_id):
        """设置默认地址"""
        try:
            # 接收参数,查询地址
            address = Address.objects.get(id=address_id)

            # 设置地址为默认地址
            request.user.default_address = address
            request.user.save()
        except Exception as e:
            logger.error(e)
            return http.JsonResponse({'code': RETCODE.DBERR, 'errmsg': '设置默认地址失败'})

        # 响应设置默认地址结果
        return http.JsonResponse({'code': RETCODE.OK, 'errmsg': '设置默认地址成功'})

class UpdateDestroyaddressView(LoginRequiredJSONMixin,View):
    """更新和删除地址"""
    def put(self,request,address_id):
        """更新地址"""
        # 接收参数
        json_dict = json.loads(request.body.decode())
        receiver = json_dict.get('receiver')
        province_id = json_dict.get('province_id')
        city_id = json_dict.get('city_id')
        district_id = json_dict.get('district_id')
        place = json_dict.get('place')
        mobile = json_dict.get('mobile')
        tel = json_dict.get('tel')
        email = json_dict.get('email')

        # 校验参数
        if not all([receiver, province_id, city_id, district_id, place, mobile]):
            return http.HttpResponseForbidden('缺少必传参数')
        if not re.match(r'^1[3-9]\d{9}$', mobile):
            return http.HttpResponseForbidden('参数mobile有误')
        if tel:
            if not re.match(r'^(0[0-9]{2,3}-)?([2-9][0-9]{6,7})+(-[0-9]{1,4})?$', tel):
                return http.HttpResponseForbidden('参数tel有误')
        if email:
            if not re.match(r'^[a-z0-9][\w\.\-]*@[a-z0-9\-]+(\.[a-z]{2,5}){1,2}$', email):
                return http.HttpResponseForbidden('参数email有误')

        # 使用最新的地址信息覆盖指定的旧的地址信息
        # address=Address.objects.get(id=address_id),这个update返回的是受影响的行数
        try:
            Address.objects.filter(id=address_id).update(
                user=request.user,
                title=receiver,
                receiver=receiver,
                province_id=province_id,
                city_id=city_id,
                district_id=district_id,
                place=place,
                mobile=mobile,
                tel=tel,
                email=email
            )
        except Exception as e:
            logger.error(e)
            return http.JsonResponse({'code': RETCODE.DBERR, 'errmsg': '修改地址失败'})
        # 响应新的地址信息给前端进行渲染
        address=Address.objects.get(id=address_id)
        address_dict = {
            "id": address.id,
            "title": address.title,
            "receiver": address.receiver,
            "province": address.province.name,
            "city": address.city.name,
            "district": address.district.name,
            "place": address.place,
            "mobile": address.mobile,
            "tel": address.tel,
            "email": address.email
        }
        return http.JsonResponse({'cpde':RETCODE.OK,'errmsg':'修改地址成功','address':address_dict})
    def delete(self,request,address_id):
        """删除地址"""
        # 实现指定地址的逻辑删除：is_delete=True
        try:
            address=Address.objects.get(id=address_id)
            address.is_deleted=True
            address.save()
        except Exception as e:
            logger.error(e)
            return http.JsonResponse({'code':RETCODE.DBERR,'errmsg':'删除地址失败'})
        # 响应结果：code,errmsg
        return http.JsonResponse({'code': RETCODE.OK, 'errmsg': '删除地址成功'})
class AddressCreateView(LoginRequiredJSONMixin,View):
    """新增地址"""
    def post(self,request):
        """实现新增地址的逻辑"""

        # 判断用户地址数量是否超过上限:查询当前登录用户的地址数量
        count = request.user.addresses.count()  # 一查多，使用related_name进行查询
        if count > USER_ADDRESS_COUNTS_LIMIT:
            return http.JsonResponse({'code': RETCODE.THROTTLINGERR, 'errmsg': '超出用户地址的上限'})
        # 接收参数
        json_dict = json.loads(request.body.decode())
        receiver = json_dict.get('receiver')
        province_id = json_dict.get('province_id')
        city_id = json_dict.get('city_id')
        district_id = json_dict.get('district_id')
        place = json_dict.get('place')
        mobile = json_dict.get('mobile')
        tel = json_dict.get('tel')
        email = json_dict.get('email')
        # 校验参数
        if not all([receiver, province_id, city_id, district_id, place, mobile]):
            return http.HttpResponseForbidden('缺少必传参数')
        if not re.match(r'^1[3-9]\d{9}$', mobile):
            return http.HttpResponseForbidden('参数mobile有误')
        if tel:
            if not re.match(r'^(0[0-9]{2,3}-)?([2-9][0-9]{6,7})+(-[0-9]{1,4})?$', tel):
                return http.HttpResponseForbidden('参数tel有误')
        if email:
            if not re.match(r'^[a-z0-9][\w\.\-]*@[a-z0-9\-]+(\.[a-z]{2,5}){1,2}$', email):
                return http.HttpResponseForbidden('参数email有误')

        # 保存用户传入的地址信息
        # 第一种方法是address=Address(
        #     title='',
        # )
        # address.save()
        try:
            address=Address.objects.create(
                user=request.user,
                title = receiver, # 标题默认就是收货人
                receiver = receiver,
                province_id = province_id,
                city_id = city_id,
                district_id = district_id,
                place = place,
                mobile = mobile,
                tel = tel,
                email = email,
            )
            # 如果登录用户没有默认地址，我们需要制定默认地址
            if not request.user.default_address:
                request.user.default_address = address
                request.user.save()
        except Exception as e:
            logger.error(e)
            return http.JsonResponse({'code':RETCODE.DBERR,'errmsg':'新增地址失败'})


            # 新增地址成功，将新增的地址响应给前端实现局部刷新
        address_dict = {
            "id": address.id,
            "title": address.title,
            "receiver": address.receiver,
            "province": address.province.name,
            "city": address.city.name,
            "district": address.district.name,
            "place": address.place,
            "mobile": address.mobile,
            "tel": address.tel,
            "email": address.email
        }

        # 响应新增地址结果：需要将新增的地址返回给前端进行渲染
        return http.JsonResponse({'code': RETCODE.OK, 'errmsg': '新增地址成功','address':address_dict})

class AddressView(LoginRequiredMixin,View):
    """用户收货地址"""
    def get(self,request):
        """查询并展示用户的地址信息"""
        # 获取当前登录用户对象
        login_user=request.user
        # 使用当前登录用户和is_deleted=False作为条件取查询地址数据
        addresses=Address.objects.filter(user=login_user,is_deleted=False)
        # 将用户地址模型列表转成字典列表：因为JsonResponse和vue.js不认识模型列表，只有django和Jinja2模板引擎认识
        # 这里最后要用vue来渲染，所以要转化成字典列表
        address_list=[]
        for address in addresses:
            address_dict={
                "id": address.id,
                "title": address.title,
                "receiver": address.receiver,
                "province": address.province.name,
                "city": address.city.name,
                "district": address.district.name,
                "place": address.place,
                "mobile": address.mobile,
                "tel": address.tel,
                "email": address.email
            }
            address_list.append(address_dict)

        # 构造上下文
        context={
            # 如果前面是空，则会取到'0'
            'default_address_id': login_user.default_address_id ,
            'addresses': address_list,
        }
        # 当传入模板的数据里面有列表，需要后面加上safe 条件
        return render(request,'user_center_site.html',context=context)
        # return render(request,'user_center_site.html')
class VerifyEmailView(View):
    """邮件的验证"""
    def get(self,request):
        # 接收参数
        token=request.GET.get('token')
        # 校验参数
        if not token:
            return http.HttpResponseForbidden('缺少token')
        # 从token中提取用户的信息user_id==>user
        user=check_verify_email_token(token)
        if not user:
            return http.HttpResponseBadRequest('无效的token')
        # 将用户的email_active字段设置为True
        try:
            user.email_active=True
            user.save()
        except Exception as e:
            logger.error(e)
            # 因为有异常是服务端的异常，Server的错误
            return http.HttpResponseServerError('激活邮件失败')
        return redirect(reverse('users:info'))

        # 响应结果：重定向到用户中心
class EmailView(LoginRequiredJSONMixin,View):
    '''添加邮箱'''
    def put(self,request):
        # 接收参数
        # body 的类型是bytes
        json_str=request.body.decode()
        json_dict=json.loads(json_str)
        email=json_dict.get('email')

        # 校验参数
        if not re.match(r'^[a-z0-9][\w\.\-]*@[a-z0-9\-]+(\.[a-z]{2,5}){1,2}$', email):
            return http.HttpResponseForbidden('参数email有误')
        # 将用户传入的邮箱保存到用户数据库的email字段中
        try:
            request.user.email=email
            request.user.save()
        except Exception as e:
            logger.error(e)
            return http.JsonResponse({'code':RETCODE.DBERR,'errmsg':'添加邮箱失败'})

        # 发送邮箱验证邮件
        verify_url=generate_verify_email_url(request.user)
        # send_verify_email(email,verify_url) # 错误的写法
        send_verify_email.delay(email,verify_url) # 一定要记得调用delay


        return http.JsonResponse({'code': RETCODE.OK, 'errmsg': 'OK'})

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
        merge_cart_cookies_redis(request=request,user=user,response=response)

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

