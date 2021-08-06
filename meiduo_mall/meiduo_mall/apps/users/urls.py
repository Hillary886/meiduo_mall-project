from django.conf.urls import url
from . import views
urlpatterns = [
    #用户注册：reverse(users/register) =='/register/'
    url(r'^register/$',views.RegisterView.as_view(),name='register'),
    # 判断用户名是否重复注册
    url(r'^usernames/(?P<username>[a-zA-Z0-9_-]{5,20})/count/$',views.UsernameCountView.as_view()),
    url(r'^mobiles/(?P<mobile>1[3-9]\d{9})/count/$',views.MobileCountView.as_view()),
    # 用户登录
    url(r'^login/$',views.LoginView.as_view(),name='login'),
    # 用户退出，因为首页需要退出的链接
    url(r'^logout/$',views.LogoutView.as_view(),name='logout'),
    # 用户中心
    url(r'^info/$',views.UserInfoView.as_view(),name='info'),
    # 添加邮箱
    url(r'^emails/$',views.EmailView.as_view()),
    # 验证邮箱
    url(r'^emails/verification/$',views.VerifyEmailView.as_view()),
    # 展示用户的地址
    url(r'^addresses/$',views.AddressView.as_view(),name='address'),
    # 新增用户的地址
    url(r'^addresses/create/$', views.AddressCreateView.as_view()),
    # 更新和删除地址
    url(r'^addresses/(?P<address_id>\d+)/$',views.UpdateDestroyaddressView.as_view()),
    # 设置默认的地址
    url(r'addresses/(?P<address_id>\d+)/default/$',views.DefaultAddressView.as_view()),
    # 更新地址的标题
    url(r'addresses/(?P<address_id>\d+)/title/$',views.UpdateTitleAddressView.as_view()),
    # 设置修改密码
    url(r'password/$', views.ChangePasswordView.as_view(),name='password'),
    # 用户商品的浏览记录
    url(r'^browse_histories/$',views.UserBrowseHistory.as_view()),
]