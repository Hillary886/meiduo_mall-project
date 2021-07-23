from django.conf.urls import url
from . import views
urlpatterns = [
    #首页的广告：'/',可以在正则中不用填写，因为路由在校验的时候会补充/的。
    url(r'^$',views.IndexView.as_view(),name='index'),


]