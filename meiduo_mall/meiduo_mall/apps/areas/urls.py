from django.conf.urls import url

from areas import views

urlpatterns = [
    # 省市区三级联动
    url(r'^areas/$',views.AreasView.as_view())
]