from django.conf.urls import url

from orders import views

urlpatterns=[
    # 结算订单
    url(r'^orders/settlement/$',views.OrderSettlementView.as_view(),name='settlement'),
    # 递交订单
    url(r'^orders/commit/$',views.OrderCommitView.as_view()),
    # 提交订单成功
    url(r'^orders/success/$',views.OrderSuccessView.as_view()),
    # 展示订单
    url(r'orders/info/(?P<page_num>\d+)/',views.UserOrderInfoView.as_view(),name='info')
]