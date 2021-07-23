from django.shortcuts import render

# Create your views here.
from django.views import View


class IndexView(View):
    def get(self,request):
        """提供首页广告页面"""
        return render(request,'index1.html')
