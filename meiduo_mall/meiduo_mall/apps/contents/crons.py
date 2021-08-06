# 静态化首页
import os
from collections import OrderedDict
from django.conf import settings
from django.template import loader

from contents.models import ContentCategory
from contents.utils import get_categories


def generate_static_index_html():
    """静态化首页"""
    # 查询首页的数据
    # 查询并展示商品分类
    categories = get_categories()
    # 查询首页广告数据
    # 查询所有广告类别
    contents = OrderedDict()

    content_categories = ContentCategory.objects.all()
    for content_category in content_categories:
        contents[content_category.key] = content_category.content_set.filter(status=True).order_by(
            'sequence')  # 查询出未下架的广告并排序
    # 构造上下文
    context = {
        'categories': categories,
        'contents': contents
    }

    # 渲染到模板
    # 先渲染模板文件
    template=loader.get_template('index.html')
    # 再使用上下文渲染模板文件,之前所用的render就是用html字符串作为响应体响应回去
    html_text=template.render(context)
    # 将模板文件写入到静态路径
    file_path=os.path.join(settings.STATICFILES_DIRS[0],'index-stastic.html')
    with open(file_path,'w',encoding='utf-8') as f:
        f.write(html_text)
