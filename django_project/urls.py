from django.urls import path, re_path
from django.contrib import admin
from django.conf import settings
from django.conf.urls.static import static
from django.http import HttpResponse
from tasks import views


def replco_iframe(request):
    """Serve Replit workspace preview iframe wrapper."""
    initial_path = request.GET.get('initialPath', '/')
    html = f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8">
<style>*{{margin:0;padding:0;border:0}}html,body,iframe{{width:100%;height:100%;overflow:hidden}}</style>
</head>
<body><iframe src="{initial_path}" style="width:100%;height:100%;border:none;" allow="same-origin"></iframe>
</body></html>"""
    return HttpResponse(html)


urlpatterns = [
    path('admin/', admin.site.urls),
    path('__replco/workspace_iframe.html', replco_iframe),
    path('', views.index, name='index'),
    path('encrypt/', views.encrypt, name='encrypt'),
] + static(settings.STATIC_URL, document_root=settings.STATICFILES_DIRS[0])