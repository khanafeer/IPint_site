from django.shortcuts import render
from django.views import View
from .scan import Scan
from django.http import Http404,HttpResponse,JsonResponse
from .models import Comments
from .forms import CommentForm

def index(req):
    return render(request=req, template_name='home/index.html')

class Comment(View):
    def post(self,req):
        form = CommentForm(req.POST)
        if form.is_valid():
            form.save()
            return JsonResponse({'status':True})
        return JsonResponse({'status':False})


class Home(View):
    def get(self,req):
        return render(request=req,template_name='home/index.html')

    def post(self,req):
        data = req.POST
        print(req.POST)
        if data['type'] == 'ip':
            title = data['ip']
            s = Scan(IP=data['ip'])
            comments = Comments.objects.filter(source=data['ip'])


        elif data['type'] == 'url':
            title = data['url']
            s = Scan(Domain=data['url'])
            comments = Comments.objects.filter(source=data['url'])


        elif data['type'] == 'hash':
            title = data['hash']
            s = Scan(Hash=data['hash'])
            comments = Comments.objects.filter(source=data['hash'])
        else:
            return Http404

        res = s.scan_all()


        return render(req,
                      template_name='home/results.html',
                      context={'type':data['type'],
                               'title':title,
                               'results':res,
                               'comments':comments})
