from django.shortcuts import render

def memorial_index(request):
    return render(request, "memorials/index.html")
