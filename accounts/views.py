from django.shortcuts import render
from django.contrib.auth.models import User
from rest_framework.response import Response
from .serializers import RegisterSerializer
from rest_framework.generics import CreateAPIView

class RegisterApi(CreateAPIView):
    queryset = User.objects.all()
    serializer_class = RegisterSerializer
    
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True) # valid değilse hata döndür demiş olduk.
        serializer.save()
        return Response({
            "message" : "User successfully created."
        })
        # Post işlemi yaptıktan sonra API'den kullanıcı bilgileri dönüyordu. Bunun yerine "User successfully created" mesajı vermek için buradaki metodu tanımladık.