from rest_framework import serializers, validators
from django.contrib.auth.models import User
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth.hashers import make_password
from dj_rest_auth.serializers import TokenSerializer


class RegisterSerializer(serializers.ModelSerializer):
        # !!!!! Kullandığımız User isimli model'in içerisinde "email", "password" ve "pasword2" bulunmadığı için bunları burada kendimiz oluşturduk.
    email = serializers.EmailField(
        required=True,
        validators=[validators.UniqueValidator(queryset=User.objects.all())]
        )
    
    password = serializers.CharField(
        write_only=True,
        required=True,
        validators=[validate_password],
        style={"input_type":"password"}  # Bununla şifreyi yazdığımız yerde şifrenin yerine nokta görülmesini sağlıyoruz.
        )
    
    password2 = serializers.CharField(
        write_only=True,
        required=True,
        style={"input_type":"password"}
        )
    
    
    class Meta:
        model = User
        fields = [
            'username',
            'first_name',
            'last_name',
            'email',
            'password',
            'password2'
        ]
        
        extra_kwargs = {
            "password" : {"write_only":True},
            "password2" : {"write_only":True}
        }
        
    def create(self, validated_data):
        password = validated_data.get("password")
        validated_data.pop("password2")
        
        user = User.objects.create(**validated_data)
        # user.password = make_password(password)
            # set_password() metodu yerine bununla da yapabiliriz. 
            # make_password() metodunu kullanmak için import etmek gerekiyor.
        user.set_password(password)
        user.save()
        return user
    
    def validate(self, data):
        if data["password"] != data["password2"]:
            raise serializers.ValidationError(
            {"password": "Password fields didn't match."})
        return data


class UserTokenSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id', 'email', 'first_name', 'last_name')
    
class CustomTokenSerializer(TokenSerializer):
    user = UserTokenSerializer(read_only=True)
    
    class Meta(TokenSerializer.Meta):
        fields = ('key', 'user')
    
    # Normalde bir kullanıcı login olduğunda, ona bir token atanıyor ve API'den geriye bu token döndürülüyordu.
    # Ancak biz API'den token'ın yanında kullanıcının bilgilerinin ('email','firs_name','last_name') de dönmesini istiyoruz.
    # Bunu sağlamak için bu serializer'ı (CustomTokenSerializer) oluşturduk.