from django.db import models
from django.contrib.auth.models import BaseUserManager ,AbstractBaseUser

class UserManger(BaseUserManager):
    def create_user(self,email,password = None):
        if not email:
            raise ValueError("user must have an valid email address")
        
        user = self.model(email=self.normalize_email(email))
        user.set_password(password)
        user.save(using = self._db)
        return user
    def create_superuser(self,email,password=None,**extra_fields):
        extra_fields.setdefault ( 'is_staff',True)
        extra_fields.setdefault ( 'is_superuser',True)
        if extra_fields.get('is_staff') is not True:
            raise ValueError("superuser must have is_staff true")
        if extra_fields.get('is_superuser') is not True:
            raise ValueError("superuser must have is_ssuperuser true")
        
        #create and save the superuser for the given email and the password
        user = self.create_user(email,password)
        user.is_staff = True
        user.is_superuser =True
        user.is_customer = True
        user.is_seller = True
        user.save(using = self._db)
        return user



class User(AbstractBaseUser):
    email = models.EmailField(verbose_name="Email",max_length=255,unique=True)#verbose_name is not nessary cuz email = is already written
    name = models.CharField(max_length=255)    
    city = models.CharField(max_length=255)
    is_active = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)
    is_customer = models.BooleanField(default=True)
    is_seller = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    USERNAME_FIELD =  'email'
    objects = UserManger()

    def __str__(self):
        return self.email

    def has_perm(self,perm,object = None):
    # does the user  has a specific permission.
    #only the superuser has ascess to all data
       return self.is_superuser

    def has_module_perm(self,app_label):
        #does th euser have permission to view the app 'app_label'?
        return self.is_superuser
    
    def has_module_perms(self, app_label):
        """Grant access to all modules for superusers."""
        return self.is_superuser