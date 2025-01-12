from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from account.models import User

# Register your models here.
class UserModelAdmin(UserAdmin):
    model = User
    list_display = ['id','email','name','is_active','is_staff','is_seller','is_customer','is_superuser']
    list_filter = ["is_superuser"]
    fieldsets = [
        ("user crediantials",{"fields":['email','password']}),
        ("personal information",{"fields":["name","city"]}),
        ("permissions",{"fields":['is_active','is_staff','is_seller','is_customer','is_superuser']})
    ]

    add_fieldsets = [
       (None, {  # Fieldset title
            'classes': ('wide',),  # CSS classes for styling
            'fields': ('email', 'password1', 'password2')  # Fields to display
        }),
    ]
    search_fields =['email']
    ordering = ["email","id"]
    filter_horizontal =[]

admin.site.register(User,UserModelAdmin)