from django.shortcuts import render,redirect
from django.contrib.auth.forms import PasswordChangeForm
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.contrib.auth import logout
from core.decorators import login_and_role_required

@login_and_role_required("customer")
def customer_dashboard_view(request):
    return render(request,'customer/dashboard.html')

@login_required(redirect_field_name='login')
def password_change_view(request):
    if request.method == "POST":
        form = PasswordChangeForm(user=request.user,data = request.POST)
        if form.is_valid():
           form.save()
           logout(request)
           messages.success(request,'ur pw is changed sucessfully now login with ur new password')
           return redirect('login')
        else:
            for fields,errors in form.errors.items():
                for error in errors:
                    messages.error(request,error)
    else:
        form = PasswordChangeForm(user = request.user)
        print(form)
    return render(request,'customer/password_change.html')