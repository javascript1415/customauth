from django import forms
from account.models import User


class RegistrationForm(forms.ModelForm):
    password = forms.CharField(widget = forms.PasswordInput)
    confirm_password = forms.CharField(widget = forms.PasswordInput)
    class  Meta:
        model = User
        fields = ['email','name','password','confirm_password']
        
        def clean(self):
            cleaned_data = super().clean()
            password = cleaned_data.get('password')
            confirm_password = cleaned_data.get('confirm_password')

            if password != confirm_password:
                self.add_error('confirm_password',"password and confirm password doesnt match ")

            return cleaned_data
        def clean_email(self):
            email = self.cleaned_data.get("email")
            if User.objects.filter(email = email):
                raise ValueError('the email already exist')
            
            return email
            

class PasswordResetForm(forms.Form):
    email = forms.EmailField(max_length=255,required=True,widget=forms.EmailInput(attrs={'placeholer':"enter ur name"}))

    def clean_email(self):
        email = self.cleaned_data.get('email')

        if not User.objects.filter(email = email).exists():
            raise forms.ValidationError(('no account is validated with this email'))

        return email
