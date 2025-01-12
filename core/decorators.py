from django.contrib.auth.decorators import login_required
from functools import wraps
from  django.http import HttpResponseForbidden



def login_and_role_required(required_role):

    erro_403_html = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Access Denied</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #f8f9fa;
            margin: 0;
            padding: 0;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            height: 100vh;
            color: #333;
        }
        .container {
            text-align: center;
            background: #fff;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }
        h1 {
            color: #e74c3c;
        }
        p {
            margin: 15px 0;
        }
        .btn {
            display: inline-block;
            margin-top: 20px;
            padding: 10px 20px;
            font-size: 16px;
            color: #fff;
            background-color: #3498db;
            border: none;
            border-radius: 5px;
            text-decoration: none;
            cursor: pointer;
            transition: background-color 0.3s ease;
        }
        .btn:hover {
            background-color: #2980b9;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Access Denied</h1>
        <p>Sorry, you are not allowed to access this page.</p>
        <a href="/" class="btn">Return to Home</a>
    </div>
</body>
</html>

"""

    def decorator(view_func):
        @wraps(view_func)
        @login_required
        def _wrapped_view(request,*args,**kwargs):
            user = request.user
            if required_role == "customer" and not user.is_customer:
                return HttpResponseForbidden(erro_403_html)
            if required_role == "seller" and not user.is_seller:
                return HttpResponseForbidden(erro_403_html)

            return view_func(request,*args,**kwargs)
        return _wrapped_view
    return decorator
                                             