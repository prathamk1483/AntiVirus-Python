from django.urls import re_path
from . import consumers

websocket_urlpatterns = [
    re_path('ws/socket-server/',consumers.DashBoardConsumer.as_asgi())
]