from django.db import models

# Create your models here.

class Comments(models.Model):
    source = models.CharField(max_length=250)
    auther = models.CharField(max_length=250)
    msg = models.TextField()
