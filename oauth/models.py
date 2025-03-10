from django.db import models

class GmailAccount(models.Model):
    gmail_address = models.EmailField(unique=True)
    access_token = models.CharField(max_length=500, unique=True, null=True, blank=True)
    refresh_token = models.CharField(max_length=255, unique=True, null=True, blank=True)
    authorization_code = models.CharField(max_length=255, unique=True, null=True, blank=True)
    expires_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f"{self.gmail_address} | {self.user}"
    
    class Meta:
        verbose_name = "GMAIL ACCOUNT"
        verbose_name_plural = "GMAIL ACCOUNTS"