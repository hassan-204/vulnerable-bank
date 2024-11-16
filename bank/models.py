from django.db import models
from django.contrib.auth.models import User

class Transaction(models.Model):
    sender = models.ForeignKey(User, related_name='sent_transactions', on_delete=models.CASCADE)
    recipient = models.ForeignKey(User, related_name='received_transactions', on_delete=models.CASCADE)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Transaction from {self.sender} to {self.recipient} of {self.amount}"


class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    balance = models.DecimalField(max_digits=10, decimal_places=2, default=16000)

    def __str__(self):
        return f"Profile for {self.user.username}"


class Cheque(models.Model):
    code = models.CharField(max_length=16, unique=True)
    amount = models.DecimalField(max_digits=10, decimal_places=2, default=500000)
    is_active = models.BooleanField(default=True)

    def __str__(self):
        return f"Cheque Code: {self.code}"


class ChequeActivation(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    cheque = models.ForeignKey(Cheque, on_delete=models.CASCADE)
    activated_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.username} activated {self.cheque.code} on {self.activated_at}"

    def can_activate(self):
        # Check if the user activated a cheque within the last 10 minutes
        last_activation = ChequeActivation.objects.filter(user=self.user).order_by('-activated_at').first()
        if last_activation and (timezone.now() - last_activation.activated_at).total_seconds() < 600:
            return False  # Less than 10 minutes
        return True