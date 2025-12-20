from django.db import models


class TrustRoot(models.Model):
    key_id = models.CharField(max_length=64, unique=True)
    pubkey_ed25519 = models.BinaryField()
    valid_from = models.DateTimeField()
    valid_to = models.DateTimeField()
    active = models.BooleanField(default=True)

    class Meta:
        ordering = ["-valid_from"]

    def __str__(self):
        return f"TrustRoot {self.key_id}"
