import uuid
from datetime import timezone

from django.contrib.auth.models import PermissionsMixin
from django.db import models
# from openshare.settings import CERT_EXPIRE_TIME TODO: set this in settings
from django.utils.translation import gettext_lazy as _

CERT_EXPIRE_TIME = 60 * 60 * 24 * 30 #one month


class Device(PermissionsMixin, models.Model):

    id = models.UUIDField(
        _("ID"),
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
        null=False
    )

    device_uid = models.CharField(
        _("Device UID"),
        max_length=255,
        unique=True,
        null=False
    )

    account_id = models.ForeignKey(
        'accounts.models.Account',
        on_delete=models.CASCADE,
        related_name='devices',
        null=False
    )

    status = models.CharField(
        _("Device status"),
        max_length=255,
        default="pending",
        null=False
    )

    pubkey_ed25519= models.BinaryField(
        _("Public key ed25519"),
        max_length=32,
        null=False
    )

    pubkey_b64= models.CharField(
        _("Public key base64"),
        max_length=255,
    )

    cert_blob= models.JSONField(
        _("Certificate blob"),
        default=dict,
    )

    cert_sig= models.BinaryField(
        _("Certificate signature"),
    )

    cert_issued_at = models.DateTimeField(
      _("Certificate issued at"),
    )

    cert_expires_at = models.DateTimeField(
      _("Certificate expires"),
      default=(timezone.now() + CERT_EXPIRE_TIME),
    )

    last_seen= models.DateTimeField(
        _("Last seen"),
        auto_now=True,
    )

    created_at = models.DateTimeField(
        _("Created at"),
        auto_now_add=True
    )

    updated_at = models.DateTimeField(
        _("Updated at"),
        auto_now=True
    )

    metadata = models.JSONField(
        _("Metadata"),
        default=dict,
    )

    class Meta:
        verbose_name = _("Device")
        verbose_name_plural = _("Devices")
        ordering = ("-created_at",)



    def set_last_seen(self, new_time=None):
        if new_time is None:
            new_time = timezone.now()
        self.last_seen = new_time

    def set_cert_issued_at(self, new_time=None):
        if new_time is None:
            new_time = timezone.now()
        self.cert_issued_at = new_time



class DeviceCerts(PermissionsMixin, models.Model):

    id = models.UUIDField(
        _("ID"),
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
        null=False
    )

    device_id = models.ForeignKey(
        _("Device ID"),
        Device,
        to_field="id",
        on_delete=models.CASCADE,
    )

    cert_blob= models.JSONField(
        _("Certificate blob"),
        default=dict,
    )

    cert_sig= models.BinaryField(
        _("Certificate signature"),
    )

    issued_at = models.DateTimeField(
      _("issued at"),
    )

    expires_at = models.DateTimeField(
      _("expires at"),
      default=(timezone.now() + CERT_EXPIRE_TIME),
    )

    issuer_id = models.CharField(
        _("issuer id"),
        max_length=255,
    )

    revoked_at = models.DateTimeField(
        _("revoked at"),
        null=True,
    )


    class Meta:
        verbose_name = _("Device certs")


    def set_issuer_id(self, issuer=None):
        self.issuer_id = issuer

    def set_revoked_at(self, new_time=None):
        if new_time is None:
            new_time = timezone.now()
        self.revoked_at = new_time


class Crls(PermissionsMixin, models.Model):
    id = models.BigAutoField(
        _("ID"),
        primary_key=True,
        null=False
    )

    version = models.IntegerField(
        _("Version"),
        unique=True,
        null=False
    )

    issued_at = models.DateTimeField(
        _("issued at"),
        null=False,
    )

    issuer_id = models.CharField(
        _("issuer id"),
        max_length=255,
        null=False
    )

    crl_blob = models.JSONField(
        _("CRL blob"),
        default=dict,
    )

    sig = models.BinaryField(
        _("Signature"),
        null=False,
    )

    notes = models.TextField(
        _("Notes"),
    )

class CrlEntries(PermissionsMixin, models.Model):

    crl_id = models.ForeignKey(
        'Crls',
        on_delete=models.CASCADE,
        null=False,
    )

    revoked_device_id = models.ForeignKey(
        'Device',
        on_delete=models.CASCADE,
        null=False,
    )

    revoked_at = models.DateTimeField(
        _("revoked at"),
        null=False,
        auto_now=True,
    )

    reason = models.TextField(
        _("Reason"),
    )


class CurrentCrl(PermissionsMixin, models.Model):

    id = models.IntegerField(
        _("ID"),
        null=False,
    )

    crl_id = models.ForeignKey(
        'Crls',
        on_delete=models.CASCADE,
    )

    updated_at = models.DateTimeField(
        _("updated at"),
        default= timezone.now
    )