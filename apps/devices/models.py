import uuid
from datetime import timedelta
from django.utils import timezone
from django.contrib.auth.models import PermissionsMixin
from django.db import models
from django.utils.translation import gettext_lazy as _


CERT_EXPIRE_TIME = timedelta(days=30)


class Device( models.Model):
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
        'accounts.Account',
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

    pubkey_ed25519 = models.BinaryField(
        _("Public key ed25519"),
        max_length=32,
        null=False
    )

    pubkey_b64 = models.CharField(
        _("Public key base64"),
        max_length=255,
    )

    cert_blob = models.JSONField(
        _("Certificate blob"),
        default=dict,
    )

    cert_sig = models.BinaryField(
        _("Certificate signature"),
    )

    cert_issued_at = models.DateTimeField(
        _("Certificate issued at"),
    )

    cert_expires_at = models.DateTimeField(
        _("Certificate expires"),
        default=lambda: timezone.now() + CERT_EXPIRE_TIME,
    )

    last_seen = models.DateTimeField(
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

    def __str__(self):
        return f"Device {self.device_uid} ({self.status})"

    def set_last_seen(self, new_time=None):
        self.last_seen = new_time or timezone.now()

    def set_cert_issued_at(self, new_time=None):
        self.cert_issued_at = new_time or timezone.now()


class DeviceCerts( models.Model):
    id = models.UUIDField(
        _("ID"),
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
        null=False
    )

    device_id = models.ForeignKey(
        Device,
        on_delete=models.CASCADE,
        related_name="certs",
    )

    cert_blob = models.JSONField(
        _("Certificate blob"),
        default=dict,
    )

    cert_sig = models.BinaryField(
        _("Certificate signature"),
    )

    issued_at = models.DateTimeField(
        _("issued at"),
    )

    expires_at = models.DateTimeField(
        _("expires at"),
        default=lambda: timezone.now() + CERT_EXPIRE_TIME,
    )

    issuer_id = models.CharField(
        _("issuer id"),
        max_length=255,
    )

    revoked_at = models.DateTimeField(
        _("revoked at"),
        null=True,
        blank=True,
    )

    class Meta:
        verbose_name = _("Device Certificate")
        verbose_name_plural = _("Device Certificates")

    def __str__(self):
        return f"Cert for {self.device_id.device_uid}"

    def set_issuer_id(self, issuer=None):
        self.issuer_id = issuer

    def set_revoked_at(self, new_time=None):
        self.revoked_at = new_time or timezone.now()


class Crls( models.Model):
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
        blank=True,
    )

    class Meta:
        verbose_name = _("CRL")
        verbose_name_plural = _("CRLs")

    def __str__(self):
        return f"CRL v{self.version} ({self.issuer_id})"


class CrlEntries( models.Model):
    crl_id = models.ForeignKey(
        Crls,
        on_delete=models.CASCADE,
        related_name="entries",
        null=False,
    )

    revoked_device_id = models.ForeignKey(
        Device,
        on_delete=models.CASCADE,
        related_name="revocations",
        null=False,
    )

    revoked_at = models.DateTimeField(
        _("revoked at"),
        auto_now=True,
    )

    reason = models.TextField(
        _("Reason"),
    )

    class Meta:
        verbose_name = _("CRL Entry")
        verbose_name_plural = _("CRL Entries")

    def __str__(self):
        return f"Revoked {self.revoked_device_id.device_uid}"


class CurrentCrl( models.Model):
    id = models.IntegerField(
        _("ID"),
        primary_key=True,
        null=False,
    )

    crl_id = models.ForeignKey(
        Crls,
        on_delete=models.CASCADE,
        related_name="current_crl",
    )

    updated_at = models.DateTimeField(
        _("updated at"),
        default=timezone.now,
    )

    class Meta:
        verbose_name = _("Current CRL")
        verbose_name_plural = _("Current CRLs")


    def __str__(self):
        return f"Current CRL #{self.crl_id_id}"
