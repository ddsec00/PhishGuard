from django import forms
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.forms import UserCreationForm

from .models import ScanReport


class RegistrationForm(UserCreationForm):
    """User registration form with a required, unique email address."""

    email = forms.EmailField(required=True)

    class Meta(UserCreationForm.Meta):
        model = get_user_model()
        fields = ("username", "email")

    def clean_email(self):
        email = self.cleaned_data["email"].strip()
        user_model = get_user_model()
        if user_model.objects.filter(email__iexact=email).exists():
            raise forms.ValidationError("An account with this email already exists.")
        return email


class ScanSubmissionForm(forms.Form):
    """Accept one pasted email or one RFC 822 `.eml` upload."""

    raw_email = forms.CharField(
        required=False,
        widget=forms.Textarea(attrs={"rows": 12}),
        label="Email content",
    )
    eml_file = forms.FileField(required=False, label=".eml file")

    def clean_raw_email(self):
        return self.cleaned_data.get("raw_email", "").strip()

    def clean_eml_file(self):
        uploaded_file = self.cleaned_data.get("eml_file")
        if uploaded_file is None:
            return None

        if not uploaded_file.name.lower().endswith(".eml"):
            raise forms.ValidationError("Upload an email file with the .eml extension.")

        if uploaded_file.size == 0:
            raise forms.ValidationError("The .eml file cannot be empty.")

        if uploaded_file.size > settings.MAX_EMAIL_UPLOAD_SIZE:
            limit_mb = settings.MAX_EMAIL_UPLOAD_SIZE // (1024 * 1024)
            raise forms.ValidationError(
                f"The .eml file must be no larger than {limit_mb} MB."
            )
        return uploaded_file

    def clean(self):
        cleaned_data = super().clean()
        raw_email = cleaned_data.get("raw_email", "")
        eml_file = cleaned_data.get("eml_file")

        if raw_email and eml_file:
            raise forms.ValidationError(
                "Choose pasted email content or one .eml file, not both."
            )
        if not raw_email and not eml_file and not self.errors:
            raise forms.ValidationError(
                "Provide either pasted email content or one .eml file."
            )
        return cleaned_data


class ScanReportEditForm(forms.ModelForm):
    """Allow a user to edit report notes without altering scan findings."""

    class Meta:
        model = ScanReport
        fields = ("notes",)
        widgets = {"notes": forms.Textarea(attrs={"rows": 5})}
