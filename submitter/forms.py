from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django import forms
from .models import CustomUser, Question, Listing
from django.utils.safestring import mark_safe



class CustomAuthenticationForm(AuthenticationForm):
    email = forms.EmailField(widget=forms.TextInput(attrs={'autofocus': True}))

class CreateUserForm(UserCreationForm):
    email = forms.EmailField(required=True)
    class Meta:
        model = CustomUser
        fields = ['first_name','last_name','email','password1','password2']
    
    def save(self, commit=True):
        user = super().save(commit=False)
        user.email = self.cleaned_data['email']
        if commit:
            user.save()
        return user

class CreateListingForm(forms.ModelForm):
    name = forms.CharField(required=True, label='Name', max_length=200)
    demographic_questions = forms.ModelMultipleChoiceField(
        label='Demographic Questions',
        required = False,
        queryset=Question.objects.filter(category = "Demographic"),
        widget=forms.CheckboxSelectMultiple()
    )

    social_questions = forms.ModelMultipleChoiceField(
        label="Social Questions",
        required = False,
        queryset=Question.objects.filter(category = "Social"),
        widget=forms.CheckboxSelectMultiple()
    )

    household_questions = forms.ModelMultipleChoiceField(
        label="Household Questions",
        required = False,
        queryset=Question.objects.filter(category = "Household"),
        widget=forms.CheckboxSelectMultiple()
    )


    def clean(self):
        cleaned_data = super().clean()
        # Check if questions are empty
        if not cleaned_data.get('demographic_questions')  and not cleaned_data.get('social_questions') and not cleaned_data.get('household_questions'):
            raise forms.ValidationError("At least one response is required.")
        
        return cleaned_data

    class Meta:
        model = Listing
        fields = [
            "name",
            "demographic_questions",
            "social_questions",
            "household_questions"
        ]

