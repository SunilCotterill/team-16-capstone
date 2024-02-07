from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django import forms
from .models import CustomUser, Question, Listing



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
    questions = forms.ModelMultipleChoiceField(
        label="Questions",
        required=True,  # Set to True
        queryset=Question.objects.all(),
        widget=forms.CheckboxSelectMultiple(attrs={"class": "form-check-input"})
    )

    def clean(self):
        cleaned_data = super().clean()
        questions = cleaned_data.get('questions')
        
        # Check if questions are empty
        if not questions:
            raise forms.ValidationError("At least one response is required.")
        
        return cleaned_data

    class Meta:
        model = Listing
        fields = [
            "name",
            "questions"
        ]

