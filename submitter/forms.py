from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django import forms
from .models import CustomUser, Question, Listing
from django.utils.safestring import mark_safe
from django.core.validators import MaxLengthValidator



class CustomAuthenticationForm(AuthenticationForm):
    email = forms.EmailField(widget=forms.TextInput(attrs={'autofocus': True}))

class CreateUserForm(UserCreationForm):
    email = forms.EmailField(required=True)
    first_name = forms.CharField(max_length=100, label='First Name', widget=forms.TextInput(attrs={'placeholder': 'First Name'}))
    last_name = forms.CharField(max_length=100, label='Last Name', widget=forms.TextInput(attrs={'placeholder': 'Last Name'}))
    email = forms.EmailField(max_length=100,label='School Email (UW or WLU)', widget=forms.EmailInput(attrs={'placeholder': 'School Email (UW or WLU)'}))
    password1 = forms.CharField(max_length=100,label='Password', widget=forms.PasswordInput(attrs={'placeholder': 'Password'}))
    password2 = forms.CharField(max_length=100, label='Confirm Password', widget=forms.PasswordInput(attrs={'placeholder': 'Confirm Password'}))
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
    demographic_questions = forms.ModelMultipleChoiceField(
        label='Demographic Questions',
        required = False,
        queryset=Question.objects.filter(category = "Demographic"),
        widget=forms.CheckboxSelectMultiple(attrs={'class': 'checkbox-select'})
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

    BEDROOM_CHOICES = [
        ('', "Number of Available Bedrooms*"),
        (1, '1 Bedroom'),
        (2, '2 Bedrooms'),
        (3, '3 Bedrooms'),
        (4, '4 Bedrooms'),
        (5, '5+ Bedrooms')
    ]



    available_bedrooms = forms.ChoiceField(choices=BEDROOM_CHOICES)


    def clean(self):
        cleaned_data = super().clean()
        # Check if questions are empty
        if not cleaned_data.get('demographic_questions')  and not cleaned_data.get('social_questions') and not cleaned_data.get('household_questions'):
            raise forms.ValidationError("You must select at least one question")
        
        return cleaned_data

    class Meta:
        model = Listing
        fields = [
            "name",
            "demographic_questions",
            "social_questions",
            "household_questions",
            "available_bedrooms",
            "address",
            "rent_amount",
            "additional_information",
            "rent_term"
        ]
        widgets = {
            'additional_information': forms.Textarea(attrs={'rows': 5, 'cols': 40, 'maxlength':50, 'placeholder': 'Additional Information/Relevant Links'}),
            'name': forms.TextInput(attrs={'placeholder': 'Listing Name*',
                                            "class": "form-group"
                                           }),
            'available_bedrooms': forms.Select(attrs={"class": "form-group"}),
            'address': forms.TextInput(attrs={'placeholder': 'Address', "class": "form-group"}),
            'rent_amount': forms.NumberInput(attrs={'placeholder': 'Rent Amount (CAD)', "class": "form-group"}),
            'rent_term': forms.TextInput(attrs={'placeholder': 'Rent Term*', "class": "form-group"})

        }


