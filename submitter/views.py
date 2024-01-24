from django.shortcuts import render, get_object_or_404, redirect, reverse
from django.http import HttpResponse, HttpResponseRedirect
from .models import Question, Answer, Listing, Response, CustomUser
from django.template import loader
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required

from .forms import CreateUserForm, CustomAuthenticationForm, CreateListingForm


def index(request):
    return redirect('submitter:register')

def submission(request, listing_id):
    listing = Listing.objects.get(pk = listing_id)
    listing_questions_list = listing.questions.all()
    question_ids = list(listing_questions_list.values_list("id", flat = True))
    listing_answers_list = Answer.objects.filter(question__in = question_ids)

    template = loader.get_template("submitter/submission.html")

    context = {
        "listing_id": listing_id,
        "listing_questions_list": listing_questions_list,
        "listing_answers_list": listing_answers_list
    }
    return render(request, "submitter/submission.html", context)

def results(request, listing_id):
    if request.user.is_authenticated:
        filters = []

        if request.method == "POST":
            for key in request.POST.keys():
                if key.startswith('question_'):
                    filters.append(int(request.POST.get(key)))


        responses = Response.objects.filter(listing_id=listing_id)
        unique_emails = responses.values_list('email', flat=True).distinct()
        emails = []

        listing = Listing.objects.get(pk = listing_id)
        listing_questions_list = listing.questions.all()
        question_ids = list(listing_questions_list.values_list("id", flat = True))
        listing_answers_list = Answer.objects.filter(question__in = question_ids)

        if filters:
            for email in unique_emails:
                flag = True
                responses_for_email = Response.objects.filter(listing_id=listing_id, email=email)
                for filter in filters:
                    if filter not in responses_for_email.values_list('answer_id', flat=True):
                        flag = False
                        break
                if flag:
                    emails.append(email)
        else:
            emails = unique_emails
        # Name for title
        name = Listing.objects.get(id=listing_id).name
        context = {
            "listing_id": listing_id,
            "unique_users": emails,
            "listing_name": name,
            "listing_questions_list": listing_questions_list,
            "listing_answers_list": listing_answers_list,
            "filtered_answers": filters
        }
        return render(request, "submitter/results.html", context)
    else:
        return redirect('submitter:home')





def result(request, listing_id, email):
    answered_ids = Response.objects.filter(listing_id=listing_id).filter(email=email).values_list('answer_id', flat=True).distinct()
    answered = Answer.objects.filter(id__in=answered_ids).values_list('id', flat=True)

    listing = Listing.objects.get(pk = listing_id)
    listing_questions_list = listing.questions.all()
    question_ids = list(listing_questions_list.values_list("id", flat = True))
    listing_answers_list = Answer.objects.filter(question__in = question_ids)

    context = {
        "listing_id": listing_id,
        "listing_questions_list": listing_questions_list,
        "listing_answers_list": listing_answers_list,
        "answered": answered,
        "email": email
    }
    return render(request, "submitter/result.html", context)


def submit(request, listing_id):
    # Get the CSRF token from the POST request
    csrf_token = request.POST.get('csrfmiddlewaretoken')

    # Loop through all the keys in the POST data
    for key in request.POST.keys():
        email = request.POST.get('email')
        if key.startswith('question_'):
            question_id = key.split('_')[1]
            selected_answer_id = request.POST.get(key)
            new_response = Response()
            new_response.listing = Listing.objects.get(pk = listing_id)
            new_response.question = Question.objects.get(pk = question_id)
            new_response.answer = Answer.objects.get(pk = selected_answer_id)
            new_response.email = email
            new_response.save()
    # results_url = reverse("submitter:results", args=[listing_id])
    redirect_url = reverse("submitter:submission_complete", args = [listing_id])
    return redirect(redirect_url)

def submission_complete(request, listing_id):
    context = {"listing_id": listing_id}
    return render(request, "submitter/submission_complete.html", context)


def new_listing(request):
    if request.method == "POST":
        form = CreateListingForm(request.POST)
        if form.is_valid():
            name = form.cleaned_data["name"]
            questions = form.cleaned_data["questions"]

            listing = Listing()
            listing.name = name
            listing.creator = request.user
            listing.save()
            for question in questions.iterator():
                listing.questions.add(question)

        redirect_url = reverse("submitter:results", args = [listing.id])
        return redirect(redirect_url, listing.id)

    else:
        form = CreateListingForm()
    return render(request, "submitter/new_listing.html", {"form":form})


def registerPage(request):
    if not request.user.is_authenticated:
        form = CreateUserForm()

        if request.method =="POST":
            form = CreateUserForm(request.POST)
            if form.is_valid():
                form.save()
                email = form['email'].value()
                password = form['password1'].value()
                user = authenticate(request, username=email, password=password)
                login(request, user)
                return redirect('submitter:home')

        context = {'form': form}
        return render(request, "submitter/register.html", context)
    else:
        return redirect('submitter:home')

def loginPage(request):
    form = CustomAuthenticationForm()

    if request.method =="POST":
        form = CustomAuthenticationForm(request, data=request.POST)
        if request.POST['email'] and request.POST['password']:
            email = form['email'].value()
            password = form['password'].value()

            # Authenticate using your custom backend
            user = authenticate(request, username=email, password=password)
            if user is not None:
                login(request, user)
                return redirect('submitter:home')
            else:
                form.add_error(None, "Invalid credentials")

    context = {'form': form}
    return render(request, "submitter/login.html", context)

def homePage(request):
    if request.user.is_authenticated:
        listings = Listing.objects.all().filter(creator=request.user)
        context={'listings':listings}
        return render(request, "submitter/homepage.html", context)
    else:
        return redirect('submitter:register')


def logout_view(request):
    logout(request)
    return redirect("submitter:login")
