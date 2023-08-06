from django.shortcuts import render, get_object_or_404, redirect, reverse
from django.http import HttpResponse, HttpResponseRedirect
from .models import Question, Answer, Listing, Response, CustomUser
from django.template import loader
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth import authenticate, login

from .forms import CreateUserForm, CustomAuthenticationForm


def index(request):
    return redirect('submitter:register')

def submission(request, listing_id):
    latest_questions_list = Question.objects.order_by("id")
    latest_answers_list = Answer.objects.order_by("id")

    template = loader.get_template("submitter/submission.html")

    context = {
        "listing_id": listing_id,
        "latest_questions_list": latest_questions_list,
        "latest_answers_list": latest_answers_list
    }

    return HttpResponse(template.render(context, request))

def results(request, listing_id):
    template = loader.get_template("submitter/results.html")
    responses = Response.objects.filter(listing_id=listing_id)
    unique_user_ids = responses.values_list('user_id', flat=True).distinct()
    unique_users = CustomUser.objects.filter(id__in=unique_user_ids)

    context = {
        "listing_id": listing_id,
        "unique_users": unique_users
    }

    return HttpResponse(template.render(context, request))


def result(request, listing_id, user_id):
    answered_ids = Response.objects.filter(listing_id=listing_id).filter(user_id=user_id).values_list('answer_id', flat=True).distinct()
    answered = Answer.objects.filter(id__in=answered_ids).values_list('id', flat=True)
    submitter = CustomUser.objects.get(pk = user_id)

    latest_questions_list = Question.objects.order_by("id")
    latest_answers_list = Answer.objects.order_by("id")
    template = loader.get_template("submitter/result.html")
    context = {
        "listing_id": listing_id,
        "latest_questions_list": latest_questions_list,
        "latest_answers_list": latest_answers_list,
        "answered": answered,
        "first_name" : submitter.first_name,
        "last_name" : submitter.last_name,
        # "responses": responses
    }

    return HttpResponse(template.render(context, request))


def submit(request, listing_id):
    # Get the CSRF token from the POST request
    csrf_token = request.POST.get('csrfmiddlewaretoken')

    # Loop through all the keys in the POST data
    for key in request.POST.keys():
        if key.startswith('question_'):
            question_id = key.split('_')[1]
            selected_answer_id = request.POST.get(key)
            new_response = Response()
            new_response.listing = Listing.objects.get(pk = listing_id)
            new_response.question = Question.objects.get(pk = question_id)
            new_response.answer = Answer.objects.get(pk = selected_answer_id)
            new_response.user = CustomUser.objects.get(pk = 1)
            new_response.save()
    # results_url = reverse("submitter:results", args=[listing_id])
    redirect_url = reverse("submitter:submission_complete", args = [listing_id])
    return redirect(redirect_url)

def submission_complete(request, listing_id):
    template = loader.get_template("submitter/submission_complete.html")
    context = {"listing_id": listing_id}
    return HttpResponse(template.render(context, request))

def new_listing(request, user_id):
    template = loader.get_template("submitter/new_listing.html")
    context = {"user_id": user_id}
    return HttpResponse(template.render(context, request))

def registerPage(request):
    if not request.user.is_authenticated:
        form = CreateUserForm()

        if request.method =="POST":
            form = CreateUserForm(request.POST)
            if form.is_valid():
                form.save()
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
        context={}
        return render(request, "submitter/homepage.html", context)
    else:
        return redirect('submitter:register')
