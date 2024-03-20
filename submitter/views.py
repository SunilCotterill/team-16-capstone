from django.shortcuts import render, redirect, reverse
from .models import Question, Answer, Listing, Response, CustomUser, ListingResponse
from django.contrib.auth.forms import  PasswordChangeForm
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout, get_user_model, update_session_auth_hash
from django.contrib.auth.decorators import login_required
from .forms import CreateUserForm

# For email verification
from django.contrib.sites.shortcuts import get_current_site
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.template.loader import render_to_string
from .tokens import account_activation_token
from django.core.mail import EmailMessage
from django.contrib import messages
from django.core.paginator import Paginator

from django.db.models import Max

from .forms import CreateUserForm, CustomAuthenticationForm, CreateListingForm

from django.urls import reverse_lazy

from django.urls import reverse_lazy

# for password reset
from django.urls import reverse_lazy
from django.contrib.auth.views import PasswordResetView
from django.contrib.messages.views import SuccessMessageMixin


# password reset class override
class ResetPasswordView(SuccessMessageMixin, PasswordResetView):
    template_name = 'submitter/password_reset.html'
    email_template_name = 'submitter/password_reset_email.html'
    subject_template_name = 'submitter/password_reset_subject.txt'
    success_message = "We've emailed you instructions for resetting your password. " \
                      "If an account exists with the email you entered, you should receive one shortly." \
                      " If you don't receive an email, " \
                      "please make sure you've entered the address you registered with, and check your spam folder."
    success_url = reverse_lazy('submitter:home')

# so we can reference the user model as User instead of CustomUser
User = get_user_model()

# send email with verification link
def verify_email(request):
    if request.user.is_authenticated:
        if request.method == "POST":
            if request.user.email_is_verified != True:
                current_site = get_current_site(request)
                user = request.user
                email = request.user.email
                subject = "Verify Email"
                message = render_to_string('submitter/verify_email_message.html', {
                    'request': request,
                    'user': user,
                    'domain': current_site.domain,
                    'uidb64':urlsafe_base64_encode(force_bytes(user.pk)),
                    'token':account_activation_token.make_token(user),
                })
                email = EmailMessage(
                    subject, message, to=[email]
                )
                email.content_subtype = 'html'
                email.send()
                return redirect('submitter:verify-email-done')
            else:
                return redirect('submitter:signup')
        return render(request, 'submitter/verify_email.html')
    else:
        return redirect('submitter:login')

def index(request):
    if request.user.is_authenticated:
        return redirect("submitter:home")
    return render(request, 'submitter/landing.html')

def submission(request, listing_id):
    listing = Listing.objects.get(pk = listing_id)
    if listing.is_closed:
        return render(request, 'submitter/listing_closed.html')
    listing_name = listing.name
    listing_questions_list = listing.questions.all()
    question_ids = list(listing_questions_list.values_list("id", flat = True))
    listing_answers_list = Answer.objects.filter(question__in = question_ids)

    previous_answers = None
    if request.user.is_authenticated:
        responder_prev_responses = Response.objects.filter(listing_response__responder=request.user.id).filter(question__in = listing_questions_list).order_by('-created_timestamp')
        
        bad_implementation = {}
        for res in responder_prev_responses:
            if res.question.id not in bad_implementation:
                bad_implementation[res.question.id] = res.answer.id
        
        previous_answers = bad_implementation.values()


        

    context = {
        "listing_id": listing_id,
        "listing_name": listing_name,
        "listing_questions_list": listing_questions_list,
        "listing_answers_list": listing_answers_list,
        "previous_answers": previous_answers
    }
    # messages = list(messages.get_messages(request))
    # if messages:
    #     context['message'] = messages[0]

    request.session['is_submitting'] = True

    return render(request, "submitter/submission.html", context)

def results(request, listing_id):

    listing = Listing.objects.get(id = listing_id)
    if not listing:
        return redirect("submitter:home")
    if not request.user.id == listing.creator.id:
        return redirect("submitter:home")

    # Kept filters for populating checkbox
    filters = []
    filters_dict = {}
    if request.method == "POST":
        for key in request.POST.keys():
            if key.startswith('question_'):
                split = key.split('_')
                question_id = split[1]
                answer_id = split[2]
                if question_id in filters_dict:
                    filters_dict[question_id].append(answer_id)
                else:
                    filters_dict[question_id] = [answer_id]
                filters.append(int(request.POST.get(key)))

    listing_responses_temp = ListingResponse.objects.filter(listing_id=listing_id).filter(responder__email_is_verified=True)

    listing_questions_list = listing.questions.all()
    question_ids = list(listing_questions_list.values_list("id", flat = True))
    listing_answers_list = Answer.objects.filter(question__in = question_ids)
    listing_responses = []
    if filters_dict:
        for listing_response in listing_responses_temp:
            flag = True
            responses_for_email = Response.objects.filter(listing_response=listing_response.id)
            responders_answers = responses_for_email.values_list('answer_id', flat=True)
            for cur_question_id in question_ids:
                if str(cur_question_id) in filters_dict:
                    if not any(int(x) in responders_answers for x in filters_dict[str(cur_question_id)]):
                        flag = False
                        break
            if flag:
                listing_responses.append(listing_response)
    else:
        listing_responses = listing_responses_temp

    name = Listing.objects.get(id=listing_id).name
    status = Listing.objects.get(id=listing_id).is_closed
    current_site = get_current_site(request)
    context = {
        "listing_id": listing_id,
        "listing_responses": listing_responses,
        "listing_name": name,
        "listing_status": status,
        "listing_questions_list": listing_questions_list,
        "listing_answers_list": listing_answers_list,
        "filtered_answers": filters,
        "listing": listing,
        'domain': current_site.domain
    }
    return render(request, "submitter/results.html", context)

def close_listing(request, listing_id):
    listing = Listing.objects.get(pk = listing_id)
    if not request.user.id == listing.creator.id:
        return redirect("submitter:home")
    listing.is_closed = True
    listing.save()
    return redirect('submitter:results', listing_id)

def reopen_listing(request, listing_id):
    listing = Listing.objects.get(pk = listing_id)
    if not request.user.id == listing.creator.id:
        return redirect("submitter:home")
    listing.is_closed = False
    listing.save()
    return redirect('submitter:results', listing_id)

def delete_listing(request, listing_id):
    listing = Listing.objects.get(pk = listing_id)
    if not request.user.id == listing.creator.id:
        return redirect("submitter:home")
    listing.delete()
    return redirect('submitter:home')

def result(request, listing_id, email):
    listing = Listing.objects.get(id = listing_id)
    if not request.user.id == listing.creator.id:
        return redirect("submitter:home")

    responder = CustomUser.objects.get(email=email)
    listingResponse = ListingResponse.objects.filter(listing=listing_id).get(responder=responder)
    answered_ids = Response.objects.filter(listing_response = listingResponse).values_list('answer__id', flat=True)
    answered = Answer.objects.filter(id__in=answered_ids).values_list('id', flat=True)

    listing_questions_list = listing.questions.all()
    question_ids = list(listing_questions_list.values_list("id", flat = True))
    listing_answers_list = Answer.objects.filter(question__in = question_ids)

    context = {
        "listing_id": listing_id,
        "listing_questions_list": listing_questions_list,
        "listing_answers_list": listing_answers_list,
        "answered": answered,
        "email": email,
        "first_name": responder.first_name,
        "last_name": responder.last_name,
        "listing_name": listing.name,
        "listing_response": listingResponse
    }
    return render(request, "submitter/result.html", context)

def submit_from_redirect(request,user):
    if "submit" in request.session:
        listing_id = request.session["listing_id"]
        listingResponse = ListingResponse()
        listingResponse.listing = Listing.objects.get(pk = listing_id)
        listingResponse.responder =  user
        try:
            listingResponse.save()
        except Exception as e:
            return redirect('submitter:login')
        keys_to_del = ["submit", "listing_id"]
        for key in request.session.keys():
            if key.startswith('question_'):
                question_id = key.split('_')[1]
                selected_answer_id = request.session.get(key)
                new_response = Response()
                new_response.question = Question.objects.get(pk = question_id)
                new_response.answer = Answer.objects.get(pk = selected_answer_id)
                new_response.listing_response = listingResponse
                new_response.save()
                keys_to_del.append(key)
        for key in keys_to_del:
            del request.session[key]

def submit(request, listing_id):
    if request.user.is_authenticated:
        # Get the CSRF token from the POST request
        csrf_token = request.POST.get('csrfmiddlewaretoken')

        listingResponse = ListingResponse()
        listingResponse.listing = Listing.objects.get(pk = listing_id)
        listingResponse.responder =  request.user
        try:
            listingResponse.save()
        except Exception as e:
            messages.error(request, "You have already submitted to this listing. You cannot submit again.")
            return redirect("submitter:submission", listing_id)


        # Loop through all the keys in the POST data
        for key in request.POST.keys():
            # email = request.POST.get('email')
            if key.startswith('question_'):
                question_id = key.split('_')[1]
                selected_answer_id = request.POST.get(key)
                new_response = Response()
                new_response.question = Question.objects.get(pk = question_id)
                new_response.answer = Answer.objects.get(pk = selected_answer_id)
                new_response.listing_response = listingResponse
                new_response.save()
    else:
        for key in request.POST.keys():
            if key.startswith('question_'):
                request.session[key] = request.POST.get(key)
            request.session["listing_id"] = listing_id
            request.session["submit"] = "true"

        request.session["info"] = "Please create an account with us so we can save these responses for future quizzes. We promise not to spam with mailing lists, even if you want us to."
        return redirect(reverse('submitter:register'))

    del request.session['is_submitting']
    redirect_url = reverse("submitter:submission_complete", args = [listing_id])
    return redirect(redirect_url)

def submission_complete(request, listing_id):
    context = {"listing_id": listing_id}
    return render(request, "submitter/submission_complete.html", context)

def new_listing(request):
    if not request.user.is_authenticated:
        return redirect("submitter:home")
    elif not request.user.email_is_verified:
        return redirect("submitter:verify-email")

    if request.method == "POST":
        form = CreateListingForm(request.POST)
        if form.is_valid():
            name = form.cleaned_data["name"]
            demographic_questions = form.cleaned_data["demographic_questions"]
            social_questions = form.cleaned_data["social_questions"]
            household_questions = form.cleaned_data["household_questions"]

            available_bedrooms = form.cleaned_data["available_bedrooms"]

            questions = demographic_questions | social_questions | household_questions


            listing = Listing()
            listing.name = name
            listing.creator = request.user
            listing.available_bedrooms = available_bedrooms
            listing.total_bedrooms = form.cleaned_data["total_bedrooms"] if "total_bedrooms" in form.cleaned_data else None
            listing.address = form.cleaned_data["address"] if "address" in form.cleaned_data else None
            listing.rent_amount = form.cleaned_data["rent_amount"] if "rent_amount" in form.cleaned_data else None
            listing.additional_information = form.cleaned_data["additional_information"] if "additional_information" in form.cleaned_data else None

            listing.save()
            for question in questions.iterator():
                listing.questions.add(question)
        else:
            return render(request, "submitter/new_listing.html", {"form":form})


        redirect_url = reverse("submitter:results", args = [listing.id])
        return redirect(redirect_url, listing.id)

    else:
        form = CreateListingForm()
        return render(request, "submitter/new_listing.html", {"form":form})

def registerPage(request):
    if not request.user.is_authenticated:
        form = CreateUserForm(request.POST or None)
        # We should really use request session to do this but for now I think this works
        if "info" in request.session and request.session["info"]:
            messages.add_message(request, messages.INFO, request.session["info"])
            del request.session["info"]

        if request.method == "POST":
            if form.is_valid():
                form.save()
                email = form['email'].value()
                password = form['password1'].value()
                user = authenticate(request, username=email, password=password)
                if "submit" in request.session:
                    submit_from_redirect(request, user)
                login(request, user)
                return verify_email(request)
            else:
                context = {'form': form}
                return render(request, "submitter/register.html", context)


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
                if "submit" in request.session:
                    submit_from_redirect(request, user)
                login(request, user)
                if "is_submitting" in request.session:
                    del request.session['is_submitting']
                    return render(request, "submitter/submission_complete.html")
                else:
                    return redirect('submitter:home')
            else:
                form.add_error(None, "Invalid credentials")

    context = {'form': form}
    return render(request, "submitter/login.html", context)

def homePage(request):
    if request.user.is_authenticated and request.user.email_is_verified:
        listings = Listing.objects.all().filter(creator=request.user).order_by('-id')
        for listing in listings:
            listing.applicant_count = ListingResponse.objects.filter(listing=listing).filter(responder__email_is_verified=True).count()
            listing.shortlist_count = ListingResponse.objects.filter(listing=listing, is_shortlisted=True).filter(responder__email_is_verified=True).count()

        context={'listings':listings, 'first_name': request.user.first_name}
        return render(request, "submitter/homepage.html", context)
    elif request.user.is_authenticated:
        return redirect('submitter:verify-email')
    else:
        return redirect('submitter:index')


def logout_view(request):
    logout(request)
    return redirect("submitter:login")

@login_required
def update_shortlist(request, listing_id, listing_response_id):
    context={}
    try:
        listingResponse = ListingResponse.objects.get(pk=listing_response_id)
        listingResponse.is_shortlisted = not listingResponse.is_shortlisted  # Toggle the shortlisted field
        listingResponse.save()
        return redirect('submitter:results', listing_id)

    except listingResponse.DoesNotExist:
        return render(request, "submitter/homepage.html", context)
    
@login_required
def update_shortlist_result(request, listing_id, listing_response_id):
    context={}
    try:
        listingResponse = ListingResponse.objects.get(pk=listing_response_id)
        listingResponse.is_shortlisted = not listingResponse.is_shortlisted  # Toggle the shortlisted field
        listingResponse.save()
        return redirect('submitter:result', listing_id, listingResponse.responder.email)

    except listingResponse.DoesNotExist:
        return render(request, "submitter/homepage.html", context)

def verify_email_done(request):
    return render(request, 'submitter/verify_email_done.html')

def verify_email_complete(request, uidb64, token):
    context = {
        'uidb64': uidb64,
        'token': token,
    }
    return render(request, 'submitter/verify_email_complete.html', context)

def verify_email_confirm(request, uidb64, token):
    if request.method == 'POST':
        uidb64 = request.POST.get('uidb64')
        token = request.POST.get('token')
        context = {}
        try:
            uidb64 = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uidb64)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            user = None

        if user is not None and account_activation_token.check_token(user, token):
            user.email_is_verified = True
            user.save()
            login(request, user)
            messages.success(request, 'Your email has been verified. You are now logged in.')
            if "is_submitting" in request.session:
                del request.session['is_submitting']
                return redirect("submitter:submission_complete")
            else:
                return render(request, 'submitter/info.html')

    return redirect('submitter:home')

def change_password(request):
   form = PasswordChangeForm(user=request.user, data=request.POST or None)
   if form.is_valid():
     form.save()
     update_session_auth_hash(request, form.user)
     return redirect('submitter:home')
   return render(request, 'submitter/change_password.html', {'form': form})

def info(request):
    if not request.user.is_authenticated:
        return redirect("submitter:home")
    elif not request.user.email_is_verified:
        return redirect("submitter:verify-email")
    return render(request, 'submitter/info.html')

def all_listings(request):
    if not request.user.is_authenticated:
        return redirect("submitter:home")
    elif not request.user.email_is_verified:
        return redirect("submitter:verify-email")
    
    
    all_listings = Listing.objects.all().filter(is_closed = False).order_by('-pk')

    bedrooms_filter = request.GET.get('available_bedrooms')
    if bedrooms_filter:
        print("HI")
        all_listings = all_listings.filter(available_bedrooms=bedrooms_filter)

    rent_bucket_filter = request.GET.get('rent_bucket')
    if rent_bucket_filter:
        if rent_bucket_filter == '1':
            all_listings = all_listings.filter(rent_amount__lte=499)  # Example: Rent up to $1000
        elif rent_bucket_filter == '2':
            all_listings = all_listings.filter(rent_amount__gt=500, rent_amount__lte=999)  # Example: Rent $1000-$2000
        elif rent_bucket_filter == '3':
            all_listings = all_listings.filter(rent_amount__gt=1000, rent_amount__lte=1499)
        elif rent_bucket_filter == '4':
            all_listings = all_listings.filter(rent_amount__gt=1500, rent_amount__lte=1999)
        elif rent_bucket_filter == '5':
            all_listings = all_listings.filter(rent_amount__gt=2000)
    
    paginator = Paginator(all_listings, 10)
    page_number = request.GET.get('page')
    page = paginator.get_page(page_number)

    
    return render(request, 'submitter/open_listings.html', {'page': page })

