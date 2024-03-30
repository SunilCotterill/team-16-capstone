from django.test import TestCase, Client, RequestFactory

from .models import Question, CustomUser, Answer, Listing, ListingResponse
from django.core.exceptions import ValidationError
from django.contrib.auth.models import AnonymousUser

from .views import close_listing, reopen_listing, delete_listing

class CustomUserModelTests(TestCase):
    def test_str_method_returns_email(self):
        email = "test@example.com"
        user = CustomUser(email=email)
        self.assertEqual(str(user), email)

    def test_email_field_validation(self):
        invalid_email = "invalidemail.com"
        password = "FakePWord123!"
        with self.assertRaises(ValidationError):
            CustomUser(email=invalid_email, password=password).full_clean()
    
    def test_waterloo_email_field_validation(self):
        invalid_email = "fail@gmail.com"
        password = "FakePWord123!"
        with self.assertRaises(ValidationError):
            CustomUser(email=invalid_email, password=password).full_clean()
    
    def test_correct_email_field_validation(self):
        invalid_email = "pass@uwaterloo.ca"
        password = "FakePWord123!"
        CustomUser(email=invalid_email, password=password).full_clean()


class QuestionModelTests(TestCase):
    def test_str_method_returns_question_text(self):
        question_text = "What is your age?"
        category = Question.Category.DEMOGRAPHIC
        question = Question(question_text=question_text, category=category)
        self.assertEqual(str(question), question_text)

class AnswerModelTests(TestCase):
    def test_str_method_returns_answer_text(self):
        answer_text = "Six and a half"
        answer = Answer(answer_text=answer_text)
        self.assertEqual(str(answer), answer_text)


class IntegrationTest(TestCase):
    def setUp(self):
        self.Client = Client()
   
    def test_index_not_logged_in(self):
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'submitter/landing.html')

    def test_index_logged_in_verified(self):
        user = CustomUser.objects.create_user(email='test@uwaterloo.ca', password='FakePWord123!', first_name='test', last_name='user')
        user.email_is_verified = True
        user.save()
        self.client.force_login(user)

        # self.assertTrue(login_result)
        response = self.client.get('/')
        self.assertEqual(response.url, '/apartmate/home/')
    

    def test_submission(self):
        user = CustomUser.objects.create_user(email='test@uwaterloo.ca', password='FakePWord123!', first_name='test', last_name='user')
        user.email_is_verified = True
        user.save()
        listing = Listing()
        listing.name = "Test Listing"
        listing.creator = user
        listing.available_bedrooms = 2
        listing.total_bedrooms = None
        listing.address = None
        listing.rent_amount = None
        listing.additional_information =  None
        listing.save()

        self.client.force_login(user)

        response = self.client.get(f'/apartmate/{listing.pk}/submission')
        self.assertTemplateUsed(response, 'submitter/submission.html')
   
    def test_results(self):
        user = CustomUser.objects.create_user(email='test@uwaterloo.ca', password='FakePWord123!', first_name='test', last_name='user')
        user.email_is_verified = True
        user.save()
        listing = Listing()
        listing.name = "Test Listing"
        listing.creator = user
        listing.available_bedrooms = 2
        listing.total_bedrooms = None
        listing.address = None
        listing.rent_amount = None
        listing.additional_information =  None
        listing.save()

        self.client.force_login(user)

        response = self.client.get(f'/apartmate/{listing.pk}/results')
        self.assertTemplateUsed(response, 'submitter/results.html')
    
    def test_results_incorrect_user(self):
        user = CustomUser.objects.create_user(email='test@uwaterloo.ca', password='FakePWord123!', first_name='test', last_name='user')
        user.email_is_verified = True
        user.save()
        listing = Listing()
        listing.name = "Test Listing"
        listing.creator = user
        listing.available_bedrooms = 2
        listing.total_bedrooms = None
        listing.address = None
        listing.rent_amount = None
        listing.additional_information =  None
        listing.save()

        user2 = CustomUser.objects.create_user(email='test2@uwaterloo.ca', password='FakePWord123!', first_name='test', last_name='user')
        user2.email_is_verified = True
        user2.save()
        self.client.force_login(user2)

        response = self.client.get(f'/apartmate/{listing.pk}/results')
        self.assertEqual(response.url, '/apartmate/home/')
    
    # MAYBE ADD FILTER CHECK

    def test_close_listing(self):
        user = CustomUser.objects.create_user(email='test@uwaterloo.ca', password='FakePWord123!', first_name='test', last_name='user')
        user.email_is_verified = True
        user.save()
        listing = Listing()
        listing.name = "Test Listing"
        listing.creator = user
        listing.available_bedrooms = 2
        listing.total_bedrooms = None
        listing.address = None
        listing.rent_amount = None
        listing.additional_information =  None
        listing.save()

        request = RequestFactory().get('/')
        request.user = user
        close_listing(request, listing.pk)
        listing_get = Listing.objects.get(pk = listing.pk)
        self.assertTrue(listing_get.is_closed)
    
    def test_reopen_listing(self):
        user = CustomUser.objects.create_user(email='test@uwaterloo.ca', password='FakePWord123!', first_name='test', last_name='user')
        user.email_is_verified = True
        user.save()
        listing = Listing()
        listing.name = "Test Listing"
        listing.creator = user
        listing.available_bedrooms = 2
        listing.total_bedrooms = None
        listing.address = None
        listing.rent_amount = None
        listing.additional_information =  None
        listing.is_closed = True
        listing.save()

        request = RequestFactory().get('/')
        request.user = user
        reopen_listing(request, listing.pk)
        listing_get = Listing.objects.get(pk = listing.pk)
        self.assertFalse(listing_get.is_closed)
    
    def test_delete_listing(self):
        user = CustomUser.objects.create_user(email='test@uwaterloo.ca', password='FakePWord123!', first_name='test', last_name='user')
        user.email_is_verified = True
        user.save()
        listing = Listing()
        listing.name = "Test Listing"
        listing.creator = user
        listing.available_bedrooms = 2
        listing.total_bedrooms = None
        listing.address = None
        listing.rent_amount = None
        listing.additional_information =  None
        listing.is_closed = True
        listing.save()

        request = RequestFactory().get('/')
        request.user = user
        delete_listing(request, listing.pk)
        try: 
            listing_get = Listing.objects.get(pk = listing.pk)
        except Listing.DoesNotExist:
            pass
    
    def test_result(self):
        user = CustomUser.objects.create_user(email='test@uwaterloo.ca', password='FakePWord123!', first_name='test', last_name='user')
        user.email_is_verified = True
        user.save()
        listing = Listing()
        listing.name = "Test Listing"
        listing.creator = user
        listing.available_bedrooms = 2
        listing.total_bedrooms = None
        listing.address = None
        listing.rent_amount = None
        listing.additional_information =  None
        listing.is_closed = True
        listing.save()

        user2 = CustomUser.objects.create_user(email='test2@uwaterloo.ca', password='FakePWord123!', first_name='test', last_name='user')
        user2.email_is_verified = True
        user2.save()
        self.client.force_login(user)

        listingResponse = ListingResponse()
        listingResponse.listing = listing
        listingResponse.responder = user2
        listingResponse.save()

        response = self.client.get(f'/apartmate/{listing.pk}/results/{user2.email}')
        self.assertTemplateUsed(response, 'submitter/result.html')
    
    def test_submit(self):
        q = Question()
        q.question_text = "How are you?"
        q.save()

        a = Answer()
        a.answer_text="Good"
        a.question = q
        a.save()

        user = CustomUser.objects.create_user(email='test@uwaterloo.ca', password='FakePWord123!', first_name='test', last_name='user')
        user.email_is_verified = True
        user.save()
        listing = Listing()
        listing.name = "Test Listing"
        listing.creator = user
        listing.available_bedrooms = 2
        listing.total_bedrooms = None
        listing.address = None
        listing.rent_amount = None
        listing.additional_information =  None
        listing.is_closed = True
        listing.save()
        listing.questions.add(q)

        user2 = CustomUser.objects.create_user(email='test2@uwaterloo.ca', password='FakePWord123!', first_name='test', last_name='user')
        user2.email_is_verified = True
        user2.save()
        self.client.force_login(user)

        listingResponse = ListingResponse()
        listingResponse.listing = listing
        listingResponse.responder = user2
        listingResponse.save()


        form_data = {
            'question_1':1
        }
        session = self.client.session
        session['is_submitting'] = 'True'
        session.save()
        response = self.client.post(f'/apartmate/{listing.pk}/submit/', form_data)

        # This throws an error if it doesn't exist
        listingResponse = ListingResponse.objects.get(pk=1)
    
    def test_new_listing(self):
        q = Question()
        q.question_text = "How are you?"
        q.category = 'Demographic'
        q.save()

        a = Answer()
        a.answer_text="Good"
        a.question = q
        a.save()

        user = CustomUser.objects.create_user(email='test@uwaterloo.ca', password='FakePWord123!', first_name='test', last_name='user')
        user.email_is_verified = True
        user.save()

        form_data = {
            'name':'test',
            'demographic_questions' : [1],
            'available_bedrooms' : 2

        }
        self.client.force_login(user)

        response = self.client.post(f'/apartmate/new_listing/', form_data)

        # This throws an error if it doesn't exist
        listingResponse = Listing.objects.get(pk=1)

    
    def test_register(self):
        form_data = {
            'email':'fake@uwaterloo.ca',
            'password1' : 'FakeP123!',
            'password2' : 'FakeP123!',
            'first_name': "Test",
            'last_name': "User"

        }

        response = self.client.post(f'/apartmate/register/', form_data)
        
        # This throws an error if it doesn't exist
        CustomUser.objects.get(pk=1)
    
    def test_register_page(self):
        response = self.client.get(f'/apartmate/register/')
        self.assertTemplateUsed(response, 'submitter/register.html')
    
    def test_login_page(self):
        response = self.client.get(f'/apartmate/login/')
        self.assertTemplateUsed(response, 'submitter/login.html')
    
    def test_login(self):
        response = self.client.get(f'/apartmate/login/')
        self.assertTemplateUsed(response, 'submitter/login.html')
        user = CustomUser.objects.create_user(email='test@uwaterloo.ca', password='FakePWord123!', first_name='test', last_name='user')
        user.email_is_verified = True
        user.save()

        form_data = {
            'email':'test@uwaterloo.ca',
            'password' : 'FakePWord123!',
        }

        response = self.client.post(f'/apartmate/login/', form_data)
        self.assertEqual(response.url, '/apartmate/home/')





        