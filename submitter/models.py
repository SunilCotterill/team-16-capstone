from django.db import models



class User(models.Model):
    email = models.EmailField(max_length=254)
    first_name = models.CharField(max_length=200)
    last_name = models.CharField(max_length=200)
    def __str__(self):
        return self.email


class Listing(models.Model):
    creator = models.ForeignKey(User, on_delete=models.CASCADE)

class Question(models.Model):
    question_text = models.CharField(max_length=200)
    def __str__(self):
        return self.question_text
    

class Answer(models.Model):
    question = models.ForeignKey(Question, on_delete=models.CASCADE)
    answer_text = models.CharField(max_length=200)
    def __str__(self):
        return self.answer_text

class Response(models.Model):
    # This is the user that submitted the question
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    listing = models.ForeignKey(Listing, on_delete=models.CASCADE)
    question = models.ForeignKey(Question, on_delete=models.CASCADE)
    answer =  models.ForeignKey(Answer, on_delete=models.CASCADE)