# Generated by Django 4.2.3 on 2024-04-07 22:09

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('submitter', '0005_remove_listing_total_bedrooms_alter_listing_address_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='listing',
            name='rent_term',
            field=models.CharField(default='Summer 2024', max_length=300),
            preserve_default=False,
        ),
    ]