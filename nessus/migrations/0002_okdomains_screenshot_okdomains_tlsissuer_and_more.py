# Generated by Django 4.2.3 on 2023-07-28 08:22

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('nessus', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='okdomains',
            name='screenshot',
            field=models.TextField(default=None, null=True),
        ),
        migrations.AddField(
            model_name='okdomains',
            name='tlsissuer',
            field=models.TextField(default=None, null=True),
        ),
        migrations.AddField(
            model_name='okdomains',
            name='url',
            field=models.TextField(default=None, null=True),
        ),
    ]
