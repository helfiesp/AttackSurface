# Generated by Django 4.2.3 on 2023-07-29 10:37

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('nessus', '0003_remove_okdomains_screenshot_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='okdomains',
            name='nmap',
            field=models.TextField(default=None, null=True),
        ),
    ]
