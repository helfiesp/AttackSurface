# Generated by Django 4.2.3 on 2023-08-02 08:09

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('nessus', '0005_okdomains_ip_data'),
    ]

    operations = [
        migrations.AddField(
            model_name='okdomains',
            name='ip',
            field=models.TextField(default=None, null=True),
        ),
    ]
