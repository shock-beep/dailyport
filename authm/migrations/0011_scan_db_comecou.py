# Generated by Django 4.2.11 on 2024-03-19 14:58

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('authm', '0010_auto_20240315_1554'),
    ]

    operations = [
        migrations.AddField(
            model_name='scan_db',
            name='comecou',
            field=models.BooleanField(default=False),
        ),
    ]
