# Generated by Django 3.2.12 on 2024-06-06 13:45

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('authm', '0042_auto_20240604_0836'),
    ]

    operations = [
        migrations.AddField(
            model_name='ipaddress',
            name='domain',
            field=models.CharField(max_length=999, null=True),
        ),
    ]