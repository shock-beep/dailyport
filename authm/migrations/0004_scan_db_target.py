# Generated by Django 3.2.12 on 2024-03-11 14:49

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('authm', '0003_scan_db'),
    ]

    operations = [
        migrations.AddField(
            model_name='scan_db',
            name='target',
            field=models.GenericIPAddressField(null=True),
        ),
    ]
