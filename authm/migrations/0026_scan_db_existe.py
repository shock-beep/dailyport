# Generated by Django 4.2.11 on 2024-04-10 13:32

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('authm', '0025_ipaddress_delete_parsing'),
    ]

    operations = [
        migrations.AddField(
            model_name='scan_db',
            name='existe',
            field=models.BooleanField(default=False),
        ),
    ]
