# Generated by Django 3.2.12 on 2024-05-23 09:15

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('authm', '0040_alter_port_number'),
    ]

    operations = [
        migrations.AddField(
            model_name='ipaddress',
            name='port_scan',
            field=models.BooleanField(default=False, null=True),
        ),
        migrations.AddField(
            model_name='ipaddress',
            name='serv_scan',
            field=models.BooleanField(default=False, null=True),
        ),
        migrations.AddField(
            model_name='ipaddress',
            name='web_scan',
            field=models.BooleanField(default=False, null=True),
        ),
    ]
