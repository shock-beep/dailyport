# Generated by Django 4.2.11 on 2024-04-10 10:38

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('authm', '0023_scan_db_pingd_alter_parsing_protocolo_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='scan_db',
            name='acabou',
            field=models.BooleanField(default=False),
        ),
    ]
