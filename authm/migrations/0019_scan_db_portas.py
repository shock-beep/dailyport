# Generated by Django 4.2.11 on 2024-04-08 09:51

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('authm', '0018_parsing_domain_scan_db_max_agressi_scan_db_velo_nmap'),
    ]

    operations = [
        migrations.AddField(
            model_name='scan_db',
            name='portas',
            field=models.CharField(max_length=999, null=True),
        ),
    ]
