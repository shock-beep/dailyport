# Generated by Django 4.2.11 on 2024-03-20 10:51

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('authm', '0013_alter_scan_db_comecou'),
    ]

    operations = [
        migrations.AlterField(
            model_name='scan_db',
            name='comecou',
            field=models.BooleanField(null=True),
        ),
    ]