# Generated by Django 4.2.11 on 2024-04-11 08:55

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('authm', '0028_scan_db_ja_abertas'),
    ]

    operations = [
        migrations.AddField(
            model_name='scan_db',
            name='op_portas',
            field=models.BooleanField(default=False),
        ),
    ]