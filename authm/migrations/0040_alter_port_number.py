# Generated by Django 3.2.12 on 2024-05-22 13:49

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('authm', '0039_auto_20240513_0841'),
    ]

    operations = [
        migrations.AlterField(
            model_name='port',
            name='number',
            field=models.CharField(max_length=999),
        ),
    ]
