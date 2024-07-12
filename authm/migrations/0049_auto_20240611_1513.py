# Generated by Django 3.2.12 on 2024-06-11 15:13

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('authm', '0048_alter_ipaddress_address'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='port',
            name='ip_address',
        ),
        migrations.RemoveField(
            model_name='ipaddress',
            name='address',
        ),
        migrations.AddField(
            model_name='ipaddress',
            name='ip',
            field=models.GenericIPAddressField(null=True),
        ),
        migrations.AddField(
            model_name='ipaddress',
            name='portas',
            field=models.CharField(max_length=999, null=True),
        ),
        migrations.AddField(
            model_name='ipaddress',
            name='servicos',
            field=models.CharField(max_length=999, null=True),
        ),
        migrations.DeleteModel(
            name='CVE',
        ),
        migrations.DeleteModel(
            name='Port',
        ),
    ]