# Generated by Django 5.0.4 on 2024-04-15 08:24

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('authm', '0030_scan_db_portas_ch'),
    ]

    operations = [
        migrations.CreateModel(
            name='ScanResult',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('ip', models.CharField(max_length=15)),
                ('port', models.IntegerField()),
                ('service', models.CharField(max_length=100)),
                ('version', models.CharField(max_length=100)),
            ],
        ),
        migrations.DeleteModel(
            name='IPAddress',
        ),
    ]
