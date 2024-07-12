# Generated by Django 3.2.12 on 2024-05-07 10:18

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('authm', '0036_scan_db_openvas_comecou'),
    ]

    operations = [
        migrations.CreateModel(
            name='final_ip',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('ip_address', models.GenericIPAddressField(unique=True)),
            ],
        ),
        migrations.CreateModel(
            name='outputFinal',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('IP', models.CharField(max_length=32, null=True)),
            ],
        ),
        migrations.CreateModel(
            name='final_port',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('port_number', models.PositiveIntegerField()),
                ('cve', models.CharField(max_length=100)),
                ('severity', models.CharField(max_length=20)),
                ('ip_address', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='authm.ipaddress')),
            ],
        ),
    ]
