# Generated by Django 3.2.19 on 2024-05-13 08:41

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('authm', '0038_auto_20240507_1048'),
    ]

    operations = [
        migrations.CreateModel(
            name='CVE',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('cve_id', models.CharField(max_length=15)),
                ('description', models.TextField()),
            ],
        ),
        migrations.DeleteModel(
            name='outputFinal',
        ),
        migrations.RenameField(
            model_name='ipaddress',
            old_name='address',
            new_name='ip',
        ),
        migrations.AlterUniqueTogether(
            name='port',
            unique_together=set(),
        ),
        migrations.AddField(
            model_name='cve',
            name='ports',
            field=models.ManyToManyField(related_name='cves', to='authm.Port'),
        ),
        migrations.RemoveField(
            model_name='port',
            name='cve',
        ),
        migrations.RemoveField(
            model_name='port',
            name='port_number',
        ),
        migrations.RemoveField(
            model_name='port',
            name='severity',
        ),
    ]