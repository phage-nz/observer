# Observer
**OSINT Compromise Monitoring  
https://github.com/phage-nz/observer**

**Note:** This project is not actively maintained.

## About
Observer is a flexible platform for finding information suggesting compromise of organisations and countries of interest. It achieves this by trawling through OSINT and scan data, and reporting items of interest to dashboards per entity. At a minimum it requires:
- BinaryEdge Starter API key ($10/month).  
- PasteBin scraping API access.  
- VirusTotal API key.  
- Shodan API key.  
- Twitter API key.  

## Deployment
Install OS pre-req's:
```
apt install apache2 libssl-dev postgresql postgresql-contrib python3 python3-dev python3-pip redis-server
sudo usermod -a -G redis www-data
sudo usermod -a -G redis ubuntu
```

Set up Apache according to: https://www.digitalocean.com/community/tutorials/how-to-secure-apache-with-let-s-encrypt-on-ubuntu-18-04

Clone the project:
```
cd /opt
git clone https://github.com/phage-nz/observer
```

Install Python pre-req's:
```
cd /opt/observer
pip3 install -r requirements.txt
```

Prepare the database:
```
sudo su - postgres
psql
CREATE DATABASE observer;
CREATE USER observer WITH PASSWORD 'YOUR PASSWORD HERE';
ALTER ROLE observer SET client_encoding TO 'utf8';
ALTER ROLE observer SET default_transaction_isolation TO 'read committed';
ALTER ROLE observer SET timezone TO 'UTC';
GRANT ALL PRIVILEGES ON DATABASE observer TO observer;
```

Complete the settings files:
* /opt/observer/observer/settings.py  
* /opt/observer/scripts/load_settings.py  

In load_settings.py, the following are replaced with your home country details:
```
HOME_COUNTRY_NAME = 'New Zealand'
HOME_COUNTRY_CODE = 'NZ'
```

A list of favored AV engines is also defined in the head of /opt/observer/core/virustotal_utils.py

Set up the database and load settings:  
```
python3 manage.py migrate contenttypes
python3 manage.py makemigrations web
python3 manage.py migrate --fake-initial
python3 manage.py migrate
python3 manage.py collectstatic
python3 manage.py createsuperuser
python3 manage.py runscript load_settings
```

Edit /opt/observer/apache/observer.conf to include the parameters of your current Apache configuration (e.g. host name, certificate paths), then enable the Observer Apache site and systemd services:
```
cp /opt/observer/apache/observer.conf /etc/apache2/sites-available
ln -s /etc/apache2/sites-available/observer.conf /etc/apache2/sites-enabled/observer.conf
systemctl restart apache2
cp /opt/observer/systemd/observer.service /etc/systemd/system
cp /opt/observer/systemd/observer-web.service /etc/systemd/system
systemctl enable observer.service
systemctl enable observer-web.service
systemctl start observer.service
systemctl start observer-web.service
```

Once set up, sign in to Django admin at https://yourdomain.here/admin and input your feeds. Feeds must be of a plaintext type (e.g. https://urlhaus.abuse.ch/downloads/csv_online/). Also, define at least one organisation object. You can then run a batch job to search for their data by defining their name at the head of /opt/observer/scripts/batch.py and running:
```
python3 manage.py runscript batch
```

In regards to permissions:  
- Staff can see all organisations.  
- Organisation members can be added a group of the same name as their organisation to deny them the ability to see data beyond their own.  
- All users can see data for the home country.  