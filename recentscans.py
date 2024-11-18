from ./pyenv/lib/python3.11/site-packages/tenable.io import TenableIO
tio = TenableIO('TIO_ACCESS_KEY', 'TIO_SECRET_KEY')
for scan in tio.scans.list():
	print('{status}: {id}/{uuid} - {name}'.format(**scan))
