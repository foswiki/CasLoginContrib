
# ---+ Security and Authentication
# ---++ CAS Login Contrib
# if you set your =Login/{LoginManager}= to CasLogin then you will need to set these options too

# **URL**
# Top-level URL of the CAS server (/login, /logout etc will be appended to this URL)
$Foswiki::cfg{CAS}{casUrl} = 'https://jasig:8443/';

# **PATH**
# Path to the SSL certificate for the CAS server 
# (needed if the CAS server's certificate is not installed in the OS's global certificate repository)
# (the =cipher RC4-SHA= can be removed if you're not getting the problem described below)
# 
# <verbatim>
# openssl  s_client -cipher RC4-SHA   -connect jasig.home.org.au:8443 2>&1 | sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/ p' > ../foswiki/core/jasig.crt
# </verbatim>
$Foswiki::cfg{CAS}{CAFile} = 'foswiki/jasig.crt';

# **BOOLEAN**
# Foswiki logout also logs out from CAS
$Foswiki::cfg{CAS}{LogoutFromCAS} = $FALSE;

# **STRING EXPERT**
# specify the SSL ciphers to use when contacting the CAS server
#    if you are having SSL connection issues, setting this to 'SSLv3' may help
$Foswiki::cfg{CAS}{SSL_version} = '';

# **BOOLEAN**
# Allow a user to log in to foswiki using the email addresses known to the password 
# system.
$Foswiki::cfg{CAS}{AllowLoginUsingEmailAddress} = 0;


